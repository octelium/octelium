/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package harness

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/octelium/octelium/apis/main/quicv0"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	dataPlaneMTUDefault = 1280

	quicInitMsgType  = 1
	quicInitHdrSize  = 8
	quicMaxPayload   = 4096
	quicMaxPacket    = 65535
	quicRedialPeriod = 1500 * time.Millisecond
)

type DataPlaneOpts struct {
	Tunnel userv1.ConnectRequest_Initialize_ConnectionType

	AccessToken string
	TLSConfig   *tls.Config

	Addresses []netip.Addr

	KeepAliveSeconds int

	EndpointOverride func(gw *userv1.Gateway) string
}

type GatewayStats struct {
	ID string `json:"id"`

	TxBytes   uint64 `json:"txBytes"`
	RxBytes   uint64 `json:"rxBytes"`
	TxPackets uint64 `json:"txPackets,omitempty"`
	RxPackets uint64 `json:"rxPackets,omitempty"`

	LastHandshake time.Time `json:"lastHandshake,omitzero"`
	Connects      int       `json:"connects,omitempty"`
	LastErr       string    `json:"lastErr,omitempty"`
}

type DataPlane struct {
	opts  DataPlaneOpts
	key   []byte
	addrs []netip.Addr
	hasV4 bool
	hasV6 bool

	tun  tun.Device
	tnet *netstack.Net

	wg   *device.Device
	quic *quicEngine

	mu       sync.Mutex
	gateways []*userv1.Gateway
	closed   bool
}

func stateAddrs(state *userv1.ConnectionState) []netip.Addr {
	hasV4 := state.L3Mode != userv1.ConnectionState_V6
	hasV6 := state.L3Mode != userv1.ConnectionState_V4

	var ret []netip.Addr
	for _, addr := range state.Addresses {
		if hasV4 && addr.V4 != "" {
			if pfx, err := netip.ParsePrefix(addr.V4); err == nil {
				ret = append(ret, pfx.Addr())
			}
		}
		if hasV6 && addr.V6 != "" {
			if pfx, err := netip.ParsePrefix(addr.V6); err == nil {
				ret = append(ret, pfx.Addr())
			}
		}
	}

	return ret
}

func NewDataPlane(state *userv1.ConnectionState, gws []*userv1.Gateway,
	o DataPlaneOpts) (*DataPlane, error) {
	if state == nil {
		return nil, errors.Errorf("No Connection state")
	}

	addrs := o.Addresses
	if len(addrs) == 0 {
		addrs = stateAddrs(state)
	}
	if len(addrs) == 0 {
		return nil, errors.Errorf("The Connection state has no usable address")
	}

	mtu := int(state.Mtu)
	if mtu <= 0 || mtu > 9000 {
		mtu = dataPlaneMTUDefault
	}

	tunDev, tnet, err := netstack.CreateNetTUN(addrs, nil, mtu)
	if err != nil {
		return nil, err
	}

	ret := &DataPlane{
		opts:     o,
		key:      bytes.Clone(state.X25519Key),
		addrs:    addrs,
		tun:      tunDev,
		tnet:     tnet,
		gateways: gws,
	}

	for _, addr := range addrs {
		if addr.Is4() {
			ret.hasV4 = true
		} else {
			ret.hasV6 = true
		}
	}

	switch o.Tunnel {
	case userv1.ConnectRequest_Initialize_QUICV0:
		ret.quic = newQUICEngine(ret, mtu)
		ret.quic.start(gws)
	default:
		ret.wg = device.NewDevice(tunDev, conn.NewStdNetBind(),
			device.NewLogger(device.LogLevelSilent, ""))

		if err := ret.wg.IpcSet(ret.wgUAPI(gws)); err != nil {
			ret.wg.Close()
			return nil, errors.Errorf("Could not configure the WireGuard device: %+v", err)
		}

		if err := ret.wg.Up(); err != nil {
			ret.wg.Close()
			return nil, err
		}
	}

	return ret, nil
}

func (c *VClient) DataPlane(o DataPlaneOpts) (*DataPlane, error) {
	if o.AccessToken == "" {
		o.AccessToken = c.Session.AccessToken
	}
	o.Tunnel = c.opts.Tunnel

	state := c.State()
	if state == nil {
		return nil, errors.Errorf("The client is not connected")
	}

	ret, err := NewDataPlane(state, c.Gateways(), o)
	if err != nil {
		return nil, err
	}

	c.OnGateways(func(gws []*userv1.Gateway) {
		cur := c.State()
		if cur == nil || !bytes.Equal(cur.X25519Key, ret.key) {
			return
		}
		if err := ret.UpdateGateways(gws); err != nil {
			zap.L().Debug("Could not update the data plane Gateways", zap.Error(err))
		}
	})

	return ret, nil
}

func wgKeyHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", errors.Errorf("Invalid WireGuard key length %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func (d *DataPlane) endpoint(gw *userv1.Gateway, port int32) string {
	if d.opts.EndpointOverride != nil {
		if ret := d.opts.EndpointOverride(gw); ret != "" {
			return ret
		}
	}

	if len(gw.Addresses) == 0 {
		return ""
	}

	return net.JoinHostPort(gw.Addresses[0], strconv.Itoa(int(port)))
}

func (d *DataPlane) gwPrefixes(gw *userv1.Gateway) []netip.Prefix {
	var ret []netip.Prefix
	for _, cidr := range gw.CIDRs {
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if (pfx.Addr().Is4() && d.hasV4) || (pfx.Addr().Is6() && d.hasV6) {
			ret = append(ret, pfx)
		}
	}
	return ret
}

func (d *DataPlane) wgUAPI(gws []*userv1.Gateway) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(d.key))
	b.WriteString("replace_peers=true\n")

	for _, gw := range gws {
		if gw.Wireguard == nil || gw.Wireguard.PublicKey == "" {
			continue
		}

		pub, err := wgKeyHex(gw.Wireguard.PublicKey)
		if err != nil {
			continue
		}

		endpoint := d.endpoint(gw, gw.Wireguard.Port)
		if endpoint == "" {
			continue
		}

		fmt.Fprintf(&b, "public_key=%s\n", pub)
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", d.opts.KeepAliveSeconds)
		b.WriteString("replace_allowed_ips=true\n")
		for _, pfx := range d.gwPrefixes(gw) {
			fmt.Fprintf(&b, "allowed_ip=%s\n", pfx)
		}
	}

	return b.String()
}

func (d *DataPlane) UpdateGateways(gws []*userv1.Gateway) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.gateways = gws
	d.mu.Unlock()

	if d.quic != nil {
		d.quic.sync(gws)
		return nil
	}

	return d.wg.IpcSet(d.wgUAPI(gws))
}

func (d *DataPlane) Addrs() []netip.Addr { return d.addrs }

func (d *DataPlane) Matches(state *userv1.ConnectionState) bool {
	return state != nil && bytes.Equal(d.key, state.X25519Key)
}

func (d *DataPlane) Tunnel() userv1.ConnectRequest_Initialize_ConnectionType { return d.opts.Tunnel }

func (d *DataPlane) Gateways() []*userv1.Gateway {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gateways
}

func (d *DataPlane) GatewayFor(addr netip.Addr) *userv1.Gateway {
	for _, gw := range d.Gateways() {
		for _, cidr := range gw.CIDRs {
			if pfx, err := netip.ParsePrefix(cidr); err == nil && pfx.Contains(addr) {
				return gw
			}
		}
	}
	return nil
}

func (d *DataPlane) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.tnet.DialContext(ctx, network, addr)
}

func (d *DataPlane) HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         d.tnet.DialContext,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

func (d *DataPlane) Get(ctx context.Context, url string, timeout time.Duration) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}

	c := &http.Client{
		Transport: &http.Transport{
			DialContext:       d.tnet.DialContext,
			DisableKeepAlives: true,
		},
	}

	res, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return res.StatusCode, nil, err
	}

	return res.StatusCode, body, nil
}

func (d *DataPlane) Stats() (map[string]GatewayStats, error) {
	if d.quic != nil {
		return d.quic.stats(), nil
	}

	out, err := d.wg.IpcGet()
	if err != nil {
		return nil, err
	}

	byKey := map[string]string{}
	for _, gw := range d.Gateways() {
		if gw.Wireguard == nil {
			continue
		}
		if pub, err := wgKeyHex(gw.Wireguard.PublicKey); err == nil {
			byKey[pub] = gw.Id
		}
	}

	return parseUAPIStats(out, byKey), nil
}

func parseUAPIStats(out string, byKey map[string]string) map[string]GatewayStats {
	ret := map[string]GatewayStats{}

	var cur *GatewayStats
	var sec, nsec int64

	flush := func() {
		if cur == nil {
			return
		}
		if sec > 0 || nsec > 0 {
			cur.LastHandshake = time.Unix(sec, nsec)
		}
		ret[cur.ID] = *cur
		cur = nil
		sec, nsec = 0, 0
	}

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		k, v, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}

		switch k {
		case "public_key":
			flush()
			id, ok := byKey[v]
			if !ok {
				id = v
			}
			cur = &GatewayStats{ID: id}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "last_handshake_time_sec":
			sec, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	flush()

	return ret
}

func StatsDelta(before, after map[string]GatewayStats) map[string]GatewayStats {
	ret := map[string]GatewayStats{}
	for id, cur := range after {
		prev := before[id]
		ret[id] = GatewayStats{
			ID:            id,
			TxBytes:       cur.TxBytes - min(prev.TxBytes, cur.TxBytes),
			RxBytes:       cur.RxBytes - min(prev.RxBytes, cur.RxBytes),
			TxPackets:     cur.TxPackets - min(prev.TxPackets, cur.TxPackets),
			RxPackets:     cur.RxPackets - min(prev.RxPackets, cur.RxPackets),
			LastHandshake: cur.LastHandshake,
			Connects:      cur.Connects - min(prev.Connects, cur.Connects),
			LastErr:       cur.LastErr,
		}
	}
	return ret
}

func (d *DataPlane) WaitReady(ctx context.Context) error {
	if d.quic == nil {
		return nil
	}
	return d.quic.waitReady(ctx)
}

func (d *DataPlane) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	d.mu.Unlock()

	if d.quic != nil {
		d.quic.close()
		d.tun.Close()
		return
	}

	d.wg.Close()
}

type quicGW struct {
	gw     *userv1.Gateway
	cidrs  []netip.Prefix
	cancel context.CancelFunc

	mu       sync.Mutex
	conn     *quic.Conn
	connects int
	lastErr  string
	ready    chan struct{}

	txPackets atomic.Uint64
	rxPackets atomic.Uint64
	txBytes   atomic.Uint64
	rxBytes   atomic.Uint64
}

func (g *quicGW) current() *quic.Conn {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.conn
}

type quicEngine struct {
	dp  *DataPlane
	mtu int

	ctx    context.Context
	cancel context.CancelFunc

	mu  sync.Mutex
	gws map[string]*quicGW

	routes atomic.Pointer[[]*quicGW]
}

func newQUICEngine(dp *DataPlane, mtu int) *quicEngine {
	ctx, cancel := context.WithCancel(context.Background())
	return &quicEngine{
		dp:     dp,
		mtu:    mtu,
		ctx:    ctx,
		cancel: cancel,
		gws:    map[string]*quicGW{},
	}
}

func (e *quicEngine) start(gws []*userv1.Gateway) {
	e.sync(gws)
	go e.tunReadLoop()
}

func (e *quicEngine) sync(gws []*userv1.Gateway) {
	e.mu.Lock()
	defer e.mu.Unlock()

	seen := map[string]bool{}
	for _, gw := range gws {
		if gw.Quicv0 == nil {
			continue
		}
		seen[gw.Id] = true

		if _, ok := e.gws[gw.Id]; ok {
			continue
		}

		ctx, cancel := context.WithCancel(e.ctx)
		g := &quicGW{
			gw:     gw,
			cidrs:  e.dp.gwPrefixes(gw),
			cancel: cancel,
			ready:  make(chan struct{}),
		}
		e.gws[gw.Id] = g
		go e.maintain(ctx, g)
	}

	for id, g := range e.gws {
		if !seen[id] {
			g.cancel()
			delete(e.gws, id)
		}
	}

	routes := make([]*quicGW, 0, len(e.gws))
	for _, g := range e.gws {
		routes = append(routes, g)
	}
	e.routes.Store(&routes)
}

func (e *quicEngine) maintain(ctx context.Context, g *quicGW) {
	for ctx.Err() == nil {
		qconn, err := e.dial(ctx, g.gw)
		if err != nil {
			g.mu.Lock()
			g.lastErr = err.Error()
			g.mu.Unlock()

			if Sleep(ctx, quicRedialPeriod) != nil {
				return
			}
			continue
		}

		g.mu.Lock()
		g.conn = qconn
		g.connects++
		g.lastErr = ""
		select {
		case <-g.ready:
		default:
			close(g.ready)
		}
		g.mu.Unlock()

		e.receiveLoop(ctx, g, qconn)

		qconn.CloseWithError(0, "")

		g.mu.Lock()
		if g.conn == qconn {
			g.conn = nil
		}
		g.mu.Unlock()

		if Sleep(ctx, quicRedialPeriod) != nil {
			return
		}
	}
}

func encodeQUICMsg(msg pbutils.Message, typ uint32) ([]byte, error) {
	payload, err := pbutils.Marshal(msg)
	if err != nil {
		return nil, err
	}

	ret := make([]byte, quicInitHdrSize+len(payload))
	binary.BigEndian.PutUint32(ret[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(ret[4:quicInitHdrSize], typ)
	copy(ret[quicInitHdrSize:], payload)

	return ret, nil
}

func decodeQUICMsg(r io.Reader) ([]byte, uint32, error) {
	var hdr [quicInitHdrSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}

	size := binary.BigEndian.Uint32(hdr[0:4])
	typ := binary.BigEndian.Uint32(hdr[4:quicInitHdrSize])
	if typ == 0 || size == 0 || size > quicMaxPayload {
		return nil, 0, errors.Errorf("Invalid QUICv0 message: type=%d size=%d", typ, size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, 0, err
	}

	return payload, typ, nil
}

func (e *quicEngine) dial(ctx context.Context, gw *userv1.Gateway) (*quic.Conn, error) {
	addr := e.dp.endpoint(gw, gw.Quicv0.Port)
	if addr == "" {
		return nil, errors.Errorf("The Gateway %s has no address", gw.Id)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if e.dp.opts.TLSConfig != nil {
		tlsCfg = e.dp.opts.TLSConfig.Clone()
		tlsCfg.MinVersion = tls.VersionTLS13
	}
	tlsCfg.MaxVersion = tls.VersionTLS13
	tlsCfg.NextProtos = []string{"h3"}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = gw.Hostname
	}

	keepAlive := time.Duration(gw.Quicv0.KeepAliveSeconds) * time.Second
	if keepAlive <= 0 {
		keepAlive = 30 * time.Second
	}

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	qconn, err := quic.DialAddr(dialCtx, addr, tlsCfg, &quic.Config{
		EnableDatagrams:      true,
		Versions:             []quic.Version{quic.Version1, quic.Version2},
		KeepAlivePeriod:      keepAlive,
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       60 * time.Second,
	})
	if err != nil {
		return nil, errors.Errorf("Could not dial the Gateway %s at %s: %+v", gw.Id, addr, err)
	}

	if err := e.initConn(dialCtx, qconn); err != nil {
		qconn.CloseWithError(0, "")
		return nil, errors.Errorf("Could not initialize the Gateway %s: %+v", gw.Id, err)
	}

	return qconn, nil
}

func (e *quicEngine) initConn(ctx context.Context, qconn *quic.Conn) error {
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	if deadline, ok := ctx.Deadline(); ok {
		stream.SetDeadline(deadline)
	}

	req, err := encodeQUICMsg(&quicv0.InitRequest{AccessToken: e.dp.opts.AccessToken}, quicInitMsgType)
	if err != nil {
		return err
	}

	if _, err := stream.Write(req); err != nil {
		return err
	}

	payload, typ, err := decodeQUICMsg(stream)
	if err != nil {
		return err
	}
	if typ != quicInitMsgType {
		return errors.Errorf("Unexpected init response type %d", typ)
	}

	resp := &quicv0.InitResponse{}
	if err := pbutils.Unmarshal(payload, resp); err != nil {
		return err
	}
	if resp.Type != quicv0.InitResponse_OK {
		return errors.Errorf("The Gateway rejected the init request: %s", resp.Type)
	}

	return nil
}

func (e *quicEngine) receiveLoop(ctx context.Context, g *quicGW, qconn *quic.Conn) {
	bufs := make([][]byte, 1)

	for {
		msg, err := qconn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}

		g.rxPackets.Add(1)
		g.rxBytes.Add(uint64(len(msg)))

		bufs[0] = msg
		if _, err := e.dp.tun.Write(bufs, 0); err != nil && e.ctx.Err() != nil {
			return
		}
	}
}

func packetDst(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 {
		return netip.Addr{}, false
	}

	switch pkt[0] >> 4 {
	case 4:
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	default:
		return netip.Addr{}, false
	}
}

func (e *quicEngine) route(dst netip.Addr) *quicGW {
	routes := e.routes.Load()
	if routes == nil {
		return nil
	}

	for _, g := range *routes {
		for _, pfx := range g.cidrs {
			if pfx.Contains(dst) {
				return g
			}
		}
	}

	return nil
}

func (e *quicEngine) tunReadLoop() {
	batch := max(1, e.dp.tun.BatchSize())
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, quicMaxPacket)
	}
	sizes := make([]int, batch)

	for {
		n, err := e.dp.tun.Read(bufs, sizes, 0)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}

		if e.ctx.Err() != nil {
			continue
		}

		for i := range n {
			pkt := bufs[i][:sizes[i]]

			dst, ok := packetDst(pkt)
			if !ok {
				continue
			}

			g := e.route(dst)
			if g == nil {
				continue
			}

			qconn := g.current()
			if qconn == nil {
				continue
			}

			if err := qconn.SendDatagram(bytes.Clone(pkt)); err == nil {
				g.txPackets.Add(1)
				g.txBytes.Add(uint64(len(pkt)))
			}
		}
	}
}

func (e *quicEngine) waitReady(ctx context.Context) error {
	e.mu.Lock()
	gws := make([]*quicGW, 0, len(e.gws))
	for _, g := range e.gws {
		gws = append(gws, g)
	}
	e.mu.Unlock()

	for _, g := range gws {
		select {
		case <-g.ready:
		case <-ctx.Done():
			g.mu.Lock()
			lastErr := g.lastErr
			g.mu.Unlock()
			return errors.Errorf("The QUICv0 Gateway %s is not connected: %s", g.gw.Id, lastErr)
		}
	}

	return nil
}

func (e *quicEngine) stats() map[string]GatewayStats {
	e.mu.Lock()
	defer e.mu.Unlock()

	ret := map[string]GatewayStats{}
	for id, g := range e.gws {
		g.mu.Lock()
		ret[id] = GatewayStats{
			ID:        id,
			TxPackets: g.txPackets.Load(),
			RxPackets: g.rxPackets.Load(),
			TxBytes:   g.txBytes.Load(),
			RxBytes:   g.rxBytes.Load(),
			Connects:  g.connects,
			LastErr:   g.lastErr,
		}
		g.mu.Unlock()
	}

	return ret
}

func (e *quicEngine) close() {
	e.cancel()

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, g := range e.gws {
		if qconn := g.current(); qconn != nil {
			qconn.CloseWithError(0, "")
		}
	}
}

func DominantGateway(delta map[string]GatewayStats) string {
	var ret string
	var best uint64
	for id, s := range delta {
		if s.RxBytes > best || (s.RxBytes == best && best > 0 && id < ret) {
			ret = id
			best = s.RxBytes
		}
	}
	return ret
}

func GatewayIDs(stats map[string]GatewayStats, minBytes uint64) []string {
	var ret []string
	for id, s := range stats {
		if s.RxBytes >= minBytes {
			ret = append(ret, id)
		}
	}
	sort.Strings(ret)
	return ret
}
