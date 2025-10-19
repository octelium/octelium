// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/quicv0"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var tunPacketOffset = 0

const (
	IPv4offsetSrc = 12
	IPv4offsetDst = IPv4offsetSrc + net.IPv4len
)

const (
	IPv6offsetSrc = 8
	IPv6offsetDst = IPv6offsetSrc + net.IPv6len
)

func (c *Controller) doInitDevQUICV0(ctx context.Context) error {

	switch runtime.GOOS {
	case "linux":
	case "darwin":
		tunPacketOffset = 4
	default:
		tunPacketOffset = 4
		// return errors.Errorf("QUIC is currently only supported for Linux and MacOS")
	}

	zap.L().Debug("Initializing the QUIC engine")

	c.quicEngine = newQUICEngine(c)

	if err := c.quicEngine.run(ctx); err != nil {
		return err
	}

	return nil
}

type quicEngine struct {
	ctl       *Controller
	quicGWMap quicGWMap

	tunCh chan []byte

	mu            sync.Mutex
	isClosed      bool
	clusterDomain string

	gwCloseCh chan string
}

type quicGWMap struct {
	sync.RWMutex
	gwMap map[string]*quicGW
}

type quicGW struct {
	sync.Mutex
	gw            *userv1.Gateway
	conn          *quic.Conn
	tunCh         chan<- []byte
	gwCh          chan []byte
	cidrs         []netip.Prefix
	engine        *quicEngine
	clusterDomain string
	isClosed      bool
	cancelFn      context.CancelFunc
	gwCloseCh     chan<- string
}

func newQUICEngine(ctl *Controller) *quicEngine {
	zap.L().Debug("Creating a new QUIC engine")
	return &quicEngine{
		ctl:       ctl,
		tunCh:     make(chan []byte, 1024),
		gwCloseCh: make(chan string, 300),
		quicGWMap: quicGWMap{
			gwMap: make(map[string]*quicGW),
		},
		clusterDomain: ctl.c.Info.Cluster.Domain,
	}
}

func (c *quicEngine) run(ctx context.Context) error {
	zap.L().Debug("Starting running QUIC engine")

	for _, gw := range c.ctl.c.Connection.Gateways {
		if err := c.addGW(ctx, gw); err != nil {
			return errors.Errorf("Could not add GW: %s. %+v", gw.Id, err)
		}
	}

	go c.startTunReadLoop(ctx)
	go c.startTunWriteLoop(ctx)
	go c.startGWReconnectLoop(ctx)

	zap.L().Debug("QUIC engine is now running")

	return nil
}

func (c *quicEngine) getGWByID(id string) *userv1.Gateway {
	for _, gw := range c.ctl.c.Connection.Gateways {
		if gw.Id == id {
			return gw
		}
	}

	return nil
}

func (c *quicEngine) startGWReconnectLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case gwID := <-c.gwCloseCh:
			zap.L().Debug("gw closed. Reconnecting it", zap.String("id", gwID))
			go c.doReconnectGW(ctx, gwID)
		}
	}
}

func (c *quicEngine) doReconnectGW(ctx context.Context, gwID string) error {

	gw := c.getGWByID(gwID)
	if gw == nil {
		zap.L().Debug("Could not find gw. Skipping reconnection", zap.String("id", gwID))
		return nil
	}

	tickerCh := time.NewTicker(1500 * time.Millisecond)
	defer tickerCh.Stop()
	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("Exiting GW reconnection loop", zap.String("id", gwID))
			return nil
		case <-tickerCh.C:
			if err := c.addGW(ctx, gw); err == nil {
				zap.L().Debug("Successfully reconnected gw", zap.String("id", gwID))
				return nil
			} else {
				zap.L().Debug("Could not reconnect gw. Trying again...", zap.String("id", gwID), zap.Error(err))
			}
		}
	}
}

func (c *quicEngine) close() error {
	c.mu.Lock()

	if c.isClosed {
		c.mu.Unlock()
		return nil
	}

	zap.L().Debug("Closing QUIC engine")

	c.isClosed = true
	c.mu.Unlock()

	c.quicGWMap.Lock()
	defer c.quicGWMap.Unlock()

	for _, gw := range c.quicGWMap.gwMap {
		gw.close()
	}

	zap.L().Debug("QUIC engine closed")

	return nil
}

func (c *quicEngine) addGW(ctx context.Context, gw *userv1.Gateway) error {
	c.quicGWMap.Lock()
	defer c.quicGWMap.Unlock()

	quicGW, err := newQUIGW(c, gw)
	if err != nil {
		return err
	}
	c.quicGWMap.gwMap[gw.Id] = quicGW

	return quicGW.run(ctx)
}

func newQUIGW(engine *quicEngine, gw *userv1.Gateway) (*quicGW, error) {

	if gw.Quicv0 == nil {
		return nil, errors.Errorf("Gateway %s does not have QUICv0 info", gw.Id)
	}

	ret := &quicGW{
		engine:        engine,
		gw:            gw,
		tunCh:         engine.tunCh,
		gwCh:          make(chan []byte, 1024),
		clusterDomain: engine.clusterDomain,
		gwCloseCh:     engine.gwCloseCh,
	}

	for _, cidrStr := range gw.CIDRs {
		cidr, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			return nil, err
		}
		ret.cidrs = append(ret.cidrs, cidr)
	}

	zap.L().Debug("Created QUIC gw", zap.String("id", gw.Id))

	return ret, nil
}

const hdrSize = 8

func encodeMsg(resp pbutils.Message, typ uint32) ([]byte, error) {

	respBytes, err := pbutils.Marshal(resp)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(respBytes)+hdrSize)

	binary.BigEndian.PutUint32(buf[0:4], uint32(len(respBytes)))
	binary.BigEndian.PutUint32(buf[4:hdrSize], typ)
	copy(buf[hdrSize:], respBytes[:])
	return buf, nil
}

func decodeMsg(stream *quic.Stream) ([]byte, uint32, error) {
	bufSize := 1024
	buf := make([]byte, bufSize)
	n, err := stream.Read(buf)
	if err != nil {
		return nil, 0, errors.Errorf("Could not read init stream req: %+v", err)
	}

	if n <= hdrSize || n >= 1024 {
		return nil, 0, errors.Errorf("Invalid init stream req size: %d", n)
	}
	payloadSize := binary.BigEndian.Uint32(buf[:4])
	typ := binary.BigEndian.Uint32(buf[4:hdrSize])

	switch typ {
	case 0:
		return nil, 0, errors.Errorf("Invalid msg type")
	}

	if payloadSize > 4096 {
		return nil, 0, errors.Errorf("Invalid msg size")
	}

	if payloadSize+uint32(hdrSize) < uint32(n) {
		return nil, 0, errors.Errorf("msg size does not match")
	}

	if payloadSize+uint32(hdrSize) == uint32(n) {
		return buf[hdrSize:n], typ, nil
	}

	var ni int
	curPayloadSize := uint32(n - hdrSize)

	ret := make([]byte, n)
	copy(ret[:], buf[:n])

	for ; curPayloadSize < payloadSize; curPayloadSize = curPayloadSize + uint32(ni) {
		iBuf := make([]byte, bufSize)
		ni, err = stream.Read(iBuf)
		if err != nil {
			return nil, 0, errors.Errorf("Could not read subsequent stream req %+v", err)
		}
		ret = append(ret, iBuf[:ni]...)
	}

	if uint32(len(ret[hdrSize:])) != payloadSize {
		return nil, 0, errors.Errorf("Final payloadSize does not match: %d ... %d", len(ret[hdrSize:]), payloadSize)
	}

	return ret[hdrSize:], typ, nil
}

func (c *quicGW) connect(ctx context.Context) error {
	var err error

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: ldflags.IsDev() || utils.IsInsecureTLS(),
	}

	quicCfg := &quic.Config{
		EnableDatagrams: true,
		Versions:        []quic.Version{quic.Version1, quic.Version2},
		KeepAlivePeriod: func() time.Duration {
			if c.gw.Quicv0.KeepAliveSeconds == 0 {
				return 30 * time.Second
			}
			return time.Duration(c.gw.Quicv0.KeepAliveSeconds) * time.Second
		}(),
	}

	addr := net.JoinHostPort(c.gw.Hostname, fmt.Sprintf("%d", c.gw.Quicv0.Port))

	zap.L().Debug("Connecting to gw", zap.String("id", c.gw.Id), zap.String("addr", addr))
	c.conn, err = quic.DialAddr(ctx, addr, tlsCfg, quicCfg)
	if err != nil {
		return errors.Errorf("Could not dial QUIC gw: %s: %+v", c.gw.Id, err)
	}

	zap.L().Debug("Opening the init stream", zap.String("id", c.gw.Id))
	initStream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}

	defer initStream.Close()

	sessToken, err := cliutils.GetDB().GetSessionToken(c.engine.ctl.c.Info.Cluster.Domain)
	if err != nil {
		return err
	}

	reqMsg := &quicv0.InitRequest{
		AccessToken: sessToken.AccessToken,
	}

	reqMsgBytes, err := encodeMsg(reqMsg, 1)
	if err != nil {
		return errors.Errorf("Could not encode initReq msg: %+v", err)
	}
	zap.L().Debug("Sending init req", zap.String("id", c.gw.Id))
	_, err = initStream.Write(reqMsgBytes)
	if err != nil {
		return err
	}

	payload, typ, err := decodeMsg(initStream)
	if err != nil {
		return errors.Errorf("Could not decode initResp msg: %+v", err)
	}

	if typ != 1 {
		return errors.Errorf("Invalid response message type")
	}

	respMsg := &quicv0.InitResponse{}
	if err := pbutils.Unmarshal(payload[:], respMsg); err != nil {
		return err
	}

	if respMsg.Type != quicv0.InitResponse_OK {
		return errors.Errorf("Invalid init gw session response: %s", respMsg.Type.String())
	}

	zap.L().Debug("Successfully connected to gw", zap.String("id", c.gw.Id))

	return nil
}

func (c *quicEngine) deleteGWByID(gwID string) error {
	c.quicGWMap.Lock()
	defer c.quicGWMap.Unlock()
	gw, ok := c.quicGWMap.gwMap[gwID]
	if !ok {
		return nil
	}
	gw.close()
	delete(c.quicGWMap.gwMap, gwID)

	return nil
}

func (c *quicGW) run(ctx context.Context) error {

	ctx, cancel := context.WithCancel(ctx)
	c.cancelFn = cancel
	zap.L().Debug("Starting running gw", zap.String("id", c.gw.Id))
	if err := c.connect(ctx); err != nil {
		return err
	}

	go c.startSendToGWLoop(ctx)
	go c.startReceiveFromGWLoop(ctx)
	go c.waitClose(ctx)

	return nil
}

func (c *quicGW) close() {
	c.Lock()
	defer c.Unlock()
	if c.isClosed {
		return
	}
	zap.L().Debug("Closing gw", zap.String("id", c.gw.Id))
	c.isClosed = true
	c.cancelFn()

	c.gwCloseCh <- c.gw.Id

	if c.conn != nil {
		c.conn.CloseWithError(0, "")
	}
}

func (c *quicGW) waitClose(ctx context.Context) {
	defer c.close()

	select {
	case <-ctx.Done():
		zap.L().Debug("ctx done. Exiting gw", zap.String("id", c.gw.Id))
	case <-c.conn.Context().Done():
		zap.L().Debug("Disconnected from gw", zap.String("id", c.gw.Id), zap.Error(c.conn.Context().Err()))
	}
}

/*
func (c *quicGW) reconnect(ctx context.Context) error {
	zap.L().Debug("Starting reconnecting to gw", zap.String("id", c.gw.Id))
	for {

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			err := c.connect(ctx)
			if err == nil {
				zap.L().Debug("Successfully reconnected to gw", zap.String("id", c.gw.Id))
				return nil
			}
			zap.L().Warn("Could not reconnect to gw. Trying again...", zap.String("id", c.gw.Id), zap.Error(err))
			time.Sleep(2 * time.Second)
		}
	}
}
*/

func (c *quicGW) startSendToGWLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case buf := <-c.gwCh:
			if err := c.conn.SendDatagram(buf); err != nil {
				zap.L().Debug("Could not send datagram msg", zap.String("gw", c.gw.Id), zap.Error(err))
			}
		}
	}
}

func (c *quicGW) startReceiveFromGWLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			msg, err := c.conn.ReceiveDatagram(ctx)
			if err != nil {
				zap.L().Debug("Could not receive msg", zap.String("id", c.gw.Id), zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if len(msg) <= ipv4.HeaderLen {
				zap.L().Debug("Invalid length of received msg", zap.String("id", c.gw.Id))
				continue
			}

			c.tunCh <- msg
		}
	}
}

func (c *quicEngine) startTunWriteLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-c.tunCh:

			buffs := make([][]byte, 1)
			buffs[0] = pkt[:]

			if _, err := c.ctl.getTUNDev().Write(buffs, 0); err != nil {
				zap.L().Debug("Could not write to tun", zap.Error(err))
			}
		}
	}
}

func (c *quicEngine) startTunReadLoop(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffs := make([][]byte, 1)
			sizes := make([]int, 1)

			buffs[0] = make([]byte, 1500)

			n, err := c.ctl.getTUNDev().Read(buffs, sizes, tunPacketOffset)
			if err != nil {
				zap.L().Debug("Could not read from tun", zap.Error(err))
				continue
			}

			for i := 0; i < n; i++ {
				pktBuf := buffs[i][tunPacketOffset : sizes[i]+tunPacketOffset]
				c.processTunPkt(pktBuf)
			}

		}
	}
}

func (c *quicEngine) processTunPkt(pkt []byte) {
	c.quicGWMap.RLock()
	defer c.quicGWMap.RUnlock()

	gw := c.getGWFromPkt(pkt)

	if gw != nil {
		gw.gwCh <- pkt
	}
}

func (c *quicEngine) getGWFromPkt(pkt []byte) *quicGW {

	var dst netip.Addr

	switch pkt[0] >> 4 {
	case ipv4.Version:
		if len(pkt) < ipv4.HeaderLen {
			return nil
		}
		var dstBytes [4]byte
		copy(dstBytes[:], pkt[IPv4offsetDst:IPv4offsetDst+net.IPv4len])
		dst = netip.AddrFrom4(dstBytes)
	case ipv6.Version:
		if len(pkt) < ipv6.HeaderLen {
			return nil
		}
		var dstBytes [16]byte
		copy(dstBytes[:], pkt[IPv6offsetDst:IPv6offsetDst+net.IPv6len])
		dst = netip.AddrFrom16(dstBytes)
	default:
		return nil
	}

	for _, gw := range c.quicGWMap.gwMap {
		for _, cidr := range gw.cidrs {
			if cidr.Contains(dst) {
				return gw
			}
		}
	}

	return nil
}
