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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/quicv0"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	clientV4 = "100.65.0.2"
	clientV6 = "fdee:1::2"
)

type testGateway struct {
	id    string
	addrs []netip.Addr
	cidrs []string
	port  int
	key   wgtypes.Key
	dev   *device.Device
}

func freeUDPPort(t *testing.T) int {
	t.Helper()

	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer c.Close()

	return c.LocalAddr().(*net.UDPAddr).Port
}

func serveHTTP(t *testing.T, tnet *netstack.Net, addr netip.Addr, body string) {
	t.Helper()

	lis, err := tnet.ListenTCP(&net.TCPAddr{IP: addr.AsSlice(), Port: 80})
	require.NoError(t, err)

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s from %s", body, r.RemoteAddr)
	})}
	go srv.Serve(lis)
	t.Cleanup(func() { srv.Close() })
}

func newTestWGGateway(t *testing.T, id string, cidrs []string, addrs ...netip.Addr) *testGateway {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	tunDev, tnet, err := netstack.CreateNetTUN(addrs, nil, 1420)
	require.NoError(t, err)

	dev := device.NewDevice(tunDev, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)

	port := freeUDPPort(t)
	require.NoError(t, dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n",
		hex.EncodeToString(key[:]), port)))
	require.NoError(t, dev.Up())

	for _, addr := range addrs {
		serveHTTP(t, tnet, addr, id)
	}

	return &testGateway{id: id, addrs: addrs, cidrs: cidrs, port: port, key: key, dev: dev}
}

func (g *testGateway) allowPeer(t *testing.T, pub wgtypes.Key, allowed ...string) {
	t.Helper()

	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\n", hex.EncodeToString(pub[:]))
	for _, a := range allowed {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a)
	}

	require.NoError(t, g.dev.IpcSet(b.String()))
}

func (g *testGateway) rotate(t *testing.T) {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	require.NoError(t, g.dev.IpcSet(fmt.Sprintf("private_key=%s\n", hex.EncodeToString(key[:]))))
	g.key = key
}

func (g *testGateway) user() *userv1.Gateway {
	return &userv1.Gateway{
		Id:        g.id,
		Addresses: []string{"127.0.0.1"},
		CIDRs:     g.cidrs,
		Wireguard: &userv1.Gateway_WireGuard{
			Port:      int32(g.port),
			PublicKey: g.key.PublicKey().String(),
		},
	}
}

func testState(t *testing.T, mode userv1.ConnectionState_L3Mode) (*userv1.ConnectionState, wgtypes.Key) {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	return &userv1.ConnectionState{
		X25519Key: key[:],
		Mtu:       1280,
		L3Mode:    mode,
		Addresses: []*metav1.DualStackNetwork{
			{V4: clientV4 + "/32", V6: clientV6 + "/128"},
		},
	}, key
}

func mustGet(t *testing.T, dp *DataPlane, url string) string {
	t.Helper()

	var code int
	var body []byte
	var err error

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		code, body, err = dp.Get(t.Context(), url, 3*time.Second)
		if err == nil && code == http.StatusOK {
			return string(body)
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("GET %s did not succeed: code=%d err=%+v", url, code, err)
	return ""
}

func TestDataPlaneWireGuardRouting(t *testing.T) {
	gw1 := newTestWGGateway(t, "gw-1", []string{"10.91.0.0/24", "fd91::/64"},
		netip.MustParseAddr("10.91.0.1"), netip.MustParseAddr("fd91::1"))
	gw2 := newTestWGGateway(t, "gw-2", []string{"10.92.0.0/24", "fd92::/64"},
		netip.MustParseAddr("10.92.0.1"), netip.MustParseAddr("fd92::1"))

	state, key := testState(t, userv1.ConnectionState_BOTH)
	for _, gw := range []*testGateway{gw1, gw2} {
		gw.allowPeer(t, key.PublicKey(), clientV4+"/32", clientV6+"/128")
	}

	dp, err := NewDataPlane(state, []*userv1.Gateway{gw1.user(), gw2.user()}, DataPlaneOpts{})
	require.NoError(t, err)
	t.Cleanup(dp.Close)
	require.NoError(t, dp.WaitReady(t.Context()))

	assert.ElementsMatch(t, []netip.Addr{
		netip.MustParseAddr(clientV4), netip.MustParseAddr(clientV6),
	}, dp.Addrs())

	assert.Equal(t, "gw-2", dp.GatewayFor(netip.MustParseAddr("10.92.0.1")).Id)
	assert.Nil(t, dp.GatewayFor(netip.MustParseAddr("10.93.0.1")))

	before, err := dp.Stats()
	require.NoError(t, err)

	body := mustGet(t, dp, "http://10.91.0.1/")
	assert.True(t, strings.HasPrefix(body, "gw-1 from "+clientV4), body)

	time.Sleep(300 * time.Millisecond)

	mid, err := dp.Stats()
	require.NoError(t, err)

	delta := StatsDelta(before, mid)
	assert.Greater(t, delta["gw-1"].RxBytes, uint64(0))
	assert.Zero(t, delta["gw-2"].TxBytes,
		"traffic to a Service behind gw-1 must not be sent to gw-2")
	assert.False(t, mid["gw-1"].LastHandshake.IsZero())
	assert.True(t, mid["gw-2"].LastHandshake.IsZero(),
		"without traffic or keepalives no handshake is made with gw-2")

	body = mustGet(t, dp, "http://[fd92::1]/")
	assert.True(t, strings.HasPrefix(body, "gw-2 from ["+clientV6+"]"), body)

	time.Sleep(300 * time.Millisecond)

	after, err := dp.Stats()
	require.NoError(t, err)

	delta = StatsDelta(mid, after)
	assert.Greater(t, delta["gw-2"].RxBytes, uint64(0))
	assert.Less(t, delta["gw-1"].TxBytes, uint64(512),
		"only the teardown of the previous connection may still reach gw-1")
	assert.Equal(t, "gw-2", DominantGateway(delta))
	assert.Equal(t, []string{"gw-1", "gw-2"}, GatewayIDs(after, 1))

	t.Run("the Gateway rotates its key", func(t *testing.T) {
		gw1.rotate(t)

		code, _, err := dp.Get(t.Context(), "http://10.91.0.1/", 2*time.Second)
		assert.False(t, err == nil && code == http.StatusOK,
			"the stale Gateway key must break the tunnel")

		require.NoError(t, dp.UpdateGateways([]*userv1.Gateway{gw1.user(), gw2.user()}))
		mustGet(t, dp, "http://10.91.0.1/")
	})
}

func TestDataPlaneWireGuardL3Mode(t *testing.T) {
	gw := newTestWGGateway(t, "gw-1", []string{"10.91.0.0/24", "fd91::/64"},
		netip.MustParseAddr("10.91.0.1"), netip.MustParseAddr("fd91::1"))

	state, key := testState(t, userv1.ConnectionState_V4)
	gw.allowPeer(t, key.PublicKey(), clientV4+"/32")

	dp, err := NewDataPlane(state, []*userv1.Gateway{gw.user()}, DataPlaneOpts{})
	require.NoError(t, err)
	t.Cleanup(dp.Close)

	assert.Equal(t, []netip.Addr{netip.MustParseAddr(clientV4)}, dp.Addrs())
	assert.NotContains(t, dp.wgUAPI(dp.Gateways()), "fd91::/64",
		"an IPv4-only Connection must not route the IPv6 Service range")

	mustGet(t, dp, "http://10.91.0.1/")

	_, _, err = dp.Get(t.Context(), "http://[fd91::1]/", 2*time.Second)
	assert.Error(t, err)
}

func TestDataPlaneWireGuardSpoofedSource(t *testing.T) {
	gw := newTestWGGateway(t, "gw-1", []string{"10.91.0.0/24"}, netip.MustParseAddr("10.91.0.1"))

	state, key := testState(t, userv1.ConnectionState_V4)
	gw.allowPeer(t, key.PublicKey(), clientV4+"/32")

	dp, err := NewDataPlane(state, []*userv1.Gateway{gw.user()}, DataPlaneOpts{
		Addresses: []netip.Addr{netip.MustParseAddr("100.65.0.99")},
	})
	require.NoError(t, err)
	t.Cleanup(dp.Close)

	_, _, err = dp.Get(t.Context(), "http://10.91.0.1/", 3*time.Second)
	assert.Error(t, err, "the Gateway must drop packets whose source is not the Connection address")
}

type testQUICGateway struct {
	addr  string
	token string

	mu   sync.Mutex
	conn *quic.Conn
}

func newTestQUICGateway(t *testing.T, token string, srvAddr netip.Addr) (*testQUICGateway, *x509.CertPool) {
	t.Helper()

	srvTLS, pool := testTLS(t, "octelium-gw-test.example.com")
	srvTLS = srvTLS.Clone()
	srvTLS.NextProtos = []string{"h3"}
	srvTLS.MinVersion = tls.VersionTLS13

	lis, err := quic.ListenAddr("127.0.0.1:0", srvTLS, &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  10 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { lis.Close() })

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{srvAddr}, nil, 1280)
	require.NoError(t, err)
	t.Cleanup(func() { tunDev.Close() })

	serveHTTP(t, tnet, srvAddr, "quic")

	gw := &testQUICGateway{
		addr:  lis.Addr().String(),
		token: token,
	}

	go gw.drain(tunDev)

	go func() {
		for {
			qconn, err := lis.Accept(context.Background())
			if err != nil {
				return
			}
			go gw.handle(qconn, tunDev)
		}
	}()

	return gw, pool
}

func (g *testQUICGateway) drain(tunDev tun.Device) {
	bufs := [][]byte{make([]byte, quicMaxPacket)}
	sizes := []int{0}

	for {
		n, err := tunDev.Read(bufs, sizes, 0)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			continue
		}

		g.mu.Lock()
		qconn := g.conn
		g.mu.Unlock()

		if qconn == nil {
			continue
		}

		for i := range n {
			qconn.SendDatagram(append([]byte(nil), bufs[i][:sizes[i]]...))
		}
	}
}

func (g *testQUICGateway) handle(qconn *quic.Conn, tunDev tun.Device) {
	ctx := qconn.Context()

	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		return
	}

	payload, _, err := decodeQUICMsg(stream)
	if err != nil {
		qconn.CloseWithError(1, "")
		return
	}

	req := &quicv0.InitRequest{}
	if err := pbutils.Unmarshal(payload, req); err != nil || req.AccessToken != g.token {
		qconn.CloseWithError(8, "")
		return
	}

	resp, _ := encodeQUICMsg(&quicv0.InitResponse{Type: quicv0.InitResponse_OK}, quicInitMsgType)
	stream.Write(resp)
	stream.Close()

	g.mu.Lock()
	g.conn = qconn
	g.mu.Unlock()

	for {
		msg, err := qconn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		tunDev.Write([][]byte{msg}, 0)
	}
}

func TestDataPlaneQUIC(t *testing.T) {
	srvAddr := netip.MustParseAddr("10.95.0.1")
	gw, pool := newTestQUICGateway(t, "the-token", srvAddr)

	host, port, err := net.SplitHostPort(gw.addr)
	require.NoError(t, err)

	var portNum int
	fmt.Sscanf(port, "%d", &portNum)

	state, _ := testState(t, userv1.ConnectionState_V4)
	gws := []*userv1.Gateway{{
		Id:        "gw-q",
		Hostname:  "octelium-gw-test.example.com",
		Addresses: []string{host},
		CIDRs:     []string{"10.95.0.0/24"},
		Quicv0:    &userv1.Gateway_QUICV0{Port: int32(portNum)},
	}}

	t.Run("a valid token", func(t *testing.T) {
		dp, err := NewDataPlane(state, gws, DataPlaneOpts{
			Tunnel:      userv1.ConnectRequest_Initialize_QUICV0,
			AccessToken: "the-token",
			TLSConfig:   &tls.Config{RootCAs: pool},
		})
		require.NoError(t, err)
		t.Cleanup(dp.Close)

		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		require.NoError(t, dp.WaitReady(ctx))

		body := mustGet(t, dp, "http://10.95.0.1/")
		assert.True(t, strings.HasPrefix(body, "quic from "+clientV4), body)

		stats, err := dp.Stats()
		require.NoError(t, err)
		assert.Equal(t, 1, stats["gw-q"].Connects)
		assert.Greater(t, stats["gw-q"].TxPackets, uint64(0))
		assert.Greater(t, stats["gw-q"].RxPackets, uint64(0))
	})

	t.Run("a rejected token never becomes ready", func(t *testing.T) {
		dp, err := NewDataPlane(state, gws, DataPlaneOpts{
			Tunnel:      userv1.ConnectRequest_Initialize_QUICV0,
			AccessToken: "a-forged-token",
			TLSConfig:   &tls.Config{RootCAs: pool},
		})
		require.NoError(t, err)
		t.Cleanup(dp.Close)

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()

		err = dp.WaitReady(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "gw-q")
	})
}

func TestParseUAPIStats(t *testing.T) {
	out := strings.Join([]string{
		"private_key=aa",
		"listen_port=1234",
		"public_key=0101",
		"endpoint=127.0.0.1:1",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=5",
		"tx_bytes=10",
		"rx_bytes=20",
		"public_key=0202",
		"tx_bytes=0",
		"rx_bytes=0",
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"errno=0",
	}, "\n")

	got := parseUAPIStats(out, map[string]string{"0101": "gw-1"})

	require.Len(t, got, 2)
	assert.Equal(t, uint64(10), got["gw-1"].TxBytes)
	assert.Equal(t, uint64(20), got["gw-1"].RxBytes)
	assert.Equal(t, time.Unix(1700000000, 5), got["gw-1"].LastHandshake)
	assert.True(t, got["0202"].LastHandshake.IsZero(), "an unknown peer is keyed by its public key")
}

func TestPacketDst(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0] = 0x45
	copy(v4[16:20], []byte{10, 1, 2, 3})

	got, ok := packetDst(v4)
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("10.1.2.3"), got)

	v6 := make([]byte, 40)
	v6[0] = 0x60
	want := netip.MustParseAddr("fd00::1234")
	b := want.As16()
	copy(v6[24:40], b[:])

	got, ok = packetDst(v6)
	require.True(t, ok)
	assert.Equal(t, want, got)

	_, ok = packetDst(v6[:30])
	assert.False(t, ok)

	_, ok = packetDst([]byte{0x45})
	assert.False(t, ok)
}
