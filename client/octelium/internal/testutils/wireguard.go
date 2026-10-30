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

package testutils

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"
)

type WGPeer struct {
	Net     *netstack.Net
	Updates chan *userv1.ConnectResponse
	key     wgtypes.Key
	gateway *userv1.Gateway
	mu      sync.Mutex
	state   *userv1.ConnectionState
	addrs   []*metav1.DualStackNetwork
}

func NewWGPeer(t testing.TB) *WGPeer {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	tun, goNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd00::1")}, nil, 1280)
	require.NoError(t, err)
	dev := device.NewDevice(tun, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	pub := clientKey.PublicKey()
	require.NoError(t, dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=100.64.0.0/16\nallowed_ip=fd00::/64\n",
		hex.EncodeToString(key[:]), hex.EncodeToString(pub[:]))))
	require.NoError(t, dev.Up())
	config, err := dev.IpcGet()
	require.NoError(t, err)
	var port int
	for _, line := range strings.Split(config, "\n") {
		if raw, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err = strconv.Atoi(raw)
			require.NoError(t, err)
		}
	}
	require.Positive(t, port)
	return &WGPeer{
		Net: goNet, key: clientKey, Updates: make(chan *userv1.ConnectResponse, 32),
		gateway: &userv1.Gateway{
			Id: "test-gateway", Addresses: []string{"127.0.0.1"}, CIDRs: []string{"100.64.0.1/32", "fd00::1/128"},
			Wireguard: &userv1.Gateway_WireGuard{Port: int32(port), PublicKey: key.PublicKey().String()},
		},
	}
}

func (p *WGPeer) Configure(state *userv1.ConnectionState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state.X25519Key = append([]byte(nil), p.key[:]...)
	state.Gateways = nil
	state.Addresses = append(state.Addresses, p.addrs...)
	p.state = proto.Clone(state).(*userv1.ConnectionState)
}

func (p *WGPeer) SendInitial(stream userv1.MainService_ConnectServer, initial *userv1.ConnectResponse) error {
	p.Configure(initial.GetState())
	if err := stream.Send(initial); err != nil {
		return err
	}
	return p.SendGateway(stream)
}

func (p *WGPeer) SendGateway(stream userv1.MainService_ConnectServer) error {
	return stream.Send(&userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddGateway_{AddGateway: &userv1.ConnectResponse_AddGateway{Gateway: p.gateway}}})
}

type WGAddress struct {
	peer *WGPeer
	addr *net.UDPAddr
	once sync.Once
}

func (p *WGPeer) ReserveUDP(address string, port int) *WGAddress {
	return &WGAddress{peer: p, addr: &net.UDPAddr{IP: net.ParseIP(address), Port: port}}
}

func (a *WGAddress) LocalAddr() net.Addr { return a.addr }

func (a *WGAddress) Close() error {
	a.once.Do(func() {
		addr := &metav1.DualStackNetwork{V4: a.addr.IP.String() + "/32"}
		if a.addr.IP.To4() == nil {
			addr = &metav1.DualStackNetwork{V6: a.addr.IP.String() + "/128"}
		}
		p := a.peer
		p.mu.Lock()
		p.addrs = append(p.addrs, addr)
		var state *userv1.ConnectionState
		if p.state != nil {
			p.state.Addresses = append(p.state.Addresses, addr)
			state = proto.Clone(p.state).(*userv1.ConnectionState)
			state.Gateways = []*userv1.Gateway{p.gateway}
		}
		p.mu.Unlock()
		if state != nil {
			p.Updates <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_State{State: state}}
		}
	})
	return nil
}

func (p *WGPeer) RoundTrip(address string, payload []byte) bool {
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return false
	}
	c, err := p.Net.DialUDP(nil, addr)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := c.Write(payload); err != nil {
		return false
	}
	buf := make([]byte, len(payload)+1)
	n, err := c.Read(buf)
	return err == nil && string(buf[:n]) == string(payload)
}
