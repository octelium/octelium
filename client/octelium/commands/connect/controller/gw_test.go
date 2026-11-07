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
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"
)

func newTestGatewayCtl(gws []*userv1.Gateway) *Controller {
	k, _ := wgtypes.GeneratePrivateKey()

	return &Controller{
		wgPrivateKey:  k,
		ipv4Supported: true,
		ipv6Supported: true,
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Gateways: gws,
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				KeepAliveSeconds: 25,
			},
		},
	}
}

func TestToUAPISkipsGatewaysWithoutWireGuard(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	pubKey := k.PublicKey().String()

	c := newTestGatewayCtl([]*userv1.Gateway{
		nil,
		{
			Id:        "no-wireguard",
			Addresses: []string{"1.2.3.4"},
			CIDRs:     []string{"10.0.0.0/8"},
			Quicv0:    &userv1.Gateway_QUICV0{Port: 8443},
		},
		{
			Id:        "no-addresses",
			CIDRs:     []string{"10.0.0.0/8"},
			Wireguard: &userv1.Gateway_WireGuard{Port: 5432, PublicKey: pubKey},
		},
		{
			Id:        "ok",
			Addresses: []string{"5.6.7.8"},
			CIDRs:     []string{"10.0.0.0/8"},
			Wireguard: &userv1.Gateway_WireGuard{Port: 5432, PublicKey: pubKey},
		},
	})

	uapi, err := c.toUAPI()
	assert.NoError(t, err)

	assert.Equal(t, 1, strings.Count(uapi, "public_key="))
	assert.Equal(t, 1, strings.Count(uapi, "endpoint="))
	assert.True(t, strings.Contains(uapi, "endpoint=5.6.7.8:5432"))
}

func TestGatewayEventsWithoutDevice(t *testing.T) {
	ctx := context.Background()

	c := newTestGatewayCtl(nil)
	c.isNetstack = true

	assert.NotNil(t, c.AddGateway(ctx, nil))
	assert.NotNil(t, c.UpdateGateway(ctx, nil))

	assert.NotNil(t, c.AddGateway(ctx, &userv1.Gateway{
		Id:        "gw-1",
		Addresses: []string{"1.2.3.4"},
		Wireguard: &userv1.Gateway_WireGuard{Port: 5432},
	}))

	assert.NotNil(t, c.DeleteGateway(ctx, "gw-1"))
}

func TestGatewayEventsWithoutQUICEngine(t *testing.T) {
	ctx := context.Background()

	c := newTestGatewayCtl(nil)
	c.isQUIC = true

	assert.NotNil(t, c.AddGateway(ctx, &userv1.Gateway{
		Id:     "gw-1",
		Quicv0: &userv1.Gateway_QUICV0{Port: 8443},
	}))

	assert.Nil(t, c.DeleteGateway(ctx, "gw-1"))
}

func TestGetGWFromPktEmpty(t *testing.T) {
	e := &quicEngine{
		quicGWMap: quicGWMap{
			gwMap: make(map[string]*quicGW),
		},
	}

	assert.Nil(t, e.getGWFromPkt(nil))
	assert.Nil(t, e.getGWFromPkt([]byte{}))
}

func TestGetClusterDNSServersWithoutDNS(t *testing.T) {
	c := newTestGatewayCtl(nil)

	assert.Nil(t, c.getClusterDNSServers())
}

func TestGatewayKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to reproduce CL-012 in tmp/client-test-report.md")
	}
	t.Run("CL-012-QUIC-gateway-update", func(t *testing.T) {
		old := &userv1.Gateway{Id: "gw", Addresses: []string{"192.0.2.1"}, Quicv0: &userv1.Gateway_QUICV0{Port: 443}}
		c := newTestGatewayCtl([]*userv1.Gateway{old})
		c.isQUIC = true
		updated := proto.Clone(old).(*userv1.Gateway)
		updated.Addresses = []string{"192.0.2.2"}
		assert.NoError(t, c.UpdateGateway(t.Context(), updated))
		assert.Equal(t, updated.Addresses, c.c.Connection.Gateways[0].Addresses)
	})
}

func TestGatewayEndpointByHostIPFamily(t *testing.T) {
	for _, mode := range testControllerIPModes {
		t.Run(mode.name, func(t *testing.T) {
			for _, tt := range []struct {
				name      string
				addresses []string
				ipv4      bool
				ipv6      bool
				want      string
			}{
				{"ipv4-host", []string{"2001:db8::1", "192.0.2.1"}, true, false, "192.0.2.1:51820"},
				{"ipv6-host", []string{"192.0.2.1", "2001:db8::1"}, false, true, "[2001:db8::1]:51820"},
				{"dual-stack-ipv6-first", []string{"2001:db8::1", "192.0.2.1"}, true, true, "[2001:db8::1]:51820"},
				{"dual-stack-ipv4-first", []string{"192.0.2.1", "2001:db8::1"}, true, true, "192.0.2.1:51820"},
				{"unknown-host", []string{"2001:db8::1", "192.0.2.1"}, false, false, "[2001:db8::1]:51820"},
				{"unsupported-family", []string{"2001:db8::1"}, true, false, "[2001:db8::1]:51820"},
				{"same-family-order", []string{"192.0.2.2", "192.0.2.1"}, true, false, "192.0.2.2:51820"},
				{"mapped-ipv4", []string{"2001:db8::1", "::ffff:192.0.2.1"}, true, false, "192.0.2.1:51820"},
				{"invalid-first", []string{"invalid", "", "192.0.2.1"}, true, false, "192.0.2.1:51820"},
				{"unusable-first", []string{"::", "0.0.0.0", "ff02::1", "224.0.0.1", "192.0.2.1"}, true, false, "192.0.2.1:51820"},
			} {
				t.Run(tt.name, func(t *testing.T) {
					c := newTestGatewayCtl(nil)
					c.ipv4Supported = mode.v4
					c.ipv6Supported = mode.v6
					c.checkGatewayRoute = func(addr netip.Addr) bool {
						return (addr.Is4() && tt.ipv4) || (addr.Is6() && tt.ipv6)
					}
					gw := &userv1.Gateway{Addresses: tt.addresses, Wireguard: &userv1.Gateway_WireGuard{PublicKey: c.wgPrivateKey.PublicKey().String(), Port: 51820}}
					c.c.Connection.Gateways = []*userv1.Gateway{gw}
					original := proto.Clone(gw)
					endpoint, err := c.getGatewayEndpoint(gw)
					require.NoError(t, err)
					assert.Equal(t, tt.want, endpoint.String())
					uapi, err := c.toUAPI()
					require.NoError(t, err)
					assert.Contains(t, uapi, "endpoint="+tt.want+"\n")
					assert.True(t, proto.Equal(original, gw))
				})
			}
		})
	}
}

func TestGatewayEndpointInvalidAddresses(t *testing.T) {
	for _, addresses := range [][]string{nil, {"invalid"}, {"::", "224.0.0.1"}} {
		c := newTestGatewayCtl(nil)
		_, err := c.getGatewayEndpoint(&userv1.Gateway{Id: "gw", Addresses: addresses, Wireguard: &userv1.Gateway_WireGuard{}})
		assert.ErrorContains(t, err, "does not have a valid endpoint address")
	}
}

func TestSelectGatewayAddr(t *testing.T) {
	first := netip.MustParseAddr("192.0.2.1")
	second := netip.MustParseAddr("2001:db8::1")
	addrs := []netip.Addr{first, second}

	t.Run("nil-check", func(t *testing.T) {
		assert.Equal(t, first, selectGatewayAddr(addrs, nil))
	})

	t.Run("single-address-skips-check", func(t *testing.T) {
		assert.Equal(t, second, selectGatewayAddr([]netip.Addr{second}, func(netip.Addr) bool {
			t.Fatal("checked the route of the only address")
			return false
		}))
	})

	t.Run("no-route-falls-back-to-first", func(t *testing.T) {
		var checked []netip.Addr
		assert.Equal(t, first, selectGatewayAddr(addrs, func(addr netip.Addr) bool {
			checked = append(checked, addr)
			return false
		}))
		assert.Equal(t, addrs, checked)
	})

	t.Run("stops-at-first-routable", func(t *testing.T) {
		var checked []netip.Addr
		assert.Equal(t, first, selectGatewayAddr(addrs, func(addr netip.Addr) bool {
			checked = append(checked, addr)
			return true
		}))
		assert.Equal(t, []netip.Addr{first}, checked)
	})

	t.Run("skips-unroutable-first", func(t *testing.T) {
		assert.Equal(t, second, selectGatewayAddr(addrs, func(addr netip.Addr) bool {
			return addr == second
		}))
	})

	t.Run("stuck-check-falls-back-to-first", func(t *testing.T) {
		startedAt := time.Now()
		assert.Equal(t, first, selectGatewayAddr(addrs, func(netip.Addr) bool {
			time.Sleep(20 * gatewayRouteCheckTimeout)
			return false
		}))
		assert.GreaterOrEqual(t, time.Since(startedAt), gatewayRouteCheckTimeout)
		assert.Less(t, time.Since(startedAt), 10*gatewayRouteCheckTimeout)
	})
}

func TestGatewaySrcAddrUsable(t *testing.T) {
	for _, tt := range []struct {
		name string
		src  netip.Addr
		dst  string
		want bool
	}{
		{"invalid", netip.Addr{}, "192.0.2.1", false},
		{"unspecified-ipv4", netip.MustParseAddr("0.0.0.0"), "192.0.2.1", false},
		{"unspecified-ipv6", netip.MustParseAddr("::"), "2001:db8::1", false},
		{"ipv4-link-local", netip.MustParseAddr("169.254.1.1"), "192.0.2.1", false},
		{"ipv6-link-local", netip.MustParseAddr("fe80::1"), "2001:db8::1", false},
		{"ipv6-link-local-zone", netip.MustParseAddr("fe80::1%eth0"), "2001:db8::1", false},
		{"loopback-to-global", netip.MustParseAddr("127.0.0.1"), "192.0.2.1", false},
		{"loopback-to-loopback", netip.MustParseAddr("127.0.0.1"), "127.0.0.1", true},
		{"ula-to-global", netip.MustParseAddr("fd00::5"), "2001:db8::1", false},
		{"ula-to-ula", netip.MustParseAddr("fd00::5"), "fd00::1", true},
		{"global-ipv6", netip.MustParseAddr("2001:db8:1::5"), "2001:db8::1", true},
		{"global-ipv4", netip.MustParseAddr("203.0.113.5"), "192.0.2.1", true},
		{"private-ipv4-behind-nat", netip.MustParseAddr("10.0.0.5"), "192.0.2.1", true},
		{"cgnat-ipv4", netip.MustParseAddr("100.64.0.5"), "192.0.2.1", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isGatewaySrcAddrUsable(tt.src, netip.MustParseAddr(tt.dst)))
		})
	}
}

func TestGatewayAddrRoutableLoopback(t *testing.T) {
	assert.True(t, isGatewayAddrRoutable(netip.MustParseAddr("127.0.0.1")))

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback is not available: %v", err)
	}
	defer conn.Close()
	assert.True(t, isGatewayAddrRoutable(netip.MustParseAddr("::1")))
}

func testGatewayEndpointHostRoutes(t *testing.T, getEndpoint func(*Controller, *userv1.Gateway) string) {
	t.Helper()
	const ipv4 = "198.51.100.10"
	const ipv6 = "2001:db8:ffff::10"

	for _, addresses := range [][]string{{ipv4, ipv6}, {ipv6, ipv4}} {
		for _, addr := range addresses {
			t.Logf("Gateway address %s routable: %v", addr, isGatewayAddrRoutable(netip.MustParseAddr(addr)))
		}

		c := newTestGatewayCtl(nil)
		c.checkGatewayRoute = isGatewayAddrRoutable
		gw := &userv1.Gateway{
			Addresses: addresses,
			Wireguard: &userv1.Gateway_WireGuard{PublicKey: c.wgPrivateKey.PublicKey().String()},
		}
		c.c.Connection.Gateways = []*userv1.Gateway{gw}

		startedAt := time.Now()
		endpoint := getEndpoint(c, gw)
		assert.Less(t, time.Since(startedAt), 10*gatewayRouteCheckTimeout)
		assert.Contains(t, addresses, endpoint)
		t.Logf("Selected %s from %v", endpoint, addresses)
	}
}

func TestGatewayEndpointHostRoutes(t *testing.T) {
	testGatewayEndpointHostRoutes(t, func(c *Controller, gw *userv1.Gateway) string {
		endpoint, err := c.getGatewayEndpoint(gw)
		require.NoError(t, err)
		return endpoint.IP.String()
	})
}
