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
	"os"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/tun"
	bufferv2 "gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func newTestNetstackCtl(t *testing.T) *Controller {
	c := &Controller{
		ipv4Supported: true,
		ipv6Supported: true,
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Addresses: []*metav1.DualStackNetwork{
					{
						V4: "100.64.0.2/32",
						V6: "fd00::2/128",
					},
				},
			},
			Info: &cliconfigv1.Connection_Info{
				Cluster: &cliconfigv1.Connection_Info_Cluster{
					Domain: "example.com",
				},
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				DeviceName: "octelium0",
				Mtu:        1280,
				IgnoreDNS:  true,
			},
		},
	}

	assert.Nil(t, c.createNetstackTUN())
	assert.True(t, c.isNetstack)
	assert.NotNil(t, c.nsTun)

	return c
}

func newTestPacketBuffer() *stack.PacketBuffer {
	pkt := make([]byte, 60)
	pkt[0] = 4 << 4

	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData(pkt),
	})
}

func TestNetTunCloseIsIdempotent(t *testing.T) {
	c := newTestNetstackCtl(t)

	assert.Nil(t, c.nsTun.Close())
	assert.Nil(t, c.nsTun.Close())
	assert.Nil(t, c.nsTun.Close())
}

func TestNetTunReadAfterClose(t *testing.T) {
	c := newTestNetstackCtl(t)

	assert.Nil(t, c.nsTun.Close())

	buf := [][]byte{make([]byte, 65535)}
	sizes := []int{0}

	n, err := c.nsTun.Read(buf, sizes, 0)
	assert.Equal(t, 0, n)
	assert.ErrorIs(t, err, os.ErrClosed)
}

func TestNetTunReadUnblocksOnClose(t *testing.T) {
	c := newTestNetstackCtl(t)

	errCh := make(chan error, 1)
	go func() {
		buf := [][]byte{make([]byte, 65535)}
		sizes := []int{0}
		_, err := c.nsTun.Read(buf, sizes, 0)
		errCh <- err
	}()

	assert.Nil(t, c.nsTun.Close())
	assert.ErrorIs(t, <-errCh, os.ErrClosed)
}

func TestNetTunWritePacketAfterClose(t *testing.T) {
	c := newTestNetstackCtl(t)
	ep := (*endpoint)(c.nsTun)

	assert.Nil(t, c.nsTun.Close())

	pkt := newTestPacketBuffer()
	defer pkt.DecRef()

	assert.NotNil(t, ep.WritePacket(pkt))
}

func TestNetTunConcurrentWritePacketAndClose(t *testing.T) {
	c := newTestNetstackCtl(t)
	ep := (*endpoint)(c.nsTun)

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkt := newTestPacketBuffer()
			defer pkt.DecRef()
			ep.WritePacket(pkt)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.Nil(t, c.nsTun.Close())
	}()

	wg.Wait()
}

func TestCreateNetstackTUNWithInvalidAddresses(t *testing.T) {
	c := &Controller{
		ipv4Supported: true,
		ipv6Supported: true,
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Addresses: []*metav1.DualStackNetwork{
					{
						V4: "100.64.0.2/32",
					},
					{
						V4: "100.64.0.2/32",
					},
				},
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				DeviceName: "octelium0",
				Mtu:        1280,
			},
		},
	}

	assert.NotNil(t, c.createNetstackTUN())
	assert.False(t, c.isNetstack)
	assert.Nil(t, c.nsTun)
}

func TestControllerCloseWithNetstackTUN(t *testing.T) {
	c := newTestNetstackCtl(t)
	nsTun := c.nsTun

	assert.Nil(t, c.Close())
	assert.Nil(t, c.Close())

	buf := [][]byte{make([]byte, 65535)}
	sizes := []int{0}
	_, err := nsTun.Read(buf, sizes, 0)
	assert.ErrorIs(t, err, os.ErrClosed)
}

func testControllerNetstackAddresses(c *Controller) []string {
	var ret []string
	for _, addr := range c.nsTun.stack.AllAddresses()[1] {
		if addr.AddressWithPrefix.Address == header.IPv4Broadcast {
			continue
		}
		ret = append(ret, addr.AddressWithPrefix.String())
	}
	return ret
}

func testControllerNetstackRoutes(c *Controller) []tcpip.Route {
	ret := c.nsTun.stack.GetRouteTable()
	for i := range ret {
		ret[i].RouteEntry = tcpip.RouteEntry{}
	}
	return ret
}

func TestNetstackAddressesAndRoutesByIPMode(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			c.c.Preferences.Mtu = 1420
			c.c.Connection.Addresses = append(c.c.Connection.Addresses,
				&metav1.DualStackNetwork{V4: "100.64.0.3/24", V6: "fd00::3/64"})
			if !assert.Nil(t, c.createNetstackTUN()) {
				return
			}
			t.Cleanup(func() { assert.Nil(t, c.Close()) })

			var addresses []string
			var routes []tcpip.Route
			if tt.v4 {
				addresses = append(addresses, "100.64.0.2/32", "100.64.0.3/32")
				routes = append(routes, tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
			}
			if tt.v6 {
				addresses = append(addresses, "fd00::2/128", "fd00::3/128")
				routes = append(routes, tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})
			}
			assert.ElementsMatch(t, addresses, testControllerNetstackAddresses(c))
			assert.Equal(t, routes, testControllerNetstackRoutes(c))
			assert.Equal(t, tt.v4, c.nsTun.hasV4)
			assert.Equal(t, tt.v6, c.nsTun.hasV6)
			assert.Same(t, c.nsTun, c.getTUNDev())
			assert.Same(t, (*Net)(c.nsTun), c.GetGoNet())
			assert.Same(t, (*Net)(c.nsTun), c.GetNetstackNet())
			mtu, err := c.nsTun.MTU()
			assert.Nil(t, err)
			assert.Equal(t, 1420, mtu)
			select {
			case event := <-c.nsTun.Events():
				assert.Equal(t, tun.Event(tun.EventUp), event)
			default:
				t.Fatal("netstack TUN did not signal that it is up")
			}

			assert.Nil(t, c.setRoutes())
			assert.Nil(t, c.unsetRoutes())
			assert.Nil(t, c.DeleteDev())
			assert.Equal(t, routes, testControllerNetstackRoutes(c))
		})
	}
}

func TestNetstackReconcilesRemovedAndDuplicateAddresses(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			if !assert.Nil(t, c.createNetstackTUN()) {
				return
			}
			t.Cleanup(func() { assert.Nil(t, c.Close()) })
			routes := testControllerNetstackRoutes(c)
			addr := &metav1.DualStackNetwork{V4: "100.64.0.9/32", V6: "fd00::9/128"}
			c.c.Connection.Addresses = []*metav1.DualStackNetwork{addr, addr, {}}
			assert.Nil(t, c.SetDevAddrs())
			var want []string
			if tt.v4 {
				want = append(want, addr.V4)
			}
			if tt.v6 {
				want = append(want, addr.V6)
			}
			assert.ElementsMatch(t, want, testControllerNetstackAddresses(c))
			assert.Nil(t, c.SetDevAddrs())
			assert.ElementsMatch(t, want, testControllerNetstackAddresses(c))
			c.c.Connection.Addresses = nil
			assert.Nil(t, c.SetDevAddrs())
			assert.Empty(t, testControllerNetstackAddresses(c))
			assert.Equal(t, routes, testControllerNetstackRoutes(c))
		})
	}
}

func TestNetstackIgnoresDisabledAddressFamily(t *testing.T) {
	for _, tt := range testControllerIPModes[:2] {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			if tt.v4 {
				c.c.Connection.Addresses[0].V6 = "invalid"
			} else {
				c.c.Connection.Addresses[0].V4 = "invalid"
			}
			if !assert.Nil(t, c.createNetstackTUN()) {
				return
			}
			t.Cleanup(func() { assert.Nil(t, c.Close()) })
			assert.Nil(t, c.SetDevAddrs())
			assert.Len(t, testControllerNetstackAddresses(c), 1)
		})
	}
}

func TestNetstackAddressValidationPreservesCurrentAddresses(t *testing.T) {
	for _, tt := range []struct {
		name string
		addr *metav1.DualStackNetwork
	}{
		{"invalid-v4", &metav1.DualStackNetwork{V4: "100.64.0.3/99"}},
		{"invalid-v6", &metav1.DualStackNetwork{V6: "fd00::3/129"}},
		{"wrong-v4-family", &metav1.DualStackNetwork{V4: "fd00::3/128"}},
		{"invalid-second-family", &metav1.DualStackNetwork{V4: "100.64.0.3/32", V6: "invalid"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
			if !assert.Nil(t, c.createNetstackTUN()) {
				return
			}
			t.Cleanup(func() { assert.Nil(t, c.Close()) })
			old := testControllerNetstackAddresses(c)
			c.c.Connection.Addresses = []*metav1.DualStackNetwork{tt.addr}
			assert.NotNil(t, c.SetDevAddrs())
			assert.ElementsMatch(t, old, testControllerNetstackAddresses(c))
		})
	}
}

func TestNetstackAddressUpdateRequiresInitializedTUN(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	assert.EqualError(t, c.SetDevAddrs(), "The netstack TUN is not initialized")
	assert.Nil(t, c.GetGoNet())
	assert.Nil(t, c.GetNetstackNet())
}
