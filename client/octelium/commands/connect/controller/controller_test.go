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
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"
)

func genConnectionConfig(t *testing.T, domain string) *cliconfigv1.Connection {

	k, _ := wgtypes.GeneratePrivateKey()

	connCfg := &cliconfigv1.Connection{
		Connection: &userv1.ConnectionState{
			X25519Key: k[:],
			Cidr: &metav1.DualStackNetwork{
				V4: "100.64.0.0/16",
				V6: "fdee:be1d::/96",
			},
			Addresses: []*metav1.DualStackNetwork{
				{
					V4: "100.64.1.2/32",
					V6: "fdee:be1d::3/128",
				},
			},
			Gateways: []*userv1.Gateway{},
			Dns: &userv1.DNS{
				Servers: []string{"8.8.8.8"},
			},
		},
		Info: &cliconfigv1.Connection_Info{
			Cluster: &cliconfigv1.Connection_Info_Cluster{
				Domain: domain,
			},
		},

		Preferences: &cliconfigv1.Connection_Preferences{
			DeviceName: fmt.Sprintf("octelium-%s", utilrand.GetRandomStringLowercase(6)),

			IgnoreDNS:        false,
			KeepAliveSeconds: 25,
			Mtu:              1280,

			L3Mode:   cliconfigv1.Connection_Preferences_BOTH,
			LocalDNS: &cliconfigv1.Connection_Preferences_LocalDNS{},

			/*
				ServeOpts: &cliconfigv1.Connection_Preferences_ServeOpts{
					IsEnabled: true,
					ProxyMode: cliconfigv1.Connection_Preferences_ServeOpts_USERSPACE,
				},
			*/
		},
	}

	switch runtime.GOOS {
	case "linux":
		connCfg.Preferences.LinuxPrefs = &cliconfigv1.Connection_Preferences_Linux{}
	case "windows":
		connCfg.Preferences.WindowsPrefs = &cliconfigv1.Connection_Preferences_Windows{}
	case "darwin":
		connCfg.Preferences.MacosPrefs = &cliconfigv1.Connection_Preferences_MacOS{}
		connCfg.Preferences.DeviceName = "utun"
	}

	connCfg.Preferences.LinuxPrefs.ImplementationMode = cliconfigv1.Connection_Preferences_Linux_WG_NETSTACK
	connCfg.Preferences.LinuxPrefs.EnforceImplementationMode = true

	return connCfg
}

func TestController(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("This test needs the Linux WireGuard netstack configuration")
	}
	ctx := context.Background()

	{

		connCfg := genConnectionConfig(t, "example.com")

		c, err := NewController(connCfg)
		assert.Nil(t, err, "%+v", err)

		err = c.Start(context.Background())
		assert.Nil(t, err, "%+v", err)

		ipc, err := c.dev.IpcGet()
		assert.Nil(t, err, "%+v", err)

		zap.S().Debugf("ipc: %s", ipc)

		{
			k, _ := wgtypes.GeneratePrivateKey()

			gw := &userv1.Gateway{
				Id:        utilrand.GetRandomStringLowercase(6),
				Addresses: []string{"1.2.3.4"},

				CIDRs: []string{"1.2.3.4/32"},

				Wireguard: &userv1.Gateway_WireGuard{
					Port:      5432,
					PublicKey: k.PublicKey().String(),
				},
			}

			err := c.AddGateway(ctx, gw)
			assert.Nil(t, err)

			uapiCfg, err := c.dev.IpcGet()
			assert.Nil(t, err)
			cfg := fromUAPI(uapiCfg)

			assert.Equal(t, 1, len(cfg.Peers))
			assert.Equal(t, gw.Wireguard.PublicKey, cfg.Peers[0].PublicKey.String())

			k, _ = wgtypes.GeneratePrivateKey()

			gw.Wireguard.PublicKey = k.PublicKey().String()
			err = c.UpdateGateway(ctx, gw)
			assert.Nil(t, err)

			uapiCfg, err = c.dev.IpcGet()
			assert.Nil(t, err)
			cfg = fromUAPI(uapiCfg)

			assert.Equal(t, 1, len(cfg.Peers))
			assert.Equal(t, gw.Wireguard.PublicKey, cfg.Peers[0].PublicKey.String())

			assert.Nil(t, err)

			err = c.DeleteGateway(ctx, gw.Id)
			assert.Nil(t, err)

			uapiCfg, err = c.dev.IpcGet()
			assert.Nil(t, err)
			cfg = fromUAPI(uapiCfg)

			assert.Equal(t, 0, len(cfg.Peers))
		}

		for i := 0; i < 10; i++ {
			k, _ := wgtypes.GeneratePrivateKey()

			gw := &userv1.Gateway{
				Id:        utilrand.GetRandomStringLowercase(6),
				Addresses: []string{fmt.Sprintf("%d.2.3.4", i)},
				CIDRs:     []string{fmt.Sprintf("%d.2.3.4/32", i)},

				Wireguard: &userv1.Gateway_WireGuard{
					Port:      5432,
					PublicKey: k.PublicKey().String(),
				},
			}

			err := c.AddGateway(ctx, gw)
			assert.Nil(t, err)

			uapiCfg, err := c.dev.IpcGet()
			assert.Nil(t, err)
			cfg := fromUAPI(uapiCfg)

			assert.Equal(t, i+1, len(cfg.Peers))

			k, _ = wgtypes.GeneratePrivateKey()

			gw.Wireguard.PublicKey = k.PublicKey().String()
			err = c.UpdateGateway(ctx, gw)
			assert.Nil(t, err)
			assert.Equal(t, i+1, len(cfg.Peers))
		}

		err = c.Close()
		assert.Nil(t, err)
	}
}

func TestUpdateDNS(t *testing.T) {

	newCtl := func(servers []string) *Controller {
		return &Controller{
			ipv4Supported: true,
			ipv6Supported: true,
			c: &cliconfigv1.Connection{
				Connection: &userv1.ConnectionState{
					Dns: &userv1.DNS{
						Servers: servers,
					},
				},
				Info: &cliconfigv1.Connection_Info{
					Cluster: &cliconfigv1.Connection_Info_Cluster{
						Domain: "example.com",
					},
				},
				Preferences: &cliconfigv1.Connection_Preferences{
					IgnoreDNS: true,
				},
			},
		}
	}

	{
		c := newCtl([]string{"100.64.0.53"})
		c.isClosed = true
		assert.NotNil(t, c.UpdateDNS(&userv1.DNS{
			Servers: []string{"100.64.0.54"},
		}))
	}

	{
		c := newCtl([]string{"100.64.0.53"})

		assert.Nil(t, c.UpdateDNS(nil))
		assert.Equal(t, []string{"100.64.0.53"}, c.c.Connection.Dns.Servers)

		assert.Nil(t, c.UpdateDNS(&userv1.DNS{}))
		assert.Equal(t, []string{"100.64.0.53"}, c.c.Connection.Dns.Servers)

		assert.Nil(t, c.UpdateDNS(&userv1.DNS{
			Servers: []string{},
		}))
		assert.Equal(t, []string{"100.64.0.53"}, c.c.Connection.Dns.Servers)
	}

	{
		c := newCtl([]string{"100.64.0.53"})

		assert.Nil(t, c.UpdateDNS(&userv1.DNS{
			Servers: []string{"100.64.0.54", "fdee:e61::53"},
		}))
		assert.Equal(t, []string{"100.64.0.54", "fdee:e61::53"}, c.c.Connection.Dns.Servers)
		assert.Equal(t, []string{"100.64.0.54", "fdee:e61::53"}, c.GetClusterDNSServers())
		assert.True(t, c.getCurrentDNS().Equal(net.ParseIP("100.64.0.54")))
	}
}

var testControllerIPModes = []struct {
	name string
	mode userv1.ConnectionState_L3Mode
	v4   bool
	v6   bool
}{
	{"ipv4", userv1.ConnectionState_V4, true, false},
	{"ipv6", userv1.ConnectionState_V6, false, true},
	{"dual-stack", userv1.ConnectionState_BOTH, true, true},
}

func newTestPlatformController(t *testing.T, mode userv1.ConnectionState_L3Mode) *Controller {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if !assert.Nil(t, err) {
		t.FailNow()
	}

	return &Controller{
		isNetstack:    true,
		isQUIC:        true,
		ipv4Supported: mode != userv1.ConnectionState_V6,
		ipv6Supported: mode != userv1.ConnectionState_V4,
		wgPrivateKey:  key,
		resolvConf:    resolvConfState{path: filepath.Join(t.TempDir(), "resolv.conf")},
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				L3Mode:    mode,
				X25519Key: key[:],
				Cidr: &metav1.DualStackNetwork{
					V4: "100.64.0.0/16",
					V6: "fd00::/64",
				},
				Addresses: []*metav1.DualStackNetwork{
					{V4: "100.64.0.2/32", V6: "fd00::2/128"},
				},
				Dns: &userv1.DNS{Servers: []string{"100.64.0.53", "fd00::53"}},
			},
			Info: &cliconfigv1.Connection_Info{
				Cluster: &cliconfigv1.Connection_Info_Cluster{Domain: "example.com"},
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				DeviceName:     "octelium-test",
				IgnoreDNS:      true,
				UserHome:       t.TempDir(),
				ConnectionType: cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0,
				LinuxPrefs:     &cliconfigv1.Connection_Preferences_Linux{},
				MacosPrefs:     &cliconfigv1.Connection_Preferences_MacOS{},
				WindowsPrefs:   &cliconfigv1.Connection_Preferences_Windows{},
			},
		},
	}
}

func TestNewControllerNegotiatedIPModes(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			for _, connectionType := range []cliconfigv1.Connection_Preferences_ConnectionType{
				cliconfigv1.Connection_Preferences_CONNECTION_TYPE_WG,
				cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0,
			} {
				t.Run(connectionType.String(), func(t *testing.T) {
					cfg := newTestPlatformController(t, tt.mode).c
					cfg.Preferences.ConnectionType = connectionType
					cfg.Preferences.L3Mode = cliconfigv1.Connection_Preferences_V6
					c, err := NewController(cfg)
					if !assert.Nil(t, err) {
						return
					}
					c.isNetstack = true
					t.Cleanup(func() { assert.Nil(t, c.Close()) })

					assert.Same(t, cfg, c.c)
					assert.Equal(t, tt.v4, c.ipv4Supported)
					assert.Equal(t, tt.v6, c.ipv6Supported)
					assert.Equal(t, connectionType == cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0, c.isQUIC)
					assert.Equal(t, cfg.Connection.X25519Key, c.wgPrivateKey[:])
					assert.False(t, c.isClosed)
					assert.Nil(t, c.dev)
					assert.Nil(t, c.nsTun)
				})
			}
		})
	}
}

func TestNewControllerRejectsInvalidPrivateKeyLength(t *testing.T) {
	for _, size := range []int{0, 1, 31, 33, 64} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			cfg := newTestPlatformController(t, userv1.ConnectionState_BOTH).c
			cfg.Connection.X25519Key = make([]byte, size)
			c, err := NewController(cfg)
			assert.NotNil(t, err)
			assert.Nil(t, c)
		})
	}
}

func TestControllerMTUPrecedence(t *testing.T) {
	for _, tt := range []struct {
		name       string
		preference int32
		connection int32
		want       int
	}{
		{"default", 0, 0, 1280},
		{"connection", 0, 1380, 1380},
		{"preference", 1420, 0, 1420},
		{"override", 1420, 1380, 1420},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
			c.c.Preferences.Mtu = tt.preference
			c.c.Connection.Mtu = tt.connection
			assert.Equal(t, tt.want, c.getMTU())
		})
	}
}

type testControllerCloseTUN struct {
	tun.Device
	err   error
	calls int
}

func (d *testControllerCloseTUN) Close() error {
	d.calls++
	return d.err
}

type testControllerCloseListener struct {
	net.Listener
	err   error
	calls int
}

func (l *testControllerCloseListener) Close() error {
	l.calls++
	return l.err
}

func TestControllerCloseAggregatesErrorsAndContinuesCleanup(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	assert.Nil(t, c.createNetstackTUN())
	listenerErr := errors.New("listener close failed")
	tunErr := errors.New("TUN close failed")
	lis := &testControllerCloseListener{err: listenerErr}
	dev := &testControllerCloseTUN{err: tunErr}
	c.uapi = lis
	c.tundev = dev
	ctx, cancel := context.WithCancel(context.Background())
	c.svcProxy = &serviceProxy{cancelFn: cancel}
	t.Cleanup(cancel)

	err := c.Close()
	assert.ErrorIs(t, err, listenerErr)
	assert.ErrorIs(t, err, tunErr)
	assert.True(t, c.isClosed)
	assert.True(t, c.svcProxy.isClosed)
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
	assert.Nil(t, c.tundev)
	select {
	case <-c.nsTun.closed:
	default:
		t.Fatal("netstack TUN remained open after another resource failed to close")
	}

	assert.Same(t, err, c.Close())
	assert.Equal(t, 1, lis.calls)
	assert.Equal(t, 1, dev.calls)
	assert.NotNil(t, c.Start(context.Background()))
}

func TestControllerCloseCleanupJournal(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
			dbC, err := db.Open("memory")
			if !assert.Nil(t, err) {
				return
			}
			t.Cleanup(func() { assert.Nil(t, dbC.Close()) })
			c.dbC = dbC
			c.prepareCleanup()
			if !assert.NotNil(t, c.cleanup) {
				return
			}
			assert.Equal(t, cliconfigv1.ConnectionCleanup_PREPARED, c.cleanup.Phase)
			if fail {
				c.tundev = &testControllerCloseTUN{err: errors.New("close failed")}
			}

			err = c.Close()
			cleanup, getErr := dbC.GetConnectionCleanup("example.com")
			if fail {
				assert.NotNil(t, err)
				if assert.Nil(t, getErr) {
					assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, cleanup.Phase)
				}
				assert.NotNil(t, c.cleanup)
			} else {
				assert.Nil(t, err)
				assert.True(t, dbC.ErrorIsNotFound(getErr))
				assert.Nil(t, c.cleanup)
			}
			assert.Equal(t, err, c.Close())
		})
	}
}

func TestControllerSetConnectionStateAppliesAddressesAndDNS(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			if !assert.Nil(t, c.createNetstackTUN()) {
				return
			}
			t.Cleanup(func() { assert.Nil(t, c.Close()) })
			state := proto.Clone(c.c.Connection).(*userv1.ConnectionState)
			state.Addresses = []*metav1.DualStackNetwork{{V4: "100.64.0.3/32", V6: "fd00::3/128"}}
			state.Dns = &userv1.DNS{Servers: []string{"100.64.0.54", "fd00::54"}}

			assert.Nil(t, c.SetConnectionState(state))
			assert.Same(t, state, c.c.Connection)
			var addresses, servers []string
			if tt.v4 {
				addresses = append(addresses, "100.64.0.3/32")
				servers = append(servers, "100.64.0.54")
			}
			if tt.v6 {
				addresses = append(addresses, "fd00::3/128")
				servers = append(servers, "fd00::54")
			}
			assert.ElementsMatch(t, addresses, testControllerNetstackAddresses(c))
			assert.Equal(t, servers, c.GetClusterDNSServers())
			assert.Nil(t, c.Reconfigure())
			assert.ElementsMatch(t, addresses, testControllerNetstackAddresses(c))
		})
	}
}

func TestControllerSetConnectionStateRollsBackInvalidAddresses(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			if !assert.Nil(t, c.createNetstackTUN()) {
				return
			}
			t.Cleanup(func() { assert.Nil(t, c.Close()) })
			assert.Nil(t, c.SetDNS())
			old := c.c.Connection
			addresses := testControllerNetstackAddresses(c)
			servers := c.GetClusterDNSServers()
			state := proto.Clone(old).(*userv1.ConnectionState)
			state.Addresses = []*metav1.DualStackNetwork{{V4: "invalid", V6: "invalid"}}
			state.Dns = &userv1.DNS{Servers: []string{"100.64.0.99", "fd00::99"}}

			assert.NotNil(t, c.SetConnectionState(state))
			assert.Same(t, old, c.c.Connection)
			assert.ElementsMatch(t, addresses, testControllerNetstackAddresses(c))
			assert.Equal(t, servers, c.GetClusterDNSServers())
			assert.Nil(t, c.Reconfigure())
		})
	}
}

func TestControllerUpdatePrivateKeyNetstack(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.isQUIC = false
	c.c.Preferences.ConnectionType = cliconfigv1.Connection_Preferences_CONNECTION_TYPE_WG
	if !assert.Nil(t, c.doInitDevNetstack(context.Background())) {
		return
	}
	t.Cleanup(func() { assert.Nil(t, c.Close()) })
	old := c.wgPrivateKey
	assert.NotNil(t, c.UpdatePrivateKey("invalid"))
	assert.Equal(t, old, c.wgPrivateKey)
	key, err := wgtypes.GeneratePrivateKey()
	assert.Nil(t, err)
	assert.Nil(t, c.UpdatePrivateKey(key.String()))
	assert.Equal(t, key, c.wgPrivateKey)
	uapi, err := c.dev.IpcGet()
	assert.Nil(t, err)
	assert.Equal(t, &key, fromUAPI(uapi).PrivateKey)
}

func TestControllerUpdatePrivateKeyQUICIsIgnored(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	old := c.wgPrivateKey
	assert.Nil(t, c.UpdatePrivateKey("invalid"))
	assert.Equal(t, old, c.wgPrivateKey)
}

func TestControllerSOCKSListenAddressesByIPMode(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			c.c.Preferences.L3Mode = cliconfigv1.Connection_Preferences_L3Mode(tt.mode)
			c.c.Preferences.ESOCKS5 = &cliconfigv1.Connection_Preferences_ESOCKS5{}
			var want []string
			if tt.v4 {
				want = append(want, "100.64.0.2:1080")
			}
			if tt.v6 {
				want = append(want, "[fd00::2]:1080")
			}
			assert.Equal(t, want, getESOCKS5ListenAddrs(c.c))
			c.c.Preferences.ESOCKS5.Port = 2080
			c.c.Preferences.ESOCKS5.ListenIPAddresses = []string{" 127.0.0.1 ", "", " ", "::1"}
			assert.Equal(t, []string{"127.0.0.1:2080", "[::1]:2080"}, getESOCKS5ListenAddrs(c.c))
		})
	}
}

func TestControllerSOCKSListenAddressesWithoutConfig(t *testing.T) {
	for _, cfg := range []*cliconfigv1.Connection{
		nil,
		{},
		{Connection: &userv1.ConnectionState{}},
		{Connection: &userv1.ConnectionState{}, Preferences: &cliconfigv1.Connection_Preferences{}},
		{Connection: &userv1.ConnectionState{}, Preferences: &cliconfigv1.Connection_Preferences{
			ESOCKS5: &cliconfigv1.Connection_Preferences_ESOCKS5{},
		}},
	} {
		assert.Empty(t, getESOCKS5ListenAddrs(cfg))
	}
}

func TestControllerConnectionConfigSnapshotIsDetached(t *testing.T) {
	cfg := &cliconfigv1.Connection{
		Info: &cliconfigv1.Connection_Info{Cluster: &cliconfigv1.Connection_Info_Cluster{Domain: "example.com"}},
		Connection: &userv1.ConnectionState{
			X25519Key: []byte{1, 2, 3},
			Addresses: []*metav1.DualStackNetwork{{V4: "100.64.0.2/32", V6: "fd00::2/128"}},
			Gateways:  []*userv1.Gateway{{Id: "initial", Addresses: []string{"192.0.2.1"}, CIDRs: []string{"100.64.0.0/16"}}},
			Dns:       &userv1.DNS{Servers: []string{"100.64.0.53"}},
			ServiceOptions: &userv1.ConnectionState_ServiceOptions{Services: []*userv1.HostedService{{
				Name: "served.default", Address: &metav1.DualStackIP{Ipv4: "100.64.0.2"},
				Upstream: &userv1.HostedService_Upstream{Host: "127.0.0.1", Port: 8080},
			}}},
		},
		Preferences: &cliconfigv1.Connection_Preferences{
			DeviceName: "initialized-device", Mtu: 1400, IgnoreDNS: true,
			LocalDNS: &cliconfigv1.Connection_Preferences_LocalDNS{IsEnabled: true},
			PublishedServices: []*cliconfigv1.Connection_Preferences_PublishedService{{
				Name: "published.default", Fqdn: "published.default.local.example.com", Port: 80, HostPort: 8080,
			}},
		},
	}
	c := &Controller{c: cfg}
	before := proto.Clone(cfg).(*cliconfigv1.Connection)
	snapshot := c.GetConnectionConfig()
	require.True(t, proto.Equal(before, snapshot))
	require.NotSame(t, cfg, snapshot)
	snapshot.Info.Cluster.Domain = "consumer.example"
	snapshot.Connection.X25519Key[0] = 9
	snapshot.Connection.Addresses[0].V4 = "100.64.0.9/32"
	snapshot.Connection.Gateways[0].Addresses[0] = "192.0.2.9"
	snapshot.Connection.Gateways[0].CIDRs[0] = "192.0.2.0/24"
	snapshot.Connection.Dns.Servers[0] = "100.64.0.59"
	snapshot.Connection.ServiceOptions.Services[0].Address.Ipv4 = "100.64.0.9"
	snapshot.Connection.ServiceOptions.Services[0].Upstream.Host = "consumer.example"
	snapshot.Preferences.DeviceName = "consumer-device"
	snapshot.Preferences.LocalDNS.IsEnabled = false
	snapshot.Preferences.PublishedServices[0].HostPort = 9090
	require.True(t, proto.Equal(before, cfg), "the event consumer must not mutate controller configuration")
	retained := proto.Clone(snapshot).(*cliconfigv1.Connection)
	cfg.Connection.X25519Key[1] = 8
	cfg.Connection.Addresses[0].V6 = "fd00::8/128"
	cfg.Connection.Gateways[0].Addresses[0] = "192.0.2.8"
	cfg.Connection.ServiceOptions.Services[0].Name = "changed.default"
	cfg.Preferences.PublishedServices[0].Name = "changed.default"
	assert.True(t, proto.Equal(retained, snapshot), "later controller mutations must not alter a retained event")
	assert.True(t, proto.Equal(cfg, c.GetConnectionConfig()), "a later snapshot must reflect the current configuration")
}

func TestControllerConnectionConfigSnapshotPreservesPlatformPreferences(t *testing.T) {
	for _, platform := range []string{"linux", "macos", "windows"} {
		t.Run(platform, func(t *testing.T) {
			cfg := &cliconfigv1.Connection{Preferences: &cliconfigv1.Connection_Preferences{DeviceName: "effective-device"}}
			var live proto.Message
			switch platform {
			case "linux":
				cfg.Preferences.LinuxPrefs = &cliconfigv1.Connection_Preferences_Linux{
					ResolvConf: []byte("original"), TableIndex: 2001, MainTableIndex: 2002,
					ImplementationMode: cliconfigv1.Connection_Preferences_Linux_WG_NETSTACK,
				}
				live = cfg.Preferences.LinuxPrefs
			case "macos":
				cfg.Preferences.MacosPrefs = &cliconfigv1.Connection_Preferences_MacOS{
					ResolvConf: []byte("original"), DnsMode: cliconfigv1.Connection_Preferences_MacOS_NETWORKSETUP,
				}
				live = cfg.Preferences.MacosPrefs
			case "windows":
				cfg.Preferences.WindowsPrefs = &cliconfigv1.Connection_Preferences_Windows{}
				live = cfg.Preferences.WindowsPrefs
			}
			live.ProtoReflect().SetUnknown([]byte{0x08, 0x01})
			before := proto.Clone(cfg)
			c := &Controller{c: cfg}
			snapshot := c.GetConnectionConfig()
			require.True(t, proto.Equal(cfg, snapshot))
			var copied proto.Message
			switch platform {
			case "linux":
				copied = snapshot.Preferences.LinuxPrefs
				snapshot.Preferences.LinuxPrefs.ResolvConf[0] = 'x'
				snapshot.Preferences.LinuxPrefs.TableIndex++
			case "macos":
				copied = snapshot.Preferences.MacosPrefs
				snapshot.Preferences.MacosPrefs.ResolvConf[0] = 'x'
				snapshot.Preferences.MacosPrefs.DnsMode = cliconfigv1.Connection_Preferences_MacOS_RESOLVCONF
			case "windows":
				copied = snapshot.Preferences.WindowsPrefs
			}
			require.NotSame(t, live, copied)
			copied.ProtoReflect().GetUnknown()[1] = 2
			assert.True(t, proto.Equal(before, cfg), "platform settings and unknown protobuf fields must be owned by the snapshot")
		})
	}
}

func TestControllerConnectionConfigSnapshotPreservesOptionalMessages(t *testing.T) {
	for _, cfg := range []*cliconfigv1.Connection{nil, {}, {
		Connection: &userv1.ConnectionState{},
	}, {
		Preferences: &cliconfigv1.Connection_Preferences{},
	}} {
		c := &Controller{c: cfg}
		var snapshot *cliconfigv1.Connection
		require.NotPanics(t, func() { snapshot = c.GetConnectionConfig() })
		assert.True(t, proto.Equal(cfg, snapshot))
		if cfg == nil {
			assert.Nil(t, snapshot)
		} else {
			assert.NotSame(t, cfg, snapshot)
		}
	}
}

func TestControllerConnectionConfigSnapshotsDuringDNSUpdates(t *testing.T) {
	c := &Controller{c: &cliconfigv1.Connection{
		Info:       &cliconfigv1.Connection_Info{Cluster: &cliconfigv1.Connection_Info_Cluster{Domain: "example.com"}},
		Connection: &userv1.ConnectionState{Dns: &userv1.DNS{Servers: []string{"192.0.2.1", "192.0.2.1"}}},
		Preferences: &cliconfigv1.Connection_Preferences{
			IgnoreDNS: true, LocalDNS: &cliconfigv1.Connection_Preferences_LocalDNS{},
		},
	}}
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 256 {
			server := fmt.Sprintf("192.0.2.%d", i%250+1)
			assert.NoError(t, c.UpdateDNS(&userv1.DNS{Servers: []string{server, server}}))
			runtime.Gosched()
		}
	})
	t.Cleanup(wg.Wait)
	for range 256 {
		snapshot := c.GetConnectionConfig()
		servers := snapshot.GetConnection().GetDns().GetServers()
		require.Len(t, servers, 2)
		assert.Equal(t, servers[0], servers[1], "a snapshot must contain one coherent DNS update")
		servers[0] = "consumer.example"
		runtime.Gosched()
	}
	wg.Wait()
	servers := c.GetConnectionConfig().GetConnection().GetDns().GetServers()
	assert.Equal(t, servers[0], servers[1])
}
