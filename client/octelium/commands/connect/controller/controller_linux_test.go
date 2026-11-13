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
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"google.golang.org/protobuf/proto"
)

func TestLinuxControllerStartCloseNetstackIPModes(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newTestPlatformController(t, tt.mode)
			cfg := fixture.c
			cfg.Preferences.ConnectionType = cliconfigv1.Connection_Preferences_CONNECTION_TYPE_WG
			cfg.Preferences.LinuxPrefs.EnforceImplementationMode = true
			cfg.Preferences.LinuxPrefs.ImplementationMode = cliconfigv1.Connection_Preferences_Linux_WG_NETSTACK
			dbC, err := db.Open("memory")
			if !assert.Nil(t, err) {
				return
			}
			t.Cleanup(func() { assert.Nil(t, dbC.Close()) })
			c, err := NewControllerWithDB(cfg, dbC)
			if !assert.Nil(t, err) {
				return
			}
			c.resolvConf.path = fixture.resolvConf.path
			t.Cleanup(func() { assert.Nil(t, c.Close()) })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !assert.Nil(t, c.Start(ctx)) {
				return
			}
			assert.True(t, c.isNetstack)
			assert.NotNil(t, c.dev)
			assert.NotNil(t, c.svcProxy)
			assert.Equal(t, cliconfigv1.ConnectionCleanup_ACTIVE, c.cleanup.Phase)
			cleanup, err := dbC.GetConnectionCleanup("example.com")
			if assert.Nil(t, err) {
				assert.Equal(t, cliconfigv1.ConnectionCleanup_ACTIVE, cleanup.Phase)
			}
			assert.Len(t, testControllerNetstackAddresses(c), len(c.getClusterDNSServers()))
			assert.Equal(t, c.getClusterDNSServers(), c.GetClusterDNSServers())
			assert.Nil(t, c.Reconfigure())
			assert.Nil(t, c.Close())
			assert.True(t, c.svcProxy.isClosed)
			assert.Empty(t, c.nsTun.stack.AllAddresses())
			_, err = dbC.GetConnectionCleanup("example.com")
			assert.True(t, dbC.ErrorIsNotFound(err))
			assert.Nil(t, c.Close())
			assert.NotNil(t, c.Start(ctx))
		})
	}
}

func TestLinuxControllerStartFailureCanBeClosed(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.c.Preferences.LinuxPrefs.EnforceImplementationMode = true
	c.c.Preferences.LinuxPrefs.ImplementationMode = cliconfigv1.Connection_Preferences_Linux_ImplementationMode(99)
	dbC, err := db.Open("memory")
	if !assert.Nil(t, err) {
		return
	}
	t.Cleanup(func() { assert.Nil(t, dbC.Close()) })
	c.dbC = dbC
	assert.EqualError(t, c.Start(context.Background()), "unknown Implementation is enforced")
	assert.Equal(t, cliconfigv1.ConnectionCleanup_PREPARED, c.cleanup.Phase)
	assert.Nil(t, c.dev)
	assert.Nil(t, c.nsTun)
	assert.Nil(t, c.svcProxy)
	assert.Nil(t, c.Close())
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
}

func TestLinuxNetlinkFamily(t *testing.T) {
	for _, tt := range []struct {
		v4   bool
		v6   bool
		want int
	}{
		{true, true, netlink.FAMILY_ALL},
		{true, false, netlink.FAMILY_V4},
		{false, true, netlink.FAMILY_V6},
		{false, false, netlink.FAMILY_V6},
	} {
		c := &Controller{ipv4Supported: tt.v4, ipv6Supported: tt.v6}
		assert.Equal(t, tt.want, c.getNetlinkFamily())
	}
}

func TestLinuxWireGuardLinkAttributes(t *testing.T) {
	l := newWgLink("octelium-test", 1420)
	assert.Equal(t, "octelium-test", l.Attrs().Name)
	assert.Equal(t, 1420, l.Attrs().MTU)
	assert.Equal(t, "wireguard", l.Type())
}

func TestLinuxNativeOperationsRejectMissingDevice(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.isNetstack = false
	c.c.Preferences.DeviceName = "oct-missing"
	if _, err := netlink.LinkByName(c.c.Preferences.DeviceName); err == nil {
		t.Skip("the test interface name already exists")
	}
	assert.NotNil(t, c.setRoutes())
	assert.NotNil(t, c.unsetRoutes())
	assert.NotNil(t, c.SetDevAddrs())
	assert.NotNil(t, c.DeleteDev())
	c.c.Connection.Cidr = nil
	assert.Nil(t, c.setRoutes())
	assert.Nil(t, c.unsetRoutes())
}

func TestLinuxNativeOperationsRejectInvalidConfigBeforeMutation(t *testing.T) {
	if _, err := netlink.LinkByName("lo"); err != nil {
		t.Skip("loopback interface is unavailable")
	}
	for _, tt := range testControllerIPModes[:2] {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			c.isNetstack = false
			c.c.Preferences.DeviceName = "lo"
			c.c.Connection.Cidr = &metav1.DualStackNetwork{V4: "invalid-v4", V6: "invalid-v6"}
			assert.NotNil(t, c.setRoutes())
			c.c.Connection.Addresses = nil
			assert.EqualError(t, c.SetDevAddrs(), "No addresses found for the connection")
			c.c.Connection.Addresses = []*metav1.DualStackNetwork{{V4: "invalid-v4", V6: "invalid-v6"}}
			assert.NotNil(t, c.SetDevAddrs())
		})
	}
}

func TestLinuxPreferencesSelectMainTableAndBoundedAuxiliaryTable(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			routes, err := netlink.RouteList(nil, c.getNetlinkFamily())
			if !assert.NoError(t, err) {
				return
			}
			want := int64(254)
			for _, route := range routes {
				if (route.Dst == nil || route.Dst.String() == "0.0.0.0/0" || route.Dst.String() == "::/0") && route.Src == nil {
					want = int64(route.Table)
					break
				}
			}
			assert.NoError(t, c.SetPrefs())
			assert.Equal(t, want, c.c.Preferences.LinuxPrefs.MainTableIndex)
			assert.GreaterOrEqual(t, c.c.Preferences.LinuxPrefs.TableIndex, int64(10000))
			assert.LessOrEqual(t, c.c.Preferences.LinuxPrefs.TableIndex, int64(30000))
		})
	}
}

func TestLinuxDeviceCloseContinuesAfterListenerFailure(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	lisErr, tunErr := errors.New("listener close failed"), errors.New("TUN close failed")
	lis := &testControllerCloseListener{err: lisErr}
	dev := &testControllerCloseTUN{err: tunErr}
	c.uapi, c.tundev = lis, dev
	err := c.doClose()
	assert.ErrorIs(t, err, lisErr)
	assert.ErrorIs(t, err, tunErr)
	assert.Equal(t, 1, lis.calls)
	assert.Equal(t, 1, dev.calls)
	assert.Nil(t, c.tundev)
}

const testGatewayNetnsEnv = "OCTELIUM_TEST_GATEWAY_NETNS_SCENARIO"

const (
	testGatewayNetnsBase = "ip link set lo up; ip link add eth0 type dummy; ip link set eth0 up; "
	testGatewayNetnsV4   = "ip addr add 203.0.113.5/24 dev eth0; ip route add default via 203.0.113.1; "
	testGatewayNetnsV6   = "ip -6 addr add 2001:db8:1::5/64 dev eth0 nodad; ip -6 route add default via 2001:db8:1::1 dev eth0; "
	testGatewayNetnsULA  = "ip -6 addr add fd00::5/64 dev eth0 nodad; "
	testGatewayIPv4      = "198.51.100.10"
	testGatewayIPv6      = "2001:db8:ffff::10"
)

type testGatewayNetnsScenario struct {
	name      string
	setup     string
	ipv4First bool
	want      string
}

var testGatewayNetnsScenarios = []testGatewayNetnsScenario{
	{"ipv4-only", testGatewayNetnsV4, false, testGatewayIPv4},
	{"ipv6-only", testGatewayNetnsV6, true, testGatewayIPv6},
	{"dual-stack-ipv6-first", testGatewayNetnsV4 + testGatewayNetnsV6, false, testGatewayIPv6},
	{"dual-stack-ipv4-first", testGatewayNetnsV4 + testGatewayNetnsV6, true, testGatewayIPv4},
	{"no-routes-falls-back-to-first", "", false, testGatewayIPv6},
	{"no-routes-ipv4-first-falls-back-to-first", "", true, testGatewayIPv4},
	{"ipv4-only-with-ula", testGatewayNetnsV4 + testGatewayNetnsULA, false, testGatewayIPv4},
	{"ipv4-only-with-ula-default-route", testGatewayNetnsV4 + testGatewayNetnsULA +
		"ip -6 route add default via fd00::1 dev eth0; ", false, testGatewayIPv4},
	{"ipv4-only-with-link-local-default-route", testGatewayNetnsV4 +
		"ip -6 route add default via fe80::1 dev eth0; ", false, testGatewayIPv4},
	{"ipv6-only-with-idle-bridge", testGatewayNetnsV6 +
		"ip link add docker0 type bridge; ip addr add 172.17.0.1/16 dev docker0; ip link set docker0 up; ",
		true, testGatewayIPv6},
	{"ipv4-only-with-other-tunnel", testGatewayNetnsV4 +
		"ip link add tun1 type dummy; ip link set tun1 up; ip -6 addr add fdee:1::2/64 dev tun1 nodad; ip -6 route add fdee::/16 dev tun1; ",
		false, testGatewayIPv4},
	{"ipv4-only-with-policy-table", "ip addr add 203.0.113.5/24 dev eth0; ip route add default via 203.0.113.1 table 100; ip rule add lookup 100; ",
		false, testGatewayIPv4},
	{"ipv6-only-with-policy-table", "ip -6 addr add 2001:db8:1::5/64 dev eth0 nodad; ip -6 route add default via 2001:db8:1::1 dev eth0 table 100; ip -6 rule add lookup 100; ",
		true, testGatewayIPv6},
	{"ipv4-only-ipv6-disabled", testGatewayNetnsV4 + "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1; ", false, testGatewayIPv4},
}

func TestLinuxGatewayEndpointNetnsHelper(t *testing.T) {
	name := os.Getenv(testGatewayNetnsEnv)
	if name == "" {
		t.Skip("Runs only inside TestLinuxGatewayEndpointNetns")
	}

	idx := slices.IndexFunc(testGatewayNetnsScenarios, func(s testGatewayNetnsScenario) bool {
		return s.name == name
	})
	if !assert.GreaterOrEqual(t, idx, 0) {
		t.FailNow()
	}
	tt := testGatewayNetnsScenarios[idx]

	if out, err := exec.Command("sh", "-ec", testGatewayNetnsBase+tt.setup).CombinedOutput(); err != nil {
		t.Skipf("Could not set up the network namespace: %v: %s", err, out)
	}

	addresses := []string{testGatewayIPv6, testGatewayIPv4}
	if tt.ipv4First {
		addresses = []string{testGatewayIPv4, testGatewayIPv6}
	}

	c := newTestGatewayCtl(nil)
	c.checkGatewayRoute = isGatewayAddrRoutable
	c.c.Connection.Gateways = []*userv1.Gateway{{
		Addresses: addresses,
		Wireguard: &userv1.Gateway_WireGuard{PublicKey: c.wgPrivateKey.PublicKey().String(), Port: 51820},
	}}

	uapi, err := c.toUAPI()
	assert.Nil(t, err)
	assert.Contains(t, uapi, "endpoint="+net.JoinHostPort(tt.want, "51820")+"\n")
}

func TestLinuxGatewayEndpointNetns(t *testing.T) {
	for _, tt := range testGatewayNetnsScenarios {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run=^TestLinuxGatewayEndpointNetnsHelper$")
			cmd.Env = append(os.Environ(), testGatewayNetnsEnv+"="+tt.name)
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
				UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
				GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
			}

			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if err != nil && !errors.As(err, &exitErr) {
				t.Skipf("Could not create the network namespace: %v", err)
			}
			if strings.Contains(string(out), "--- SKIP") {
				t.Skipf("Could not set up the network namespace: %s", out)
			}
			assert.Nil(t, err, string(out))
		})
	}
}

const testKernelGatewayEventsNetnsEnv = "OCTELIUM_TEST_KERNEL_GATEWAY_EVENTS_NETNS"

func TestLinuxKernelGatewayEventsNetnsHelper(t *testing.T) {
	if os.Getenv(testKernelGatewayEventsNetnsEnv) == "" {
		t.Skip("Runs only inside TestLinuxKernelGatewayEventsNetns")
	}

	c := newTestGatewayCtl(nil)
	c.c.Preferences.DeviceName = "oct-test"
	if err := netlink.LinkAdd(newWgLink(c.c.Preferences.DeviceName, 1420)); err != nil {
		t.Skipf("Could not create the WireGuard device: %v", err)
	}
	wgC, err := wgctrl.New()
	require.NoError(t, err)
	defer wgC.Close()
	c.wgC = wgC

	getPeerKeys := func() []string {
		dev, err := wgC.Device(c.c.Preferences.DeviceName)
		require.NoError(t, err)
		var ret []string
		for _, peer := range dev.Peers {
			ret = append(ret, peer.PublicKey.String())
		}
		return ret
	}

	gw := newTestReliabilityGateway(t, 1)
	other := newTestReliabilityGateway(t, 2)
	require.NoError(t, c.AddGateway(t.Context(), gw))
	require.NoError(t, c.AddGateway(t.Context(), other))
	require.NoError(t, c.AddGateway(t.Context(), proto.Clone(gw).(*userv1.Gateway)))
	assert.Equal(t, []*userv1.Gateway{gw, other}, c.c.Connection.Gateways)
	assert.ElementsMatch(t, []string{gw.Wireguard.PublicKey, other.Wireguard.PublicKey}, getPeerKeys())

	updated := newTestReliabilityGateway(t, 3)
	updated.Id = gw.Id
	require.NoError(t, c.AddGateway(t.Context(), updated))
	assert.Equal(t, []*userv1.Gateway{updated, other}, c.c.Connection.Gateways)
	assert.ElementsMatch(t, []string{updated.Wireguard.PublicKey, other.Wireguard.PublicKey}, getPeerKeys())

	dup := newTestReliabilityGateway(t, 4)
	dup.Id = gw.Id
	c.c.Connection.Gateways = append(c.c.Connection.Gateways, dup)
	require.NoError(t, c.SetGatewayWGPeer(dup))
	require.NoError(t, c.DeleteGateway(t.Context(), gw.Id))
	assert.Equal(t, []*userv1.Gateway{other}, c.c.Connection.Gateways)
	assert.Equal(t, []string{other.Wireguard.PublicKey}, getPeerKeys())
}

func TestLinuxKernelGatewayEventsNetns(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run=^TestLinuxKernelGatewayEventsNetnsHelper$")
	cmd.Env = append(os.Environ(), testKernelGatewayEventsNetnsEnv+"=true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}

	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Skipf("Could not create the network namespace: %v", err)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("Could not set up the WireGuard device: %s", out)
	}
	assert.Nil(t, err, string(out))
}
