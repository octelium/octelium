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
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
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
