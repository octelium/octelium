package controller

import (
	"net"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
)

func TestDarwinRoutesByIPMode(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			commands := newTestOSCommands(t, map[string]string{"route": "exit 0"})
			c := newTestPlatformController(t, tt.mode)
			c.isNetstack = false
			assert.Nil(t, c.setRoutes())
			assert.Nil(t, c.unsetRoutes())
			var want [][]string
			for _, op := range []string{"add", "delete"} {
				if tt.v4 {
					want = append(want, []string{"route", "-q", "-n", op, "-inet", "100.64.0.0/16", "-iface", "octelium-test"})
				}
				if tt.v6 {
					want = append(want, []string{"route", "-q", "-n", op, "-inet6", "fd00::/64", "-iface", "octelium-test"})
				}
			}
			assert.Equal(t, want, commands.calls(t))
		})
	}
}

func TestDarwinRoutesSkipMissingCIDRsAndNetstack(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{"route": "exit 1"})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	assert.Nil(t, c.setRoutes())
	assert.Nil(t, c.unsetRoutes())
	c.isNetstack = false
	c.c.Connection.Cidr = nil
	assert.Nil(t, c.setRoutes())
	assert.Nil(t, c.unsetRoutes())
	c.c.Connection.Cidr = &metav1.DualStackNetwork{}
	assert.Nil(t, c.setRoutes())
	assert.Nil(t, c.unsetRoutes())
	assert.Empty(t, commands.calls(t))
}

func TestDarwinRouteAddFailureStopsAndDeleteFailureContinues(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{"route": "printf 'route failure' >&2\nexit 1"})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.isNetstack = false
	err := c.setRoutes()
	if assert.NotNil(t, err) {
		assert.Contains(t, err.Error(), "100.64.0.0/16")
		assert.Contains(t, err.Error(), "route failure")
	}
	assert.Len(t, commands.calls(t), 1)
	err = c.unsetRoutes()
	if assert.NotNil(t, err) {
		assert.Equal(t, 2, strings.Count(err.Error(), "route failure"))
	}
	assert.Equal(t, [][]string{
		{"route", "-q", "-n", "add", "-inet", "100.64.0.0/16", "-iface", "octelium-test"},
		{"route", "-q", "-n", "delete", "-inet", "100.64.0.0/16", "-iface", "octelium-test"},
		{"route", "-q", "-n", "delete", "-inet6", "fd00::/64", "-iface", "octelium-test"},
	}, commands.calls(t))
}

func TestDarwinIPv6RouteFailureIncludesCIDR(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{
		"route": "if [ \"$4\" = -inet6 ]; then printf 'IPv6 route failure'; exit 1; fi",
	})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.isNetstack = false
	err := c.setRoutes()
	if assert.NotNil(t, err) {
		assert.Contains(t, err.Error(), "fd00::/64")
		assert.Contains(t, err.Error(), "IPv6 route failure")
	}
	assert.Len(t, commands.calls(t), 2)
}

func testDarwinLoopback(t *testing.T) (string, []string) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if !assert.Nil(t, err) {
			t.FailNow()
		}
		var ret []string
		for _, addr := range addrs {
			if _, _, err := net.ParseCIDR(addr.String()); err == nil {
				ret = append(ret, addr.String())
			}
		}
		if len(ret) > 0 {
			return iface.Name, ret
		}
	}
	t.Skip("no loopback interface with IP addresses")
	return "", nil
}

func TestDarwinAddressesRemoveStaleAndAddSupportedFamilies(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			commands := newTestOSCommands(t, map[string]string{"ifconfig": "exit 0"})
			c := newTestPlatformController(t, tt.mode)
			c.isNetstack = false
			name, old := testDarwinLoopback(t)
			c.c.Preferences.DeviceName = name
			assert.Nil(t, c.SetDevAddrs())
			var want [][]string
			for _, addr := range old {
				ip, _, _ := net.ParseCIDR(addr)
				family := "inet6"
				if ip.To4() != nil {
					family = "inet"
				}
				want = append(want, []string{"ifconfig", name, family, addr, "-alias"})
			}
			if tt.v4 {
				want = append(want, []string{"ifconfig", name, "inet", "100.64.0.2/32", "100.64.0.2", "alias"})
			}
			if tt.v6 {
				want = append(want, []string{"ifconfig", name, "inet6", "fd00::2/128", "fd00::2", "alias"})
			}
			assert.Equal(t, want, commands.calls(t))
		})
	}
}

func TestDarwinAddressesKeepConfiguredAliases(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{"ifconfig": "exit 0"})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.isNetstack = false
	name, old := testDarwinLoopback(t)
	c.c.Preferences.DeviceName = name
	c.c.Connection.Addresses = nil
	for _, addr := range old {
		ip, _, _ := net.ParseCIDR(addr)
		network := &metav1.DualStackNetwork{V6: addr}
		if ip.To4() != nil {
			network = &metav1.DualStackNetwork{V4: addr}
		}
		c.c.Connection.Addresses = append(c.c.Connection.Addresses, network)
	}
	assert.Nil(t, c.SetDevAddrs())
	assert.Len(t, commands.calls(t), len(old))
	for _, call := range commands.calls(t) {
		assert.Equal(t, "alias", call[len(call)-1])
	}
}

func TestDarwinAddressCommandFailureAndDeviceUp(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{"ifconfig": "printf 'ifconfig failure'; exit 1"})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.isNetstack = false
	name, _ := testDarwinLoopback(t)
	c.c.Preferences.DeviceName = name
	err := c.SetDevAddrs()
	if assert.NotNil(t, err) {
		assert.Contains(t, err.Error(), "Could not remove address")
		assert.Contains(t, err.Error(), "ifconfig failure")
	}
	assert.Len(t, commands.calls(t), 1)
	assert.NotNil(t, c.setDevUp())
	assert.Equal(t, []string{"ifconfig", name, "up"}, commands.calls(t)[1])
}

func TestDarwinDisconnectContinuesAfterRouteAndDNSFailures(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{
		"route": "printf 'route failure'; exit 1", "scutil": "printf 'DNS failure'; exit 1",
	})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.isNetstack = false
	c.c.Preferences.IgnoreDNS = false
	c.c.Preferences.MacosPrefs.DnsMode = cliconfigv1.Connection_Preferences_MacOS_SCUTIL
	lis := &testControllerCloseListener{}
	c.uapi = lis
	err := c.doDisconnect()
	if assert.NotNil(t, err) {
		assert.Contains(t, err.Error(), "route failure")
		assert.Contains(t, err.Error(), "DNS failure")
	}
	assert.Equal(t, 1, lis.calls)
	assert.Nil(t, c.uapi)
	assert.Len(t, commands.calls(t), 3)
}
