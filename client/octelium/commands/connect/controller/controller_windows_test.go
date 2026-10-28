package controller

import (
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func TestWindowsWireGuardConfigByIPMode(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			key := c.wgPrivateKey.PublicKey().String()
			c.c.Connection.Gateways = []*userv1.Gateway{
				nil,
				{Id: "quic", Quicv0: &userv1.Gateway_QUICV0{Port: 443}},
				{Id: "no-endpoint", Wireguard: &userv1.Gateway_WireGuard{PublicKey: key}},
				{
					Id:        "wireguard",
					Addresses: []string{"2001:db8::1", "192.0.2.1"},
					CIDRs:     []string{"100.64.0.0/16", "fd00::/64"},
					Wireguard: &userv1.Gateway_WireGuard{PublicKey: key, Port: 51820},
				},
			}
			cfg, err := c.getWgConf()
			if !assert.Nil(t, err) {
				return
			}
			assert.Equal(t, "octelium-test", cfg.Name)
			assert.Equal(t, c.wgPrivateKey.String(), cfg.Interface.PrivateKey.String())
			var addrs, allowed []netip.Prefix
			var dns []netip.Addr
			if tt.v4 {
				addrs = append(addrs, netip.MustParsePrefix("100.64.0.2/32"))
				allowed = append(allowed, netip.MustParsePrefix("100.64.0.0/16"))
				dns = append(dns, netip.MustParseAddr("100.64.0.53"))
			}
			if tt.v6 {
				addrs = append(addrs, netip.MustParsePrefix("fd00::2/128"))
				allowed = append(allowed, netip.MustParsePrefix("fd00::/64"))
				dns = append(dns, netip.MustParseAddr("fd00::53"))
			}
			assert.Equal(t, addrs, cfg.Interface.Addresses)
			assert.Equal(t, dns, cfg.Interface.DNS)
			if assert.Len(t, cfg.Peers, 1) {
				assert.Equal(t, key, cfg.Peers[0].PublicKey.String())
				assert.Equal(t, allowed, cfg.Peers[0].AllowedIPs)
				assert.Equal(t, "2001:db8::1", cfg.Peers[0].Endpoint.Host)
				assert.Equal(t, uint16(51820), cfg.Peers[0].Endpoint.Port)
			}
		})
	}
}

func TestWindowsWireGuardConfigRejectsMalformedAddressesAndPeers(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*Controller)
	}{
		{"ipv4-address", func(c *Controller) { c.c.Connection.Addresses[0].V4 = "invalid" }},
		{"ipv6-address", func(c *Controller) { c.c.Connection.Addresses[0].V6 = "invalid" }},
		{"peer-key", func(c *Controller) { c.c.Connection.Gateways[0].Wireguard.PublicKey = "invalid" }},
		{"peer-cidr", func(c *Controller) { c.c.Connection.Gateways[0].CIDRs = []string{"invalid"} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
			c.c.Connection.Gateways = []*userv1.Gateway{{
				Addresses: []string{"192.0.2.1"},
				Wireguard: &userv1.Gateway_WireGuard{PublicKey: c.wgPrivateKey.PublicKey().String()},
			}}
			tt.change(c)
			cfg, err := c.getWgConf()
			assert.NotNil(t, err)
			assert.Nil(t, cfg)
		})
	}
}

func TestWindowsWireGuardConfigIgnoresDisabledAddressFamily(t *testing.T) {
	for _, tt := range testControllerIPModes[:2] {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			if tt.v4 {
				c.c.Connection.Addresses[0].V6 = "invalid"
			} else {
				c.c.Connection.Addresses[0].V4 = "invalid"
			}
			cfg, err := c.getWgConf()
			if assert.Nil(t, err) {
				assert.Len(t, cfg.Interface.Addresses, 1)
			}
		})
	}
}

func TestWindowsWireGuardConfigUsesLocalDNS(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_V6)
	c.c.Preferences.LocalDNS = &cliconfigv1.Connection_Preferences_LocalDNS{
		IsEnabled: true, ListenAddress: "[::1]:1053",
	}
	cfg, err := c.getWgConf()
	if assert.Nil(t, err) {
		assert.Equal(t, []netip.Addr{netip.MustParseAddr("::1")}, cfg.Interface.DNS)
	}
}

func TestWindowsAdapterGUIDsAreStableAndDistinct(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	guid, err := c.getGUID()
	if !assert.Nil(t, err) {
		return
	}
	assert.Equal(t, "{D9AB57BC-83B4-803B-1BB3-975190A48FB7}", guid.String())
	tunGUID, err := c.getTunGUID()
	if !assert.Nil(t, err) {
		return
	}
	assert.Equal(t, "{DC85BAA3-D4D6-BC0F-DB64-37C2A6FCB073}", tunGUID.String())
	again, err := c.getGUID()
	assert.Nil(t, err)
	assert.Equal(t, guid, again)
	c.c.Info.Cluster.Domain = "other.example.com"
	other, err := c.getGUID()
	assert.Nil(t, err)
	assert.NotEqual(t, guid, other)
	assert.Equal(t, "octelium-quicv0-other-example-com", c.getDevName("octelium-quicv0"))
}

func TestWindowsGUIDAndNRPTRequireClusterInfo(t *testing.T) {
	for _, info := range []*cliconfigv1.Connection_Info{nil, {}} {
		c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
		c.c.Info = info
		_, err := c.getGUID()
		assert.NotNil(t, err)
		_, err = c.getTunGUID()
		assert.NotNil(t, err)
		_, err = c.getNRPTRulePath()
		assert.NotNil(t, err)
		assert.NotNil(t, c.setNRPT())
		assert.NotNil(t, c.unsetNRPT())
	}
}

func TestWindowsNRPTRulePathAndValidation(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	key, err := getNRPTRuleKey("example.com")
	assert.Nil(t, err)
	path, err := c.getNRPTRulePath()
	assert.Nil(t, err)
	assert.Equal(t, nrptLocalBase+`\`+key, path)
	c.c.Connection.Dns.Servers = []string{"invalid", "dns.example.com"}
	assert.EqualError(t, c.setNRPT(), "Could not find any valid DNS server for the NRPT rule")
	c.c.Info.Cluster.Domain = "invalid domain"
	_, err = c.getNRPTRulePath()
	assert.NotNil(t, err)
}

func TestWindowsNativeOperationsWithoutAdapter(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			c.isNetstack = false
			assert.Zero(t, c.getLUID())
			assert.Nil(t, c.setRoutes())
			assert.Nil(t, c.unsetRoutes())
			assert.Nil(t, c.setIPIF())
			assert.Nil(t, c.setDevUp())
			assert.Nil(t, c.DeleteDev())
			assert.EqualError(t, c.SetDevAddrs(), "The network device is not initialized")
			assert.EqualError(t, c.doSetDNS(), "The network device is not initialized")
			c.isQUIC = false
			assert.EqualError(t, c.setWGDev(), "The WireGuard adapter is not initialized")
			c.isNetstack = true
			assert.EqualError(t, c.setWGDev(), "The WireGuard device is not initialized")
			assert.Nil(t, c.doSetDNS())
			assert.Nil(t, c.doUnsetDNS())
		})
	}
}

type testWindowsChangeCallback struct {
	calls int
}

func (c *testWindowsChangeCallback) Unregister() error {
	c.calls++
	return nil
}

func TestWindowsUnwindPartialDeviceClosesResources(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	dev := &testControllerCloseTUN{}
	cb := &testWindowsChangeCallback{}
	iw := &interfaceWatcher{
		luid:                    winipcfg.LUID(123),
		interfaceChangeCallback: cb,
		storedEvents:            []interfaceWatcherEvent{{luid: 123, family: windows.AF_INET}},
	}
	c.tundev = dev
	c.opts.ifaceWatcher = iw
	c.quicEngine = newTestQUICEngine(nil)
	engine := c.quicEngine
	c.unwindPartialDev()
	assert.Nil(t, c.tundev)
	assert.Nil(t, c.quicEngine)
	assert.Nil(t, c.opts.adapter)
	assert.Nil(t, c.opts.ifaceWatcher)
	assert.Zero(t, iw.luid)
	assert.Empty(t, iw.storedEvents)
	assert.Equal(t, 1, cb.calls)
	assert.Equal(t, 1, dev.calls)
	assert.True(t, engine.isClosed)
	c.unwindPartialDev()
	assert.Equal(t, 1, cb.calls)
	assert.Equal(t, 1, dev.calls)
}

func TestWindowsNotFoundErrors(t *testing.T) {
	for _, err := range []error{windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND, windows.ERROR_NOT_FOUND} {
		assert.True(t, isWindowsNotFound(err))
		assert.True(t, isWindowsNotFound(errors.Join(errors.New("wrapped"), err)))
	}
	assert.False(t, isWindowsNotFound(nil))
	assert.False(t, isWindowsNotFound(windows.ERROR_ACCESS_DENIED))
}

func TestWindowsWireGuardConfigKeyRotationDoesNotMutatePreviousConfig(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.c.Preferences.IgnoreDNS = true
	first, err := c.getWgConf()
	if !assert.NoError(t, err) {
		return
	}
	old := first.Interface.PrivateKey
	key, err := wgtypes.GeneratePrivateKey()
	if !assert.NoError(t, err) {
		return
	}
	c.wgPrivateKey = key
	second, err := c.getWgConf()
	if assert.NoError(t, err) {
		assert.NotEqual(t, old, second.Interface.PrivateKey)
		assert.Equal(t, key.String(), second.Interface.PrivateKey.String())
		assert.Equal(t, old, first.Interface.PrivateKey)
	}
}

func TestWindowsDeviceCloseContinuesAfterListenerFailure(t *testing.T) {
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

func TestWindowsKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to reproduce CL-011 in tmp/client-test-report.md")
	}
	t.Run("CL-011-native-WireGuard-keepalive", func(t *testing.T) {
		c := newTestPlatformController(t, userv1.ConnectionState_V4)
		c.c.Preferences.KeepAliveSeconds = 25
		c.c.Connection.Gateways = []*userv1.Gateway{{
			Id: "gw", Addresses: []string{"192.0.2.1"}, CIDRs: []string{"100.64.0.0/16"},
			Wireguard: &userv1.Gateway_WireGuard{PublicKey: c.wgPrivateKey.PublicKey().String(), Port: 51820},
		}}
		cfg, err := c.getWgConf()
		if assert.NoError(t, err) && assert.Len(t, cfg.Peers, 1) {
			assert.Equal(t, uint16(25), cfg.Peers[0].PersistentKeepalive)
		}
	})
}
