package controller

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func TestWindowsWireGuardDriverConfigurationABI(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.c.Preferences.KeepAliveSeconds = 60
	for i := range 2 {
		key, err := wgtypes.GeneratePrivateKey()
		require.Nil(t, err)
		cidrs := []string{"192.0.2.0/24", "2001:db8:1::/64"}
		if i == 1 {
			cidrs = []string{"198.51.100.0/24"}
		}
		c.c.Connection.Gateways = append(c.c.Connection.Gateways, &userv1.Gateway{
			Addresses: []string{"127.0.0.1"}, CIDRs: cidrs,
			Wireguard: &userv1.Gateway_WireGuard{PublicKey: key.PublicKey().String(), Port: 51820},
		})
	}
	cfg, err := c.getWgConf()
	require.Nil(t, err)
	configuration, size := cfg.ToDriverConfiguration()
	assert.Equal(t, uintptr(80), unsafe.Sizeof(driver.Interface{}))
	assert.Equal(t, uintptr(136), unsafe.Sizeof(driver.Peer{}))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(driver.AllowedIP{}))
	assert.Equal(t, uint32(424), size)
	require.Equal(t, uint32(2), configuration.PeerCount)
	peer := configuration.FirstPeer()
	assert.Equal(t, [32]byte(cfg.Peers[0].PublicKey), peer.PublicKey)
	assert.Equal(t, uint16(60), peer.PersistentKeepalive)
	require.Equal(t, uint32(2), peer.AllowedIPsCount)
	allowed := peer.FirstAllowedIP()
	assert.Equal(t, windows.AF_INET, int(allowed.AddressFamily))
	assert.Equal(t, uint8(24), allowed.Cidr)
	assert.Zero(t, allowed.Flags)
	allowed = allowed.NextAllowedIP()
	assert.Equal(t, windows.AF_INET6, int(allowed.AddressFamily))
	assert.Equal(t, uint8(64), allowed.Cidr)
	assert.Zero(t, allowed.Flags)
	peer = peer.NextPeer()
	assert.Equal(t, [32]byte(cfg.Peers[1].PublicKey), peer.PublicKey)
	assert.Equal(t, uint32(1), peer.AllowedIPsCount)
	assert.Equal(t, uint8(24), peer.FirstAllowedIP().Cidr)
}

func newTestWindowsNativeController(t *testing.T, mode userv1.ConnectionState_L3Mode) *Controller {
	t.Helper()
	if os.Getenv("OCTELIUM_TEST_WINDOWS_DRIVERS") != "1" {
		t.Skip("Native Windows driver tests require OCTELIUM_TEST_WINDOWS_DRIVERS=1")
	}
	require.True(t, windows.GetCurrentProcessToken().IsElevated())
	c := newTestPlatformController(t, mode)
	require.Nil(t, c.pre())
	c.isNetstack = false
	c.isQUIC = false
	c.c.Info.Cluster.Domain = fmt.Sprintf("native-%d.example.com", time.Now().UnixNano())
	c.c.Preferences.KeepAliveSeconds = 60
	c.c.Connection.Addresses = []*metav1.DualStackNetwork{{V4: "192.0.2.2/32", V6: "2001:db8:1::2/128"}}
	c.c.Connection.Dns.Servers = []string{"192.0.2.53", "2001:db8:1::53"}
	key, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	c.c.Connection.Gateways = []*userv1.Gateway{{
		Addresses: []string{"127.0.0.1"}, CIDRs: []string{"192.0.2.0/24", "2001:db8:1::/64"},
		Wireguard: &userv1.Gateway_WireGuard{PublicKey: key.PublicKey().String(), Port: 51820},
	}}
	t.Cleanup(func() {
		if c.getLUID() != 0 {
			assert.Nil(t, c.doUnsetDNS())
			assert.Nil(t, c.doUnsetRoutes())
		}
		c.unwindPartialDev()
	})
	return c
}

func testWindowsNativeNetworkConfiguration(t *testing.T, c *Controller) {
	t.Helper()
	require.NotZero(t, c.getLUID())
	require.Nil(t, c.SetDevAddrs())
	require.Nil(t, c.doSetRoutes())
	require.Nil(t, c.doSetDNSAdapter(c.getLUID()))
	var wantDNS []netip.Addr
	for _, family := range []struct {
		enabled bool
		family  winipcfg.AddressFamily
		address string
		route   string
		nextHop string
		dns     string
	}{
		{c.ipv4Supported, windows.AF_INET, "192.0.2.2", "192.0.2.0/24", "192.0.2.1", "192.0.2.53"},
		{c.ipv6Supported, windows.AF_INET6, "2001:db8:1::2", "2001:db8:1::/64", "2001:db8:1::1", "2001:db8:1::53"},
	} {
		if !family.enabled {
			continue
		}
		_, err := c.getLUID().IPAddress(netip.MustParseAddr(family.address))
		require.Nil(t, err)
		_, err = c.getLUID().Route(netip.MustParsePrefix(family.route), netip.MustParseAddr(family.nextHop))
		require.Nil(t, err)
		ipif, err := c.getLUID().IPInterface(family.family)
		require.Nil(t, err)
		assert.Equal(t, uint32(1280), ipif.NLMTU)
		wantDNS = append(wantDNS, netip.MustParseAddr(family.dns))
	}
	dns, err := c.getLUID().DNS()
	require.Nil(t, err)
	assert.ElementsMatch(t, wantDNS, dns)
	require.Nil(t, c.doUnsetDNS())
	require.Nil(t, c.doUnsetRoutes())
}

func TestWindowsNativeWireGuardLifecycle(t *testing.T) {
	for _, mode := range testControllerIPModes {
		t.Run(mode.name, func(t *testing.T) {
			c := newTestWindowsNativeController(t, mode.mode)
			guid, err := c.getGUID()
			require.Nil(t, err)
			for range 2 {
				c.opts.adapter, err = driver.CreateAdapter("OcteliumNativeTest", "WireGuard", guid)
				require.Nil(t, err)
				require.Nil(t, checkWireGuardDLLVersion())
				version, err := driver.RunningVersion()
				require.Nil(t, err)
				assert.Equal(t, uint32(1<<16|1), version)
				require.Nil(t, c.setWGDev())
				require.Nil(t, c.doSetDevUp())
				state, err := c.opts.adapter.AdapterState()
				require.Nil(t, err)
				assert.Equal(t, driver.AdapterStateUp, state)
				configuration, err := c.opts.adapter.Configuration()
				require.Nil(t, err)
				assert.Equal(t, [32]byte(c.wgPrivateKey), configuration.PrivateKey)
				require.Equal(t, uint32(1), configuration.PeerCount)
				assert.Equal(t, uint16(60), configuration.FirstPeer().PersistentKeepalive)
				cfg, err := c.getWgConf()
				require.Nil(t, err)
				peer := configuration.FirstPeer()
				require.Equal(t, uint32(len(cfg.Peers[0].AllowedIPs)), peer.AllowedIPsCount)
				allowed := peer.FirstAllowedIP()
				for i, prefix := range cfg.Peers[0].AllowedIPs {
					assert.Equal(t, prefix.Addr().AsSlice(), allowed.Address[:len(prefix.Addr().AsSlice())])
					assert.Equal(t, uint8(prefix.Bits()), allowed.Cidr)
					assert.Zero(t, allowed.Flags)
					if i+1 < len(cfg.Peers[0].AllowedIPs) {
						allowed = allowed.NextAllowedIP()
					}
				}
				testWindowsNativeNetworkConfiguration(t, c)
				key, err := wgtypes.GeneratePrivateKey()
				require.Nil(t, err)
				c.wgPrivateKey = key
				require.Nil(t, c.setWGDev())
				configuration, err = c.opts.adapter.Configuration()
				require.Nil(t, err)
				assert.Equal(t, [32]byte(key), configuration.PrivateKey)
				require.Nil(t, c.DeleteDev())
				assert.Nil(t, c.opts.adapter)
			}
		})
	}
}

func TestWindowsNativeWintunLifecycle(t *testing.T) {
	c := newTestWindowsNativeController(t, userv1.ConnectionState_BOTH)
	c.isQUIC = true
	for range 2 {
		require.Nil(t, c.doSetTunDev())
		name, err := c.tundev.Name()
		require.Nil(t, err)
		testWindowsNativeNetworkConfiguration(t, c)
		require.Nil(t, c.tundev.Close())
		c.tundev = nil
		assert.Eventually(t, func() bool {
			adapter, err := wintun.OpenAdapter(name)
			if err != nil {
				return true
			}
			adapter.Close()
			return false
		}, 10*time.Second, 100*time.Millisecond)
	}
}

func TestWindowsNativeLegacyWireGuardDriver(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_WINDOWS_LEGACY_DRIVER") != "1" {
		t.Skip("Legacy driver setup is restricted to the MSI upgrade test")
	}
	require.Equal(t, "1", os.Getenv("OCTELIUM_TEST_WINDOWS_DRIVERS"))
	require.Equal(t, "true", os.Getenv("GITHUB_ACTIONS"))
	require.True(t, windows.GetCurrentProcessToken().IsElevated())
	require.Nil(t, driver.Uninstall())
	adapter, err := driver.CreateAdapter("OcteliumLegacyUpgradeTest", "WireGuard", nil)
	require.Nil(t, err)
	t.Cleanup(func() { assert.Nil(t, adapter.Close()) })
	require.ErrorContains(t, checkWireGuardDLLVersion(), "Unsupported WireGuardNT DLL version")
	version, err := driver.RunningVersion()
	require.Nil(t, err)
	require.NotZero(t, version)
	require.NotEqual(t, uint32(1<<16|1), version)
	t.Logf("Legacy WireGuardNT driver loaded: %d.%d", version>>16, version&0xffff)
}

func TestWindowsNativeWireGuardTraffic(t *testing.T) {
	c := newTestWindowsNativeController(t, userv1.ConnectionState_BOTH)
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	tun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8:1::1"),
	}, nil, 1280)
	require.Nil(t, err)
	server := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "native-test"))
	t.Cleanup(server.Close)
	clientKey := c.wgPrivateKey.PublicKey()
	require.Nil(t, server.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=0\npublic_key=%x\nallowed_ip=192.0.2.2/32\nallowed_ip=2001:db8:1::2/128\n", serverKey[:], clientKey[:])))
	require.Nil(t, server.Up())
	configuration, err := server.IpcGet()
	require.Nil(t, err)
	var port int
	for _, line := range strings.Split(configuration, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err = strconv.Atoi(value)
			require.Nil(t, err)
		}
	}
	require.NotZero(t, port)
	c.c.Connection.Gateways[0].Wireguard.PublicKey = serverKey.PublicKey().String()
	c.c.Connection.Gateways[0].Wireguard.Port = int32(port)
	guid, err := c.getGUID()
	require.Nil(t, err)
	c.opts.adapter, err = driver.CreateAdapter("OcteliumNativeTraffic", "WireGuard", guid)
	require.Nil(t, err)
	require.Nil(t, checkWireGuardDLLVersion())
	require.Nil(t, c.setWGDev())
	require.Nil(t, c.doSetDevUp())
	require.Nil(t, c.SetDevAddrs())
	require.Nil(t, c.doSetRoutes())

	for _, addresses := range []struct {
		network string
		local   string
		remote  string
	}{
		{"udp4", "192.0.2.2", "192.0.2.1"},
		{"udp6", "2001:db8:1::2", "2001:db8:1::1"},
	} {
		t.Run(addresses.network, func(t *testing.T) {
			listener, err := serverNet.ListenUDPAddrPort(netip.AddrPortFrom(netip.MustParseAddr(addresses.remote), 0))
			require.Nil(t, err)
			t.Cleanup(func() { assert.Nil(t, listener.Close()) })
			require.Nil(t, listener.SetDeadline(time.Now().Add(15*time.Second)))
			done := make(chan error, 1)
			go func() {
				buffer := make([]byte, 1024)
				n, from, err := listener.ReadFrom(buffer)
				if err == nil {
					_, err = listener.WriteTo(buffer[:n], from)
				}
				done <- err
			}()
			var client *net.UDPConn
			require.Eventually(t, func() bool {
				client, err = net.DialUDP(addresses.network,
					&net.UDPAddr{IP: net.ParseIP(addresses.local)}, listener.LocalAddr().(*net.UDPAddr))
				return err == nil
			}, 10*time.Second, 100*time.Millisecond)
			t.Cleanup(func() { assert.Nil(t, client.Close()) })
			require.Nil(t, client.SetDeadline(time.Now().Add(15*time.Second)))
			payload := []byte("octelium-native-" + addresses.network)
			_, err = client.Write(payload)
			require.Nil(t, err)
			buffer := make([]byte, 1024)
			n, err := client.Read(buffer)
			require.Nil(t, err)
			assert.Equal(t, payload, buffer[:n])
			require.Nil(t, <-done)
		})
	}
	state, err := c.opts.adapter.Configuration()
	require.Nil(t, err)
	require.Equal(t, uint32(1), state.PeerCount)
	assert.NotZero(t, state.FirstPeer().LastHandshake)
	assert.NotZero(t, state.FirstPeer().TxBytes)
	assert.NotZero(t, state.FirstPeer().RxBytes)
}
