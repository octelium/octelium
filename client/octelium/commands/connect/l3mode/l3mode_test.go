package l3mode

import (
	"errors"
	"net"
	"testing"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetL3ModeExplicit(t *testing.T) {
	for _, tt := range []struct {
		mode string
		want userv1.ConnectRequest_Initialize_L3Mode
	}{
		{"v4", userv1.ConnectRequest_Initialize_V4},
		{"v6", userv1.ConnectRequest_Initialize_V6},
		{"both", userv1.ConnectRequest_Initialize_BOTH},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			mode, err := GetL3Mode(tt.mode)
			require.NoError(t, err)
			assert.Equal(t, tt.want, mode)
		})
	}
}

func TestSupportedIPFamilies(t *testing.T) {
	for _, tt := range []struct {
		name      string
		flags     net.Flags
		addresses []string
		exclude   string
		fail      bool
		queried   bool
		ipv4      bool
		ipv6      bool
	}{
		{name: "ipv4", flags: net.FlagUp, addresses: []string{"192.0.2.1/24"}, queried: true, ipv4: true},
		{name: "ipv6", flags: net.FlagUp, addresses: []string{"2001:db8::1/64"}, queried: true, ipv6: true},
		{name: "dual-stack", flags: net.FlagUp, addresses: []string{"192.0.2.1/24", "2001:db8::1/64"}, queried: true, ipv4: true, ipv6: true},
		{name: "mapped-ipv4", flags: net.FlagUp, addresses: []string{"::ffff:192.0.2.1/128"}, queried: true, ipv4: true},
		{name: "private", flags: net.FlagUp, addresses: []string{"10.0.0.1/24", "fd00::1/64"}, queried: true, ipv4: true, ipv6: true},
		{name: "ipv6-link-local", flags: net.FlagUp, addresses: []string{"192.0.2.1/24", "fe80::1/64"}, queried: true, ipv4: true},
		{name: "link-local-only", flags: net.FlagUp, addresses: []string{"169.254.1.1/16", "fe80::1/64"}, queried: true},
		{name: "non-unicast", flags: net.FlagUp, addresses: []string{"::/128", "0.0.0.0/32", "127.0.0.1/8", "::1/128", "224.0.0.1/32", "ff02::1/128"}, queried: true},
		{name: "down", addresses: []string{"192.0.2.1/24", "2001:db8::1/64"}},
		{name: "loopback-interface", flags: net.FlagUp | net.FlagLoopback, addresses: []string{"192.0.2.1/24"}},
		{name: "excluded-tunnel", flags: net.FlagUp, addresses: []string{"192.0.2.1/24", "fd00::1/64"}, exclude: "eth0"},
		{name: "address-error", flags: net.FlagUp, fail: true, queried: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var addrs []net.Addr
			for _, address := range tt.addresses {
				ip, prefix, err := net.ParseCIDR(address)
				require.NoError(t, err)
				prefix.IP = ip
				addrs = append(addrs, prefix)
			}
			queried := false
			ipv4, ipv6 := getSupportedIPFamilies([]net.Interface{{Name: "eth0", Flags: tt.flags}}, tt.exclude,
				func(net.Interface) ([]net.Addr, error) {
					queried = true
					if tt.fail {
						return nil, errors.New("could not read interface addresses")
					}
					return addrs, nil
				})
			assert.Equal(t, tt.queried, queried)
			assert.Equal(t, tt.ipv4, ipv4)
			assert.Equal(t, tt.ipv6, ipv6)
		})
	}
}

func TestSupportedIPFamiliesAcrossInterfaces(t *testing.T) {
	ipv4, ipv6 := getSupportedIPFamilies([]net.Interface{
		{Name: "v4", Flags: net.FlagUp},
		{Name: "v6", Flags: net.FlagUp},
		{Name: "unused", Flags: net.FlagUp},
	}, "", func(iface net.Interface) ([]net.Addr, error) {
		switch iface.Name {
		case "v4":
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.1")}}, nil
		case "v6":
			return []net.Addr{&net.IPNet{IP: net.ParseIP("2001:db8::1")}}, nil
		default:
			t.Fatal("continued reading interfaces after finding both address families")
			return nil, nil
		}
	})
	assert.True(t, ipv4)
	assert.True(t, ipv6)
}
