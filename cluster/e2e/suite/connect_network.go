/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package suite

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	resolvConfPath = "/etc/resolv.conf"

	overrideMTU = 1380
)

func hostHasIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.To4() != nil || ip.IsLoopback() ||
				ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}

			return true
		}
	}

	return false
}

func connectionAddrs(c *corev1.Session_Status_Connection, isV6 bool) []netip.Addr {
	var ret []netip.Addr

	for _, addr := range c.Addresses {
		val := addr.V4
		if isV6 {
			val = addr.V6
		}
		if val == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(val); err == nil {
			ret = append(ret, pfx.Addr())
			continue
		}
		if parsed, err := netip.ParseAddr(val); err == nil {
			ret = append(ret, parsed)
		}
	}

	return ret
}

func hasPrefix(routes []netip.Prefix, cidr string) bool {
	want, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}

	return slices.Contains(routes, want.Masked())
}

func readResolvConf(t *testing.T) string {
	t.Helper()

	content, err := os.ReadFile(resolvConfPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("Could not read %s: %+v", resolvConfPath, err)
	}

	return string(content)
}

func testConnectIPMode(t *testing.T, h *harness.H) {
	h.Require(t, capRootTUN)

	cc := h.ClusterConfig(t)
	require.NotNil(t, cc.Status.Network)
	require.NotNil(t, cc.Status.Network.ServiceSubnet)

	defaultMode := corev1.Session_Status_Connection_V4
	if hostHasIPv6() {
		defaultMode = corev1.Session_Status_Connection_V6
	}

	zap.L().Info("The default IP mode of this host",
		zap.String("mode", defaultMode.String()))

	for _, tc := range []struct {
		name string
		mode string
		want corev1.Session_Status_Connection_L3Mode
		caps []scenario.Capability
	}{
		{
			name: "Default",
			want: defaultMode,
			caps: []scenario.Capability{capIPv6},
		},
		{
			name: "IPv4",
			mode: "v4",
			want: corev1.Session_Status_Connection_V4,
		},
		{
			name: "IPv6",
			mode: "v6",
			want: corev1.Session_Status_Connection_V6,
			caps: []scenario.Capability{capIPv6},
		},
		{
			name: "DualStack",
			mode: "both",
			want: corev1.Session_Status_Connection_BOTH,
			caps: []scenario.Capability{capIPv6},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.Require(t, tc.caps...)

			args := []string{"--no-dns"}
			if tc.mode != "" {
				args = append(args, fmt.Sprintf("--ip-mode %s", tc.mode))
			}

			h.Connect(t, harness.ConnectOpts{Root: true, Args: args})

			sess := h.GetSession(t, h.Status(t).Session.Metadata.Name)
			require.NotNil(t, sess.Status.Connection)
			require.Equal(t, tc.want, sess.Status.Connection.L3Mode,
				"the Cluster did not honor the requested IP mode")

			dev, err := h.TunDevice(t)
			require.Nil(t, err, "could not determine the tunnel device")

			addrs := h.DeviceAddrs(t, dev)
			routes := h.DeviceRoutes(t, dev)

			zap.L().Info("The tunnel device state",
				zap.String("dev", dev), zap.String("mode", tc.want.String()),
				zap.Any("addrs", addrs), zap.Any("routes", routes))

			for _, family := range []struct {
				name string
				isV6 bool
				want bool
				cidr string
			}{
				{
					name: "IPv4",
					want: tc.want != corev1.Session_Status_Connection_V6,
					cidr: cc.Status.Network.ServiceSubnet.V4,
				},
				{
					name: "IPv6",
					isV6: true,
					want: tc.want != corev1.Session_Status_Connection_V4,
					cidr: cc.Status.Network.ServiceSubnet.V6,
				},
			} {
				for _, addr := range connectionAddrs(sess.Status.Connection, family.isV6) {
					assert.Equal(t, family.want, slices.Contains(addrs, addr),
						"the %s Session address %s set on the %s device does not match the %s mode. Device addresses: %v",
						family.name, addr, dev, tc.want, addrs)
				}

				if family.cidr == "" {
					continue
				}

				assert.Equal(t, family.want, hasPrefix(routes, family.cidr),
					"the %s Service subnet route %s via the %s device does not match the %s mode. Device routes: %v",
					family.name, family.cidr, dev, tc.want, routes)
			}
		})
	}

	t.Run("Cleanup", func(t *testing.T) {
		conn := h.Connect(t, harness.ConnectOpts{Root: true, Args: []string{"--no-dns"}})

		dev, err := h.TunDevice(t)
		require.Nil(t, err, "could not determine the tunnel device")

		addrs := h.LocalSessionAddrs(t)
		require.True(t, len(addrs) > 0, "no Session address was set on the host")

		require.Nil(t, conn.Disconnect())

		assert.False(t, h.HasDevice(t, dev),
			"the %s device is still present after octelium disconnect", dev)

		for _, addr := range addrs {
			assert.Empty(t, h.DeviceHoldingAddr(t, addr.String()),
				"the Session address %s is still set on the host after octelium disconnect",
				addr)
		}
	})
}

func requireKernelWireGuard(t *testing.T, h *harness.H) {
	t.Helper()

	dev := fmt.Sprintf("octwg%s", utilrand.GetRandomStringCanonical(6))

	if err := h.Run(t.Context(),
		fmt.Sprintf("sudo ip link add dev %s type wireguard", dev)); err != nil {
		t.Skipf("this host cannot create kernel WireGuard devices: %+v", err)
	}

	if err := h.Run(t.Context(), fmt.Sprintf("sudo ip link del dev %s", dev)); err != nil {
		t.Fatalf("Could not delete the probe device %s: %+v", dev, err)
	}
}

func requireTUNDevice(t *testing.T, h *harness.H) {
	t.Helper()

	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("this host has no /dev/net/tun: %+v", err)
	}
}

func testConnectImplementation(t *testing.T, h *harness.H) {
	svc := h.NewPublicService(t, "default")

	t.Run("Netstack", func(t *testing.T) {
		before := readResolvConf(t)

		port := h.Port()
		conn := h.Connect(t, harness.ConnectOpts{
			Publish: map[string]int{svc.Metadata.Name: port},
			Args:    []string{"--implementation gvisor"},
		})

		h.WaitGetStatus(t, h.HTTP(), conn.URL(svc.Metadata.Name), http.StatusOK)

		for _, addr := range h.SessionAddrs(t) {
			assert.Empty(t, h.DeviceHoldingAddr(t, addr),
				"the userspace implementation must not set the Session address %s on the host",
				addr)
		}

		assert.Equal(t, before, readResolvConf(t),
			"the userspace implementation must not touch %s", resolvConfPath)
	})

	for _, tc := range []struct {
		name        string
		mode        string
		isWireGuard bool
		probe       func(t *testing.T, h *harness.H)
	}{
		{
			name:        "Kernel",
			mode:        "kernel",
			isWireGuard: true,
			probe:       requireKernelWireGuard,
		},
		{
			name:  "TUN",
			mode:  "tun",
			probe: requireTUNDevice,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.Require(t, capRootTUN)
			tc.probe(t, h)

			h.Connect(t, harness.ConnectOpts{
				Root: true,
				Args: []string{"--no-dns", fmt.Sprintf("--implementation %s", tc.mode)},
			})

			dev, err := h.TunDevice(t)
			require.Nil(t, err, "could not determine the tunnel device")

			out := string(h.MustOutput(t, fmt.Sprintf("ip -d link show dev %s", dev)))

			zap.L().Info("The tunnel device of the enforced implementation",
				zap.String("mode", tc.mode), zap.String("dev", dev), zap.String("link", out))

			if tc.isWireGuard {
				assert.Contains(t, out, "wireguard",
					"the kernel implementation must create a WireGuard device")
			} else {
				assert.NotContains(t, out, "wireguard",
					"the userspace implementation must not create a WireGuard device")
			}
		})
	}

	t.Run("MTU", func(t *testing.T) {
		h.Require(t, capRootTUN)

		h.Connect(t, harness.ConnectOpts{
			Root: true,
			Args: []string{"--no-dns"},
			Env:  []string{fmt.Sprintf("OCTELIUM_MTU=%d", overrideMTU)},
		})

		dev, err := h.TunDevice(t)
		require.Nil(t, err, "could not determine the tunnel device")

		assert.Equal(t, overrideMTU, h.DeviceMTU(t, dev),
			"the %s device did not use the requested MTU", dev)
	})
}
