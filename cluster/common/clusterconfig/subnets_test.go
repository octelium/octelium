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

package clusterconfig

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func subnetConfig(cidr string) *corev1.ClusterConfig {
	return &corev1.ClusterConfig{Status: &corev1.ClusterConfig_Status{
		NetworkConfig: &corev1.ClusterConfig_Status_NetworkConfig{V4: &corev1.ClusterConfig_Status_NetworkConfig_V4{ClusterNetwork: cidr}},
		Network:       &corev1.ClusterConfig_Status_Network{V6RangePrefix: []byte{0x12, 0x34, 0x56, 0x78}},
	}}
}

func TestSetClusterSubnets(t *testing.T) {
	for _, tc := range []struct {
		cidr, cluster, service, wireguard, quic string
	}{
		{"", "100.64.0.0/10", "100.64.0.0/16", "100.65.0.0/16", "100.66.0.0/16"},
		{"10.0.0.0/8", "10.0.0.0/8", "10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16"},
		{"100.96.0.0/11", "100.96.0.0/11", "100.96.0.0/16", "100.97.0.0/16", "100.98.0.0/16"},
		{"172.16.0.0/12", "172.16.0.0/12", "172.16.0.0/16", "172.17.0.0/16", "172.18.0.0/16"},
		{"255.252.0.0/14", "255.252.0.0/14", "255.252.0.0/16", "255.253.0.0/16", "255.254.0.0/16"},
		{"0.0.0.0/0", "0.0.0.0/0", "0.0.0.0/16", "0.1.0.0/16", "0.2.0.0/16"},
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			c := subnetConfig(tc.cidr)
			require.NoError(t, SetClusterSubnets(c))
			network := c.Status.Network
			assert.Equal(t, &metav1.DualStackNetwork{V4: tc.cluster, V6: "fdee:1234:5678::/64"}, network.ClusterNetwork)
			assert.Equal(t, &metav1.DualStackNetwork{V4: tc.service, V6: "fdee:1234:5678::/80"}, network.ServiceSubnet)
			assert.Equal(t, &metav1.DualStackNetwork{V4: tc.wireguard, V6: "fdee:1234:5678:0:1::/80"}, network.WgConnSubnet)
			assert.Equal(t, &metav1.DualStackNetwork{V4: tc.quic, V6: "fdee:1234:5678:0:2::/80"}, network.QuicConnSubnet)
		})
	}
	for _, c := range []*corev1.ClusterConfig{{Status: &corev1.ClusterConfig_Status{}}, {Status: &corev1.ClusterConfig_Status{Network: &corev1.ClusterConfig_Status_Network{}}}} {
		require.NoError(t, SetClusterSubnets(c))
		assert.Equal(t, "100.64.0.0/10", c.Status.Network.ClusterNetwork.V4)
		assert.Equal(t, "fdee::/64", c.Status.Network.ClusterNetwork.V6)
	}
}

func TestSetClusterSubnetsRejectsInvalidCIDRs(t *testing.T) {
	for _, cidr := range []string{
		"invalid", "10.0.0.0", "10.0.0.0/-1", "10.0.0.0/33", "10.0.0.0/256", " 10.0.0.0/8", "10.0.0.0/8 ",
		"fd00::/64", "::ffff:10.0.0.0/104", "10.0.0.1/8", "10.2.0.0/14",
		"10.0.0.0/15", "10.0.0.0/16", "10.20.30.0/24", "255.255.0.0/16", "255.255.255.255/32",
	} {
		t.Run(cidr, func(t *testing.T) {
			c := subnetConfig(cidr)
			before := proto.Clone(c)
			require.ErrorContains(t, SetClusterSubnets(c), "network.v4.clusterNetwork")
			assert.True(t, proto.Equal(before, c))
		})
	}
	for _, c := range []*corev1.ClusterConfig{nil, {}} {
		require.ErrorContains(t, SetClusterSubnets(c), "ClusterConfig status")
	}
}

func TestSetClusterSubnetsValidatesNetworkOptions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*corev1.ClusterConfig_Status_NetworkConfig)
		valid  bool
	}{
		{"default", func(*corev1.ClusterConfig_Status_NetworkConfig) {}, true},
		{"dual-stack", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Mode = corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK
		}, true},
		{"v4-only", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Mode = corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY
		}, true},
		{"v6-only", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Mode = corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY
		}, true},
		{"unknown-mode", func(c *corev1.ClusterConfig_Status_NetworkConfig) { c.Mode = 99 }, false},
		{"negative-mode", func(c *corev1.ClusterConfig_Status_NetworkConfig) { c.Mode = -1 }, false},
		{"custom-bits", func(c *corev1.ClusterConfig_Status_NetworkConfig) { c.V4.RegionBits, c.V4.GatewayBits = 3, 5 }, true},
		{"minimum-region-bits", func(c *corev1.ClusterConfig_Status_NetworkConfig) { c.V4.RegionBits, c.V4.GatewayBits = 1, 7 }, true},
		{"too-many-bits", func(c *corev1.ClusterConfig_Status_NetworkConfig) { c.V4.RegionBits, c.V4.GatewayBits = 5, 4 }, false},
		{"default-region-bits", func(c *corev1.ClusterConfig_Status_NetworkConfig) { c.V4.GatewayBits = 5 }, false},
		{"default-gateway-bits", func(c *corev1.ClusterConfig_Status_NetworkConfig) { c.V4.RegionBits = 5 }, false},
		{"overflowing-bits", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.V4.RegionBits, c.V4.GatewayBits = math.MaxUint32, math.MaxUint32
		}, false},
		{"unused-v4-bits", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Mode = corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY
			c.V4.RegionBits, c.V4.GatewayBits = math.MaxUint32, math.MaxUint32
		}, true},
		{"valid-wireguard", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Wireguard = &corev1.ClusterConfig_Status_NetworkConfig_Wireguard{GatewayPort: 65535, Mtu: 1380}
		}, true},
		{"invalid-wireguard-port", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Wireguard = &corev1.ClusterConfig_Status_NetworkConfig_Wireguard{GatewayPort: 65536}
		}, false},
		{"invalid-quic-port", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Quicv0 = &corev1.ClusterConfig_Status_NetworkConfig_QUICV0{GatewayPort: math.MaxUint32}
		}, false},
		{"small-v6-mtu", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Wireguard = &corev1.ClusterConfig_Status_NetworkConfig_Wireguard{Mtu: 1279}
		}, false},
		{"small-v4-mtu", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Mode = corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY
			c.Wireguard = &corev1.ClusterConfig_Status_NetworkConfig_Wireguard{Mtu: 575}
		}, false},
		{"minimum-v4-mtu", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Mode = corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY
			c.Wireguard = &corev1.ClusterConfig_Status_NetworkConfig_Wireguard{Mtu: 576}
		}, true},
		{"overflowing-mtu", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Wireguard = &corev1.ClusterConfig_Status_NetworkConfig_Wireguard{Mtu: math.MaxUint32}
		}, false},
		{"quic-mtu-clamp", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Quicv0 = &corev1.ClusterConfig_Status_NetworkConfig_QUICV0{Enable: true, Mtu: 1380}
		}, true},
		{"small-quic-mtu", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Quicv0 = &corev1.ClusterConfig_Status_NetworkConfig_QUICV0{Enable: true, Mtu: 1279}
		}, false},
		{"same-default-wireguard-port", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Quicv0 = &corev1.ClusterConfig_Status_NetworkConfig_QUICV0{Enable: true, GatewayPort: 53820}
		}, false},
		{"same-default-quic-port", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Quicv0 = &corev1.ClusterConfig_Status_NetworkConfig_QUICV0{Enable: true}
			c.Wireguard = &corev1.ClusterConfig_Status_NetworkConfig_Wireguard{GatewayPort: 8443}
		}, false},
		{"disabled-quic-port", func(c *corev1.ClusterConfig_Status_NetworkConfig) {
			c.Quicv0 = &corev1.ClusterConfig_Status_NetworkConfig_QUICV0{GatewayPort: 53820}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := subnetConfig("")
			tc.change(c.Status.NetworkConfig)
			before := proto.Clone(c)
			err := SetClusterSubnets(c)
			if !tc.valid {
				require.Error(t, err)
				assert.True(t, proto.Equal(before, c))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "100.64.0.0/16", c.Status.Network.ServiceSubnet.V4)
			assert.Equal(t, "fdee:1234:5678::/80", c.Status.Network.ServiceSubnet.V6)
		})
	}
}

func TestSetClusterSubnetsPreservesExistingAllocation(t *testing.T) {
	for _, family := range []string{"dual-stack", "v4", "v6"} {
		t.Run(family, func(t *testing.T) {
			c := subnetConfig("")
			require.NoError(t, SetClusterSubnets(c))
			for _, subnet := range []*metav1.DualStackNetwork{c.Status.Network.ClusterNetwork, c.Status.Network.ServiceSubnet, c.Status.Network.WgConnSubnet, c.Status.Network.QuicConnSubnet} {
				if family == "v4" {
					subnet.V6 = ""
				} else if family == "v6" {
					subnet.V4 = ""
				}
			}
			c.Status.NetworkConfig.Mode = 99
			c.Status.NetworkConfig.V4.ClusterNetwork = "10.20.30.0/24"
			c.Status.NetworkConfig.V4.RegionBits = math.MaxUint32
			c.Status.NetworkConfig.Wireguard = &corev1.ClusterConfig_Status_NetworkConfig_Wireguard{GatewayPort: math.MaxUint32, Mtu: 1}
			before := proto.Clone(c)
			network := c.Status.Network
			require.NoError(t, SetClusterSubnets(c))
			assert.Same(t, network, c.Status.Network)
			assert.True(t, proto.Equal(before, c))
		})
	}
	c := subnetConfig("10.20.30.0/24")
	c.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{V4: "10.20.30.0/24"}
	c.Status.Network.ServiceSubnet = &metav1.DualStackNetwork{V4: "10.20.0.0/16"}
	c.Status.Network.WgConnSubnet = &metav1.DualStackNetwork{V4: "10.21.0.0/16"}
	c.Status.Network.QuicConnSubnet = &metav1.DualStackNetwork{V4: "10.22.0.0/16"}
	before := proto.Clone(c)
	require.NoError(t, SetClusterSubnets(c))
	assert.True(t, proto.Equal(before, c))
	c.Status.Network.WgConnSubnet = nil
	before = proto.Clone(c)
	require.ErrorContains(t, SetClusterSubnets(c), "partially allocated")
	assert.True(t, proto.Equal(before, c))
}

func TestSetClusterSubnetsPreservesIPv6Prefix(t *testing.T) {
	for _, tc := range []struct {
		prefix []byte
		want   string
	}{
		{nil, "fdee::/64"}, {[]byte{}, "fdee::/64"}, {[]byte{1}, "fdee::/64"}, {[]byte{1, 2, 3}, "fdee::/64"},
		{[]byte{1, 2, 3, 4}, "fdee:102:304::/64"}, {[]byte{255, 255, 255, 255, 7}, "fdee:ffff:ffff::/64"},
	} {
		c := subnetConfig("")
		c.Status.Network.V6RangePrefix = tc.prefix
		before := proto.Clone(c.Status.Network)
		original := c.Status.Network
		require.NoError(t, SetClusterSubnets(c))
		assert.Equal(t, tc.want, c.Status.Network.ClusterNetwork.V6)
		assert.True(t, bytes.Equal(tc.prefix, c.Status.Network.V6RangePrefix))
		assert.True(t, proto.Equal(before, original))
	}
}

func TestSetClusterSubnetsKeepsAutomaticIPv6Allocation(t *testing.T) {
	for _, cidr := range []string{"2001:db8::/48", "invalid"} {
		c := subnetConfig("")
		c.Status.NetworkConfig.V6 = &corev1.ClusterConfig_Status_NetworkConfig_V6{ClusterNetwork: cidr}
		require.NoError(t, SetClusterSubnets(c))
		assert.Equal(t, "fdee:1234:5678::/64", c.Status.Network.ClusterNetwork.V6)
		assert.Equal(t, cidr, c.Status.NetworkConfig.V6.ClusterNetwork)
	}
}

func TestSetClusterSubnetsContainsEveryIPv4Allocation(t *testing.T) {
	for bits := 0; bits <= 14; bits++ {
		for index := uint64(0); index < uint64(1)<<bits; index++ {
			var address [4]byte
			binary.BigEndian.PutUint32(address[:], uint32(index<<uint(32-bits)))
			parent := netip.PrefixFrom(netip.AddrFrom4(address), bits)
			c := subnetConfig(parent.String())
			require.NoError(t, SetClusterSubnets(c), parent)
			checkSubnetContainment(t, c)
		}
	}
}

func checkSubnetContainment(t *testing.T, c *corev1.ClusterConfig) {
	t.Helper()
	for _, family := range []string{"v4", "v6"} {
		get := func(subnet *metav1.DualStackNetwork) string {
			if family == "v4" {
				return subnet.V4
			}
			return subnet.V6
		}
		parent, err := netip.ParsePrefix(get(c.Status.Network.ClusterNetwork))
		require.NoError(t, err)
		var children []netip.Prefix
		for _, subnet := range []*metav1.DualStackNetwork{c.Status.Network.ServiceSubnet, c.Status.Network.WgConnSubnet, c.Status.Network.QuicConnSubnet} {
			child, err := netip.ParsePrefix(get(subnet))
			require.NoError(t, err)
			require.Equal(t, child.Masked(), child)
			require.GreaterOrEqual(t, child.Bits(), parent.Bits())
			require.True(t, parent.Contains(child.Addr()), "%s outside %s", child, parent)
			for _, previous := range children {
				require.False(t, previous.Overlaps(child), "%s overlaps %s", previous, child)
			}
			children = append(children, child)
		}
	}
}

func FuzzSetClusterSubnets(f *testing.F) {
	for _, cidr := range []string{"", "100.64.0.0/10", "255.252.0.0/14", "10.20.30.0/24", "invalid", "fd00::/64"} {
		f.Add(cidr, []byte{1, 2, 3, 4})
	}
	f.Fuzz(func(t *testing.T, cidr string, v6 []byte) {
		c := subnetConfig(cidr)
		c.Status.Network.V6RangePrefix = v6
		before := proto.Clone(c)
		if err := SetClusterSubnets(c); err != nil {
			require.True(t, proto.Equal(before, c))
			return
		}
		checkSubnetContainment(t, c)
	})
}
