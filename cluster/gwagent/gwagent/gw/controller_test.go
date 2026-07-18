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

package gw

import (
	"net"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func fakeClusterConfig(serviceV4, serviceV6 string, mode corev1.ClusterConfig_Status_NetworkConfig_Mode, regionBits, gatewayBits uint32) *corev1.ClusterConfig {
	return &corev1.ClusterConfig{
		Status: &corev1.ClusterConfig_Status{
			Network: &corev1.ClusterConfig_Status_Network{
				ServiceSubnet: &metav1.DualStackNetwork{
					V4: serviceV4,
					V6: serviceV6,
				},
			},
			NetworkConfig: &corev1.ClusterConfig_Status_NetworkConfig{
				Mode: mode,
				V4: &corev1.ClusterConfig_Status_NetworkConfig_V4{
					RegionBits:  regionBits,
					GatewayBits: gatewayBits,
				},
			},
		},
	}
}

func TestGetGatewaySubnetV4(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 0, 0)

		cases := []struct {
			regionIdx int
			nodeIdx   int
			expected  string
		}{
			{0, 0, "100.64.0.0/24"},
			{0, 1, "100.64.1.0/24"},
			{1, 0, "100.64.16.0/24"},
			{2, 3, "100.64.35.0/24"},
			{15, 15, "100.64.255.0/24"},
		}

		for _, tc := range cases {
			ret, err := getGatewaySubnetV4(c, tc.nodeIdx, tc.regionIdx)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, ret.String())
		}
	})

	t.Run("customBits", func(t *testing.T) {
		c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 6, 8)

		cases := []struct {
			regionIdx int
			nodeIdx   int
			expected  string
		}{
			{0, 0, "100.64.0.0/24"},
			{0, 255, "100.64.255.0/24"},
			{1, 0, "100.65.0.0/24"},
			{1, 255, "100.65.255.0/24"},
		}

		for _, tc := range cases {
			ret, err := getGatewaySubnetV4(c, tc.nodeIdx, tc.regionIdx)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, ret.String())
		}
	})

	t.Run("prefix16", func(t *testing.T) {
		c := fakeClusterConfig("100.64.0.0/16", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)

		cases := []struct {
			regionIdx int
			nodeIdx   int
			expected  string
		}{
			{0, 0, "100.64.0.0/24"},
			{1, 2, "100.64.18.0/24"},
			{15, 15, "100.64.255.0/24"},
		}

		for _, tc := range cases {
			ret, err := getGatewaySubnetV4(c, tc.nodeIdx, tc.regionIdx)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, ret.String())
		}
	})

	t.Run("nilConfig", func(t *testing.T) {
		c := &corev1.ClusterConfig{
			Status: &corev1.ClusterConfig_Status{
				Network: &corev1.ClusterConfig_Status_Network{
					ServiceSubnet: &metav1.DualStackNetwork{
						V4: "100.64.0.0/10",
					},
				},
				NetworkConfig: &corev1.ClusterConfig_Status_NetworkConfig{},
			},
		}

		ret, err := getGatewaySubnetV4(c, 0, 0)
		assert.Nil(t, err)
		assert.Equal(t, "100.64.0.0/24", ret.String())

		ret, err = getGatewaySubnetV4(c, 3, 2)
		assert.Nil(t, err)
		assert.Equal(t, "100.64.35.0/24", ret.String())
	})

	t.Run("errors", func(t *testing.T) {
		{
			c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)
			ret, err := getGatewaySubnetV4(c, 0, 16)
			assert.NotNil(t, err)
			assert.Nil(t, ret)
		}
		{
			c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)
			ret, err := getGatewaySubnetV4(c, 16, 0)
			assert.NotNil(t, err)
			assert.Nil(t, ret)
		}
		{
			c := fakeClusterConfig("100.64.0.0/20", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)
			ret, err := getGatewaySubnetV4(c, 0, 0)
			assert.NotNil(t, err)
			assert.Nil(t, ret)
		}
		{
			c := fakeClusterConfig("100.64.0.0/25", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)
			ret, err := getGatewaySubnetV4(c, 0, 0)
			assert.NotNil(t, err)
			assert.Nil(t, ret)
		}
		{
			c := fakeClusterConfig("", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)
			ret, err := getGatewaySubnetV4(c, 0, 0)
			assert.NotNil(t, err)
			assert.Nil(t, ret)
		}
		{
			c := fakeClusterConfig("not-a-cidr", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)
			ret, err := getGatewaySubnetV4(c, 0, 0)
			assert.NotNil(t, err)
			assert.Nil(t, ret)
		}
		{
			c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)
			ret, err := getGatewaySubnetV4(c, -1, 0)
			assert.NotNil(t, err)
			assert.Nil(t, ret)
		}
		{
			c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)
			ret, err := getGatewaySubnetV4(c, 0, -1)
			assert.NotNil(t, err)
			assert.Nil(t, ret)
		}
	})
}

func TestGetGatewaySubnetV6(t *testing.T) {
	c := fakeClusterConfig("", "fd00::/64", corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY, 0, 0)

	cases := []struct {
		regionIdx int
		nodeIdx   int
		expected  string
	}{
		{0, 0, "fd00::/112"},
		{1, 0, "fd00::1:0:0/112"},
		{0, 1, "fd00::1:0/112"},
		{2, 5, "fd00::2:5:0/112"},
	}

	for _, tc := range cases {
		ret, err := getGatewaySubnet(c, tc.nodeIdx, tc.regionIdx)
		assert.Nil(t, err)
		assert.Nil(t, ret.V4)
		assert.Equal(t, tc.expected, ret.V6.String())
	}
}

func TestGetGatewaySubnet(t *testing.T) {
	t.Run("dualStack", func(t *testing.T) {
		c := fakeClusterConfig("100.64.0.0/10", "fd00::/64", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)

		ret, err := getGatewaySubnet(c, 3, 2)
		assert.Nil(t, err)
		assert.Equal(t, "100.64.35.0/24", ret.V4.String())
		assert.Equal(t, "fd00::2:3:0/112", ret.V6.String())
	})

	t.Run("v4Only", func(t *testing.T) {
		c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY, 4, 4)

		ret, err := getGatewaySubnet(c, 3, 2)
		assert.Nil(t, err)
		assert.Equal(t, "100.64.35.0/24", ret.V4.String())
		assert.Nil(t, ret.V6)
	})

	t.Run("v6Only", func(t *testing.T) {
		c := fakeClusterConfig("", "fd00::/64", corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY, 4, 4)

		ret, err := getGatewaySubnet(c, 3, 2)
		assert.Nil(t, err)
		assert.Nil(t, ret.V4)
		assert.Equal(t, "fd00::2:3:0/112", ret.V6.String())
	})
}

func TestSubnetIndex(t *testing.T) {
	t.Run("roundTripV4", func(t *testing.T) {
		_, base, err := net.ParseCIDR("100.64.0.0/10")
		assert.Nil(t, err)

		for _, idx := range []uint64{0, 1, 15, 16, 35, 255} {
			sub, err := nthSubnet(base, gatewayPrefixLenV4, idx)
			assert.Nil(t, err)

			ret, err := subnetIndex(base, gatewayPrefixLenV4, sub)
			assert.Nil(t, err)
			assert.Equal(t, idx, ret)
		}
	})

	t.Run("roundTripV6", func(t *testing.T) {
		_, base, err := net.ParseCIDR("fd00::/64")
		assert.Nil(t, err)

		for _, idx := range []uint64{0, 1, 255, 65535} {
			sub, err := nthSubnet(base, gatewayPrefixLenV6, idx)
			assert.Nil(t, err)

			ret, err := subnetIndex(base, gatewayPrefixLenV6, sub)
			assert.Nil(t, err)
			assert.Equal(t, idx, ret)
		}
	})

	t.Run("errors", func(t *testing.T) {
		_, base, err := net.ParseCIDR("100.64.0.0/10")
		assert.Nil(t, err)

		{
			ret, err := subnetIndex(nil, gatewayPrefixLenV4, base)
			assert.NotNil(t, err)
			assert.Equal(t, uint64(0), ret)
		}
		{
			ret, err := subnetIndex(base, gatewayPrefixLenV4, nil)
			assert.NotNil(t, err)
			assert.Equal(t, uint64(0), ret)
		}
		{
			_, sub, err := net.ParseCIDR("100.64.1.0/25")
			assert.Nil(t, err)
			_, err = subnetIndex(base, gatewayPrefixLenV4, sub)
			assert.NotNil(t, err)
		}
		{
			_, sub, err := net.ParseCIDR("10.0.0.0/24")
			assert.Nil(t, err)
			_, err = subnetIndex(base, gatewayPrefixLenV4, sub)
			assert.NotNil(t, err)
		}
		{
			_, sub, err := net.ParseCIDR("fd00::/112")
			assert.Nil(t, err)
			_, err = subnetIndex(base, gatewayPrefixLenV4, sub)
			assert.NotNil(t, err)
		}
		{
			misaligned := &net.IPNet{
				IP:   net.ParseIP("100.64.0.128").To4(),
				Mask: net.CIDRMask(gatewayPrefixLenV4, 32),
			}
			_, err := subnetIndex(base, gatewayPrefixLenV4, misaligned)
			assert.NotNil(t, err)
		}
	})
}

func TestInferGatewayIndexV4(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 0, 0)

		cases := []struct {
			cidr      string
			regionIdx int
			expected  int
		}{
			{"100.64.0.0/24", 0, 0},
			{"100.64.1.0/24", 0, 1},
			{"100.64.16.0/24", 1, 0},
			{"100.64.35.0/24", 2, 3},
			{"100.64.255.0/24", 15, 15},
		}

		for _, tc := range cases {
			ret, err := inferGatewayIndexV4(c, tc.cidr, tc.regionIdx)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, ret)
		}
	})

	t.Run("customBits", func(t *testing.T) {
		c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 6, 8)

		cases := []struct {
			cidr      string
			regionIdx int
			expected  int
		}{
			{"100.64.0.0/24", 0, 0},
			{"100.64.255.0/24", 0, 255},
			{"100.65.0.0/24", 1, 0},
			{"100.65.255.0/24", 1, 255},
		}

		for _, tc := range cases {
			ret, err := inferGatewayIndexV4(c, tc.cidr, tc.regionIdx)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, ret)
		}
	})

	t.Run("errors", func(t *testing.T) {
		c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)

		{
			_, err := inferGatewayIndexV4(c, "100.64.16.0/24", 0)
			assert.NotNil(t, err)
		}
		{
			_, err := inferGatewayIndexV4(c, "100.64.0.0/24", 1)
			assert.NotNil(t, err)
		}
		{
			_, err := inferGatewayIndexV4(c, "not-a-cidr", 0)
			assert.NotNil(t, err)
		}
		{
			_, err := inferGatewayIndexV4(c, "100.64.0.0/25", 0)
			assert.NotNil(t, err)
		}
		{
			_, err := inferGatewayIndexV4(c, "10.0.0.0/24", 0)
			assert.NotNil(t, err)
		}
		{
			cEmpty := fakeClusterConfig("", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)
			_, err := inferGatewayIndexV4(cEmpty, "100.64.0.0/24", 0)
			assert.NotNil(t, err)
		}
	})
}

func TestInferGatewayIndexV6(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cases := []struct {
			cidr      string
			regionIdx int
			expected  int
		}{
			{"fd00::/112", 0, 0},
			{"fd00::1:0/112", 0, 1},
			{"fd00::1:0:0/112", 1, 0},
			{"fd00::2:5:0/112", 2, 5},
		}

		for _, tc := range cases {
			ret, err := inferGatewayIndexV6(tc.cidr, tc.regionIdx)
			assert.Nil(t, err)
			assert.Equal(t, tc.expected, ret)
		}
	})

	t.Run("errors", func(t *testing.T) {
		{
			_, err := inferGatewayIndexV6("fd00::/64", 0)
			assert.NotNil(t, err)
		}
		{
			_, err := inferGatewayIndexV6("fd00::2:5:0/112", 1)
			assert.NotNil(t, err)
		}
		{
			_, err := inferGatewayIndexV6("not-a-cidr", 0)
			assert.NotNil(t, err)
		}
		{
			_, err := inferGatewayIndexV6("100.64.0.0/24", 0)
			assert.NotNil(t, err)
		}
	})
}

func TestInferGatewayIndexFromCIDR(t *testing.T) {
	c := fakeClusterConfig("100.64.0.0/10", "fd00::/64", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)

	{
		ret, err := inferGatewayIndexFromCIDR(c, &metav1.DualStackNetwork{
			V4: "100.64.35.0/24",
			V6: "fd00::2:3:0/112",
		}, 2)
		assert.Nil(t, err)
		assert.Equal(t, 3, ret)
	}
	{
		ret, err := inferGatewayIndexFromCIDR(c, &metav1.DualStackNetwork{
			V4: "100.64.35.0/24",
		}, 2)
		assert.Nil(t, err)
		assert.Equal(t, 3, ret)
	}
	{
		ret, err := inferGatewayIndexFromCIDR(c, &metav1.DualStackNetwork{
			V6: "fd00::2:3:0/112",
		}, 2)
		assert.Nil(t, err)
		assert.Equal(t, 3, ret)
	}
	{
		_, err := inferGatewayIndexFromCIDR(c, nil, 0)
		assert.NotNil(t, err)
	}
	{
		_, err := inferGatewayIndexFromCIDR(c, &metav1.DualStackNetwork{}, 0)
		assert.NotNil(t, err)
	}
}

func TestGetGatewayIndex(t *testing.T) {
	c := fakeClusterConfig("100.64.0.0/10", "fd00::/64", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)

	t.Run("explicit", func(t *testing.T) {
		gw := &corev1.Gateway{
			Metadata: &metav1.Metadata{Name: "gw-1"},
			Status: &corev1.Gateway_Status{
				Index: new(int32(7)),
				Cidr: &metav1.DualStackNetwork{
					V4: "100.64.35.0/24",
				},
			},
		}

		ret, err := getGatewayIndex(c, gw, 2)
		assert.Nil(t, err)
		assert.Equal(t, 7, ret)
	})

	t.Run("explicitZero", func(t *testing.T) {
		gw := &corev1.Gateway{
			Metadata: &metav1.Metadata{Name: "gw-1"},
			Status: &corev1.Gateway_Status{
				Index: new(int32(0)),
				Cidr: &metav1.DualStackNetwork{
					V4: "100.64.35.0/24",
				},
			},
		}

		ret, err := getGatewayIndex(c, gw, 2)
		assert.Nil(t, err)
		assert.Equal(t, 0, ret)
	})

	t.Run("inferred", func(t *testing.T) {
		gw := &corev1.Gateway{
			Metadata: &metav1.Metadata{Name: "gw-1"},
			Status: &corev1.Gateway_Status{
				Cidr: &metav1.DualStackNetwork{
					V4: "100.64.35.0/24",
				},
			},
		}

		assert.Nil(t, gw.Status.Index)

		ret, err := getGatewayIndex(c, gw, 2)
		assert.Nil(t, err)
		assert.Equal(t, 3, ret)
	})

	t.Run("inferredV6Only", func(t *testing.T) {
		gw := &corev1.Gateway{
			Metadata: &metav1.Metadata{Name: "gw-1"},
			Status: &corev1.Gateway_Status{
				Cidr: &metav1.DualStackNetwork{
					V6: "fd00::2:5:0/112",
				},
			},
		}

		ret, err := getGatewayIndex(c, gw, 2)
		assert.Nil(t, err)
		assert.Equal(t, 5, ret)
	})

	t.Run("errors", func(t *testing.T) {
		{
			gw := &corev1.Gateway{
				Metadata: &metav1.Metadata{Name: "gw-1"},
			}
			_, err := getGatewayIndex(c, gw, 0)
			assert.NotNil(t, err)
		}
		{
			gw := &corev1.Gateway{
				Metadata: &metav1.Metadata{Name: "gw-1"},
				Status:   &corev1.Gateway_Status{},
			}
			_, err := getGatewayIndex(c, gw, 0)
			assert.NotNil(t, err)
		}
	})
}

func TestGatewayIndexRoundTrip(t *testing.T) {
	t.Run("dualStack", func(t *testing.T) {
		c := fakeClusterConfig("100.64.0.0/10", "fd00::/64", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)

		for regionIdx := 0; regionIdx < 4; regionIdx++ {
			for nodeIdx := 0; nodeIdx < 16; nodeIdx++ {
				gwNet, err := getGatewaySubnet(c, nodeIdx, regionIdx)
				assert.Nil(t, err)

				ret, err := inferGatewayIndexFromCIDR(c, &metav1.DualStackNetwork{
					V4: gwNet.V4.String(),
					V6: gwNet.V6.String(),
				}, regionIdx)
				assert.Nil(t, err)
				assert.Equal(t, nodeIdx, ret)
			}
		}
	})

	t.Run("v4Only", func(t *testing.T) {
		c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY, 6, 8)

		for regionIdx := 0; regionIdx < 3; regionIdx++ {
			for nodeIdx := 0; nodeIdx < 256; nodeIdx++ {
				gwNet, err := getGatewaySubnet(c, nodeIdx, regionIdx)
				assert.Nil(t, err)

				ret, err := inferGatewayIndexFromCIDR(c, &metav1.DualStackNetwork{
					V4: gwNet.V4.String(),
				}, regionIdx)
				assert.Nil(t, err)
				assert.Equal(t, nodeIdx, ret)
			}
		}
	})

	t.Run("v6Only", func(t *testing.T) {
		c := fakeClusterConfig("", "fd00::/64", corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY, 4, 4)

		for regionIdx := 0; regionIdx < 4; regionIdx++ {
			for nodeIdx := 0; nodeIdx < 16; nodeIdx++ {
				gwNet, err := getGatewaySubnet(c, nodeIdx, regionIdx)
				assert.Nil(t, err)

				ret, err := inferGatewayIndexFromCIDR(c, &metav1.DualStackNetwork{
					V6: gwNet.V6.String(),
				}, regionIdx)
				assert.Nil(t, err)
				assert.Equal(t, nodeIdx, ret)
			}
		}
	})
}

func TestGetMaxGatewaysPerRegion(t *testing.T) {
	{
		c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 0, 0)
		assert.Equal(t, 16, getMaxGatewaysPerRegion(c))
	}
	{
		c := fakeClusterConfig("100.64.0.0/10", "", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 6, 8)
		assert.Equal(t, 256, getMaxGatewaysPerRegion(c))
	}
	{
		c := fakeClusterConfig("", "fd00::/64", corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY, 4, 4)
		assert.Equal(t, maxGatewaysPerRegionV6, getMaxGatewaysPerRegion(c))
	}
}

func TestGetGatewayIndexLockKey(t *testing.T) {
	ref1 := &metav1.ObjectReference{Uid: "uid-1", Name: "region-1"}
	ref2 := &metav1.ObjectReference{Uid: "uid-2", Name: "region-2"}

	assert.Equal(t, getGatewayIndexLockKey(ref1), getGatewayIndexLockKey(ref1))
	assert.NotEqual(t, getGatewayIndexLockKey(ref1), getGatewayIndexLockKey(ref2))
	assert.True(t, len(getGatewayIndexLockKey(ref1)) > 0)
}

func TestDurationSeconds(t *testing.T) {
	ret := durationSeconds(30)
	assert.Equal(t, uint32(30), ret.GetSeconds())
}

func TestGetGatewaySetsIndex(t *testing.T) {
	c := fakeClusterConfig("100.64.0.0/10", "fd00::/64", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 4, 4)
	c.Status.Domain = "example.com"
	c.Status.NetworkConfig.Wireguard = &corev1.ClusterConfig_Status_NetworkConfig_Wireguard{
		GatewayPort: 53820,
	}
	c.Status.NetworkConfig.Quicv0 = &corev1.ClusterConfig_Status_NetworkConfig_QUICV0{
		GatewayPort: 8443,
	}

	node := &k8scorev1.Node{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: "node-1",
			UID:  "11111111-1111-1111-1111-111111111111",
		},
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	assert.Nil(t, err)

	regionRef := &metav1.ObjectReference{Uid: "region-uid", Name: "default"}

	gw, err := getGateway(3, []string{"1.2.3.4"}, node, &privateKey, c, 2, regionRef)
	assert.Nil(t, err)

	assert.NotNil(t, gw.Status.Index)
	assert.Equal(t, int32(3), gw.Status.GetIndex())
	assert.Equal(t, "100.64.35.0/24", gw.Status.Cidr.V4)
	assert.Equal(t, "fd00::2:3:0/112", gw.Status.Cidr.V6)

	ret, err := getGatewayIndex(c, gw, 2)
	assert.Nil(t, err)
	assert.Equal(t, 3, ret)
}
