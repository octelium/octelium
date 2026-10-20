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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rlockv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
	assert.Equal(t, fmt.Sprintf("octelium-gw-%s.example.com", gw.Status.Id), gw.Status.Hostname)

	ret, err := getGatewayIndex(c, gw, 2)
	assert.Nil(t, err)
	assert.Equal(t, 3, ret)
}

func TestGetGatewayHostname(t *testing.T) {
	cc := &corev1.ClusterConfig{
		Status: &corev1.ClusterConfig_Status{
			Domain: "example.com",
		},
	}

	assert.Equal(t, "octelium-gw-abcd1234.example.com", getGatewayHostname("abcd1234", cc))
}

func TestDoUpdateGatewayHostname(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	octeliumC := tst.C.OcteliumC

	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	node := &k8scorev1.Node{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: "node-1",
			UID:  "11111111-1111-1111-1111-111111111111",
		},
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	assert.Nil(t, err)

	{
		gw, err := doUpdateGateway(ctx, octeliumC, cc, node, nil, 0, privateKey)
		assert.Nil(t, err)
		assert.Nil(t, gw)
	}

	gwObject, err := getGateway(0, []string{"1.2.3.4"}, node, &privateKey, cc, 0,
		&metav1.ObjectReference{Uid: vutils.UUIDv4(), Name: "default"})
	assert.Nil(t, err)

	gwObject.Status.Hostname = fmt.Sprintf("_gw-%s.%s", gwObject.Status.Id, cc.Status.Domain)

	_, err = octeliumC.CoreC().CreateGateway(ctx, gwObject)
	assert.Nil(t, err)

	gw, err := doUpdateGateway(ctx, octeliumC, cc, node, []string{"5.6.7.8"}, 0, privateKey)
	assert.Nil(t, err)
	assert.Equal(t, gwObject.Status.Id, gw.Status.Id)
	assert.Equal(t,
		fmt.Sprintf("octelium-gw-%s.%s", gwObject.Status.Id, cc.Status.Domain), gw.Status.Hostname)
	assert.Equal(t, []string{"5.6.7.8"}, gw.Status.PublicIPs)

	gw, err = octeliumC.CoreC().GetGateway(ctx, &rmetav1.GetOptions{Name: gwObject.Metadata.Name})
	assert.Nil(t, err)
	assert.Equal(t, getGatewayHostname(gwObject.Status.Id, cc), gw.Status.Hostname)
}

type tstGatewayClient struct {
	octeliumc.ClientInterface
	core  rcorev1.ResourceServiceClient
	utils octeliumc.CoreV1Utils
	lock  rlockv1.MainServiceClient
}

func (c *tstGatewayClient) CoreC() rcorev1.ResourceServiceClient {
	return c.core
}

func (c *tstGatewayClient) CoreV1Utils() octeliumc.CoreV1Utils {
	return c.utils
}

func (c *tstGatewayClient) LockC() rlockv1.MainServiceClient {
	return c.lock
}

type tstGatewayCoreClient struct {
	rcorev1.ResourceServiceClient
	listFn   func(context.Context, *rmetav1.ListOptions) (*corev1.GatewayList, error)
	getFn    func(context.Context, *rmetav1.GetOptions) (*corev1.Gateway, error)
	updateFn func(context.Context, *corev1.Gateway) (*corev1.Gateway, error)
	createFn func(context.Context, *corev1.Gateway) (*corev1.Gateway, error)
}

func (c *tstGatewayCoreClient) ListGateway(ctx context.Context, opts *rmetav1.ListOptions,
	_ ...grpc.CallOption) (*corev1.GatewayList, error) {
	return c.listFn(ctx, opts)
}

func (c *tstGatewayCoreClient) GetGateway(ctx context.Context, opts *rmetav1.GetOptions,
	_ ...grpc.CallOption) (*corev1.Gateway, error) {
	return c.getFn(ctx, opts)
}

func (c *tstGatewayCoreClient) UpdateGateway(ctx context.Context, gw *corev1.Gateway,
	_ ...grpc.CallOption) (*corev1.Gateway, error) {
	return c.updateFn(ctx, gw)
}

func (c *tstGatewayCoreClient) CreateGateway(ctx context.Context, gw *corev1.Gateway,
	_ ...grpc.CallOption) (*corev1.Gateway, error) {
	return c.createFn(ctx, gw)
}

func TestGetAvailableGatewayIndex(t *testing.T) {
	cc := fakeClusterConfig("100.64.0.0/16", "fdee::/80",
		corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 1, 2)
	regionRef := &metav1.ObjectReference{Name: "region-1", Uid: vutils.UUIDv4()}

	newGateway := func(index *int32, v4, v6 string) *corev1.Gateway {
		return &corev1.Gateway{
			Metadata: &metav1.Metadata{Name: "gateway"},
			Status: &corev1.Gateway_Status{
				Index: index,
				Cidr:  &metav1.DualStackNetwork{V4: v4, V6: v6},
			},
		}
	}

	for _, tc := range []struct {
		name     string
		items    []*corev1.Gateway
		expected int
		listErr  error
		err      bool
	}{
		{name: "empty"},
		{name: "missingStatus", items: []*corev1.Gateway{{}}},
		{name: "explicitIndexes", items: []*corev1.Gateway{
			newGateway(new(int32(0)), "", ""), newGateway(new(int32(2)), "", ""),
		}, expected: 1},
		{name: "legacyV4", items: []*corev1.Gateway{
			newGateway(nil, "100.64.4.0/24", ""),
		}, expected: 1},
		{name: "legacyV6", items: []*corev1.Gateway{
			newGateway(nil, "", "fdee::1:0:0/112"),
		}, expected: 1},
		{name: "conflictingV4", items: []*corev1.Gateway{
			newGateway(new(int32(2)), "100.64.4.0/24", ""),
		}, expected: 1},
		{name: "conflictingV6", items: []*corev1.Gateway{
			newGateway(new(int32(2)), "", "fdee::1:0:0/112"),
		}, expected: 1},
		{name: "unresolvableIndex", items: []*corev1.Gateway{
			newGateway(nil, "invalid", ""),
		}},
		{name: "missingCIDR", items: []*corev1.Gateway{
			{Metadata: &metav1.Metadata{Name: "gateway"},
				Status: &corev1.Gateway_Status{Index: new(int32(0))}},
		}, expected: 1},
		{name: "exhausted", items: []*corev1.Gateway{
			newGateway(new(int32(0)), "", ""), newGateway(new(int32(1)), "", ""),
			newGateway(new(int32(2)), "", ""), newGateway(new(int32(3)), "", ""),
		}, err: true},
		{name: "listError", listErr: status.Error(codes.Unavailable, "unavailable"), err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &tstGatewayClient{core: &tstGatewayCoreClient{
				listFn: func(ctx context.Context, opts *rmetav1.ListOptions) (*corev1.GatewayList, error) {
					require.Len(t, opts.Filters, 1)
					assert.Contains(t, opts.Filters[0].String(), "status.regionRef.uid")
					assert.Contains(t, opts.Filters[0].String(), regionRef.Uid)
					return &corev1.GatewayList{Items: tc.items}, tc.listErr
				},
			}}
			idx, err := getAvailableGatewayIndex(t.Context(), client, cc, 1, regionRef)
			if tc.err {
				assert.NotNil(t, err)
				if tc.listErr != nil {
					assert.ErrorIs(t, err, tc.listErr)
				}
				return
			}
			require.Nil(t, err)
			assert.Equal(t, tc.expected, idx)
		})
	}

	t.Run("invalidSubnet", func(t *testing.T) {
		client := &tstGatewayClient{core: &tstGatewayCoreClient{
			listFn: func(context.Context, *rmetav1.ListOptions) (*corev1.GatewayList, error) {
				return &corev1.GatewayList{}, nil
			},
		}}
		cc := fakeClusterConfig("invalid", "", corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY, 1, 2)
		_, err := getAvailableGatewayIndex(t.Context(), client, cc, 0, regionRef)
		assert.NotNil(t, err)
	})
}

func TestGetGateway(t *testing.T) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	regionRef := &metav1.ObjectReference{Name: "region-1", Uid: vutils.UUIDv4()}
	node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "node-1", UID: "node-uid"}}

	for _, mode := range []corev1.ClusterConfig_Status_NetworkConfig_Mode{
		corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK,
		corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY,
		corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			cc := fakeClusterConfig("100.64.0.0/16", "fdee::/80", mode, 1, 2)
			cc.Status.Domain = "example.com"
			before := time.Now()
			gw, err := getGateway(2, []string{"1.2.3.4", "2001:4860::1"}, node,
				&privateKey, cc, 1, regionRef)
			require.Nil(t, err)
			assert.Equal(t, k8sutils.GetGatewayName(node), gw.Metadata.Name)
			assert.Equal(t, regionRef, gw.Status.RegionRef)
			assert.True(t, pbutils.IsEqual(&metav1.ObjectReference{
				ApiVersion: "k8s/core/v1", Kind: "Node", Name: node.Name, Uid: string(node.UID),
			}, gw.Status.NodeRef))
			assert.Equal(t, int32(2), gw.Status.GetIndex())
			assert.Len(t, gw.Status.Id, 8)
			assert.Equal(t, getGatewayHostname(gw.Status.Id, cc), gw.Status.Hostname)
			assert.Equal(t, []string{"1.2.3.4", "2001:4860::1"}, gw.Status.PublicIPs)
			assert.Equal(t, privateKey.PublicKey().String(), gw.Status.Wireguard.PublicKey)
			assert.False(t, gw.Status.Wireguard.KeyRotatedAt.AsTime().Before(before))
			assert.True(t, gw.Status.Wireguard.Port > 0)
			assert.True(t, gw.Status.Quicv0.Port > 0)
			if mode != corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY {
				assert.Equal(t, "100.64.6.0/24", gw.Status.Cidr.V4)
			} else {
				assert.Empty(t, gw.Status.Cidr.V4)
			}
			if mode != corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY {
				assert.Equal(t, "fdee::1:2:0/112", gw.Status.Cidr.V6)
			} else {
				assert.Empty(t, gw.Status.Cidr.V6)
			}
		})
	}

	cc := fakeClusterConfig("invalid", "", corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY, 1, 2)
	gw, err := getGateway(0, nil, node, &privateKey, cc, 0, regionRef)
	assert.NotNil(t, err)
	assert.Nil(t, gw)
}

func TestCNI(t *testing.T) {
	for _, mode := range []corev1.ClusterConfig_Status_NetworkConfig_Mode{
		corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK,
		corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY,
		corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv(vutils.MultusConfDirEnv, dir)
			cc := fakeClusterConfig("100.64.0.0/16", "fdee::/80", mode, 1, 2)
			cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
				V4: "100.64.0.0/10", V6: "fdee::/64",
			}
			gw := &corev1.Gateway{Status: &corev1.Gateway_Status{
				Cidr: &metav1.DualStackNetwork{V4: "100.64.4.0/24", V6: "fdee::1:0:0/112"},
			}}
			require.Nil(t, addCNI(gw, cc))
			assert.Equal(t, filepath.Join(dir, "octelium.conf"), getCNIConfPath())
			buf, err := os.ReadFile(getCNIConfPath())
			require.Nil(t, err)
			var conf struct {
				CNIVersion string `json:"cniVersion"`
				Type       string `json:"type"`
				Bridge     string `json:"bridge"`
				IsGateway  bool   `json:"isGateway"`
				IPAM       struct {
					Type   string              `json:"type"`
					Routes []map[string]string `json:"routes"`
					Ranges [][]struct {
						Subnet     string `json:"subnet"`
						RangeStart string `json:"rangeStart"`
					} `json:"ranges"`
				} `json:"ipam"`
			}
			require.Nil(t, json.Unmarshal(buf, &conf))
			assert.Equal(t, "1.0.0", conf.CNIVersion)
			assert.Equal(t, "bridge", conf.Type)
			assert.Equal(t, "octelium-bridge", conf.Bridge)
			assert.True(t, conf.IsGateway)
			assert.Equal(t, "host-local", conf.IPAM.Type)
			expected := 1
			if mode == corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK {
				expected = 2
			}
			require.Len(t, conf.IPAM.Routes, expected)
			require.Len(t, conf.IPAM.Ranges, expected)
			idx := 0
			if mode != corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY {
				assert.Equal(t, "100.64.0.0/10", conf.IPAM.Routes[0]["dst"])
				require.Len(t, conf.IPAM.Ranges[0], 1)
				assert.Equal(t, gw.Status.Cidr.V4, conf.IPAM.Ranges[0][0].Subnet)
				assert.Equal(t, "100.64.4.16", conf.IPAM.Ranges[0][0].RangeStart)
				idx++
			}
			if mode != corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY {
				assert.Equal(t, "fdee::/64", conf.IPAM.Routes[idx]["dst"])
				require.Len(t, conf.IPAM.Ranges[idx], 1)
				assert.Equal(t, gw.Status.Cidr.V6, conf.IPAM.Ranges[idx][0].Subnet)
				assert.Equal(t, "fdee::1:0:10", conf.IPAM.Ranges[idx][0].RangeStart)
			}
			require.Nil(t, deleteCNI(nil))
			_, err = os.Stat(getCNIConfPath())
			assert.True(t, os.IsNotExist(err))
			assert.NotNil(t, deleteCNI(nil))
		})
	}

	t.Run("errors", func(t *testing.T) {
		t.Setenv(vutils.MultusConfDirEnv, filepath.Join(t.TempDir(), "missing"))
		gw := &corev1.Gateway{Status: &corev1.Gateway_Status{
			Cidr: &metav1.DualStackNetwork{V4: "100.64.4.0/24"},
		}}
		for _, cc := range []*corev1.ClusterConfig{
			{}, {Status: &corev1.ClusterConfig_Status{}},
			{Status: &corev1.ClusterConfig_Status{Network: &corev1.ClusterConfig_Status_Network{}}},
		} {
			assert.NotNil(t, addCNI(gw, cc))
		}
		cc := fakeClusterConfig("100.64.0.0/16", "", corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY, 1, 2)
		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{V4: "100.64.0.0/10"}
		assert.NotNil(t, addCNI(gw, cc))
		gw.Status.Cidr.V4 = "invalid"
		assert.NotNil(t, addCNI(gw, cc))
	})

	t.Run("defaultPath", func(t *testing.T) {
		t.Setenv(vutils.MultusConfDirEnv, "")
		assert.Equal(t, filepath.Join(vutils.MultusConfDirDefault, "octelium.conf"), getCNIConfPath())
	})
}

func TestInitGateway(t *testing.T) {
	ctx := t.Context()
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	t.Setenv(vutils.MultusConfDirEnv, t.TempDir())
	client := tst.C.OcteliumC
	regionRef := &metav1.ObjectReference{Name: "default", Uid: vutils.UUIDv4()}

	var previous *corev1.Gateway
	for i := range 3 {
		node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{
			Name: fmt.Sprintf("node-%d", i), UID: types.UID("node-uid-" + fmt.Sprint(i)),
		}}
		privateKey, err := wgtypes.GeneratePrivateKey()
		require.Nil(t, err)
		require.Nil(t, InitGateway(ctx, []string{"1.2.3.4"}, node, client, 0, regionRef, privateKey))
		gw, err := client.CoreC().GetGateway(ctx, &rmetav1.GetOptions{Name: k8sutils.GetGatewayName(node)})
		require.Nil(t, err)
		assert.Equal(t, int32(i), gw.Status.GetIndex())
		if previous != nil {
			assert.NotEqual(t, previous.Status.Cidr.V4, gw.Status.Cidr.V4)
			assert.NotEqual(t, previous.Status.Cidr.V6, gw.Status.Cidr.V6)
			assert.NotEqual(t, previous.Status.Id, gw.Status.Id)
		}
		previous = gw

		rotatedKey, err := wgtypes.GeneratePrivateKey()
		require.Nil(t, err)
		require.Nil(t, InitGateway(ctx, []string{"5.6.7.8"}, node, client, 0, regionRef, rotatedKey))
		updated, err := client.CoreC().GetGateway(ctx, &rmetav1.GetOptions{Name: gw.Metadata.Name})
		require.Nil(t, err)
		assert.Equal(t, gw.Metadata.Uid, updated.Metadata.Uid)
		assert.Equal(t, gw.Status.Id, updated.Status.Id)
		assert.True(t, pbutils.IsEqual(gw.Status.Cidr, updated.Status.Cidr))
		assert.Equal(t, gw.Status.GetIndex(), updated.Status.GetIndex())
		assert.Equal(t, rotatedKey.PublicKey().String(), updated.Status.Wireguard.PublicKey)
		assert.Equal(t, []string{"5.6.7.8"}, updated.Status.PublicIPs)
	}
}

func TestDoUpdateGateway(t *testing.T) {
	cc := fakeClusterConfig("100.64.0.0/16", "fdee::/80", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 1, 2)
	cc.Status.Domain = "example.com"
	key, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "node-1", UID: "node-uid"}}
	for _, name := range []string{"legacyV4", "legacyV6", "invalidCIDR", "missingID", "getError", "updateError"} {
		t.Run(name, func(t *testing.T) {
			gw, err := getGateway(2, []string{"1.2.3.4"}, node, &key, cc, 1,
				&metav1.ObjectReference{Name: "region-1", Uid: vutils.UUIDv4()})
			require.Nil(t, err)
			gw.Status.Index = nil
			gw.Status.Wireguard = nil
			gw.Status.Hostname = "legacy.example.com"
			switch name {
			case "legacyV6":
				gw.Status.Cidr.V4 = ""
			case "invalidCIDR":
				gw.Status.Cidr.V4 = "invalid"
			case "missingID":
				gw.Status.Id = ""
			}
			expected := fmt.Errorf("backend unavailable")
			client := &tstGatewayClient{core: &tstGatewayCoreClient{
				getFn: func(ctx context.Context, opts *rmetav1.GetOptions) (*corev1.Gateway, error) {
					assert.Equal(t, k8sutils.GetGatewayName(node), opts.Name)
					if name == "getError" {
						return nil, expected
					}
					return gw, nil
				},
				updateFn: func(ctx context.Context, updated *corev1.Gateway) (*corev1.Gateway, error) {
					assert.Same(t, gw, updated)
					if name == "updateError" {
						return nil, expected
					}
					return updated, nil
				},
			}}
			updated, err := doUpdateGateway(t.Context(), client, cc, node, nil, 1, key)
			if name == "getError" || name == "updateError" {
				assert.ErrorIs(t, err, expected)
				assert.Nil(t, updated)
				return
			}
			require.Nil(t, err)
			assert.Equal(t, []string{"1.2.3.4"}, updated.Status.PublicIPs)
			assert.Equal(t, key.PublicKey().String(), updated.Status.Wireguard.PublicKey)
			if name == "invalidCIDR" {
				assert.Nil(t, updated.Status.Index)
			} else {
				assert.Equal(t, int32(2), updated.Status.GetIndex())
			}
			if name == "missingID" {
				assert.Equal(t, "legacy.example.com", updated.Status.Hostname)
			} else {
				assert.Equal(t, getGatewayHostname(gw.Status.Id, cc), updated.Status.Hostname)
			}
		})
	}
}

type tstGatewayUtils struct {
	cc  *corev1.ClusterConfig
	err error
}

func (c *tstGatewayUtils) GetClusterConfig(context.Context) (*corev1.ClusterConfig, error) {
	return c.cc, c.err
}

type tstGatewayLockClient struct {
	rlockv1.MainServiceClient
	lockFn   func(*rlockv1.LockRequest) (*rlockv1.LockResponse, error)
	unlockFn func(context.Context, *rlockv1.UnlockRequest) (*rlockv1.UnlockResponse, error)
}

func (c *tstGatewayLockClient) Lock(ctx context.Context, req *rlockv1.LockRequest,
	_ ...grpc.CallOption) (*rlockv1.LockResponse, error) {
	return c.lockFn(req)
}

func (c *tstGatewayLockClient) Unlock(ctx context.Context, req *rlockv1.UnlockRequest,
	_ ...grpc.CallOption) (*rlockv1.UnlockResponse, error) {
	return c.unlockFn(ctx, req)
}

func TestInitGatewayErrors(t *testing.T) {
	cc := fakeClusterConfig("100.64.0.0/16", "fdee::/80", corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK, 1, 2)
	cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{V4: "100.64.0.0/10", V6: "fdee::/64"}
	key, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "node-1", UID: "node-uid"}}
	regionRef := &metav1.ObjectReference{Name: "region-1", Uid: vutils.UUIDv4()}
	for _, name := range []string{
		"clusterConfig", "get", "lock", "lockNotAcquired", "getAfterLock", "list", "create", "CNI", "createdAfterLock", "unlock",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(vutils.MultusConfDirEnv, t.TempDir())
			if name == "CNI" {
				t.Setenv(vutils.MultusConfDirEnv, filepath.Join(t.TempDir(), "missing"))
			}
			expected := fmt.Errorf("backend unavailable")
			gets, locks, unlocks := 0, 0, 0
			core := &tstGatewayCoreClient{
				getFn: func(ctx context.Context, opts *rmetav1.GetOptions) (*corev1.Gateway, error) {
					gets++
					if name == "get" || name == "getAfterLock" && gets == 2 {
						return nil, expected
					}
					if name == "createdAfterLock" && gets == 2 {
						return getGateway(0, []string{"1.2.3.4"}, node, &key, cc, 0, regionRef)
					}
					return nil, status.Error(codes.NotFound, "not found")
				},
				listFn: func(context.Context, *rmetav1.ListOptions) (*corev1.GatewayList, error) {
					if name == "list" {
						return nil, expected
					}
					return &corev1.GatewayList{}, nil
				},
				createFn: func(ctx context.Context, gw *corev1.Gateway) (*corev1.Gateway, error) {
					if name == "create" {
						return nil, expected
					}
					return gw, nil
				},
				updateFn: func(ctx context.Context, gw *corev1.Gateway) (*corev1.Gateway, error) {
					return gw, nil
				},
			}
			utils := &tstGatewayUtils{cc: cc}
			if name == "clusterConfig" {
				utils.err = expected
			}
			client := &tstGatewayClient{core: core, utils: utils, lock: &tstGatewayLockClient{
				lockFn: func(req *rlockv1.LockRequest) (*rlockv1.LockResponse, error) {
					locks++
					assert.Equal(t, getGatewayIndexLockKey(regionRef), req.Key)
					assert.True(t, pbutils.IsEqual(durationSeconds(60), req.Ttl))
					assert.True(t, pbutils.IsEqual(durationSeconds(15), req.Wait))
					if name == "lock" {
						return nil, expected
					}
					return &rlockv1.LockResponse{Acquired: name != "lockNotAcquired", LeaseID: []byte("lease")}, nil
				},
				unlockFn: func(ctx context.Context, req *rlockv1.UnlockRequest) (*rlockv1.UnlockResponse, error) {
					unlocks++
					assert.Nil(t, ctx.Err())
					assert.Equal(t, getGatewayIndexLockKey(regionRef), req.Key)
					assert.Equal(t, []byte("lease"), req.LeaseID)
					return &rlockv1.UnlockResponse{}, expected
				},
			}}
			err := InitGateway(t.Context(), []string{"1.2.3.4"}, node, client, 0, regionRef, key)
			if name == "createdAfterLock" || name == "unlock" {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
			switch name {
			case "clusterConfig", "get":
				assert.Zero(t, locks)
				assert.Zero(t, unlocks)
			case "lock", "lockNotAcquired":
				assert.Equal(t, 1, locks)
				assert.Zero(t, unlocks)
			default:
				assert.Equal(t, 1, locks)
				assert.Equal(t, 1, unlocks)
			}
		})
	}
}
