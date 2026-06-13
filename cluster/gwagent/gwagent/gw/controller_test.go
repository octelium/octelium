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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
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
