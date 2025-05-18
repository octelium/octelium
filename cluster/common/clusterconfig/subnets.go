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
	"encoding/hex"
	"net"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
)

func SetClusterSubnets(clusterCfg *corev1.ClusterConfig) error {

	if clusterCfg.Status.Network == nil {
		clusterCfg.Status.Network = &corev1.ClusterConfig_Status_Network{}
	}
	if clusterCfg.Status.Network.ClusterNetwork == nil {
		clusterCfg.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{}
	}

	setClusterNetworkV4(clusterCfg)
	setClusterNetworkV6(clusterCfg)

	setServiceSubnet(clusterCfg)
	setWgConnectionSubnet(clusterCfg)
	setQUICConnectionSubnet(clusterCfg)

	return nil
}

func setClusterNetworkV4(c *corev1.ClusterConfig) {
	if c.Status.NetworkConfig == nil || c.Status.NetworkConfig.V4 == nil || c.Status.NetworkConfig.V4.ClusterNetwork == "" {
		c.Status.Network.ClusterNetwork.V4 = "100.64.0.0/10"
	} else {
		c.Status.Network.ClusterNetwork.V4 = c.Status.NetworkConfig.V4.ClusterNetwork
	}

}

func setClusterNetworkV6(clusterCfg *corev1.ClusterConfig) {
	ret := &net.IPNet{
		IP:   make([]byte, 16),
		Mask: net.CIDRMask(64, 128),
	}

	prefix, _ := hex.DecodeString("fdee")

	ret.IP[0] = prefix[0]
	ret.IP[1] = prefix[1]

	v6RangePrefix := func() []byte {
		if clusterCfg.Status.Network == nil || clusterCfg.Status.Network.V6RangePrefix == nil || len(clusterCfg.Status.Network.V6RangePrefix) < 4 {
			return make([]byte, 4)
		}
		return clusterCfg.Status.Network.V6RangePrefix
	}()

	ret.IP[2] = v6RangePrefix[0]
	ret.IP[3] = v6RangePrefix[1]
	ret.IP[4] = v6RangePrefix[2]
	ret.IP[5] = v6RangePrefix[3]

	clusterCfg.Status.Network.ClusterNetwork.V6 = ret.String()
}

func setServiceSubnet(c *corev1.ClusterConfig) {
	c.Status.Network.ServiceSubnet = &metav1.DualStackNetwork{}
	if c.Status.Network.ClusterNetwork.V4 != "" {
		_, netw, _ := net.ParseCIDR(c.Status.Network.ClusterNetwork.V4)

		svcSubnet := &net.IPNet{
			IP:   netw.IP,
			Mask: net.CIDRMask(16, 32),
		}

		c.Status.Network.ServiceSubnet.V4 = svcSubnet.String()
	}

	if c.Status.Network.ClusterNetwork.V6 != "" {
		_, netw, _ := net.ParseCIDR(c.Status.Network.ClusterNetwork.V6)

		svcSubnet := &net.IPNet{
			IP:   netw.IP,
			Mask: net.CIDRMask(80, 128),
		}

		c.Status.Network.ServiceSubnet.V6 = svcSubnet.String()
	}
}

func setWgConnectionSubnet(c *corev1.ClusterConfig) {
	c.Status.Network.WgConnSubnet = &metav1.DualStackNetwork{}
	if c.Status.Network.ClusterNetwork.V4 != "" {
		_, netw, _ := net.ParseCIDR(c.Status.Network.ClusterNetwork.V4)

		ipv4 := netw.IP.To4()

		connSubnet := &net.IPNet{
			IP:   net.IPv4(ipv4[0], ipv4[1]+byte(1), 0, 0),
			Mask: net.CIDRMask(16, 32),
		}

		c.Status.Network.WgConnSubnet.V4 = connSubnet.String()
	}

	if c.Status.Network.ClusterNetwork.V6 != "" {
		_, netw, _ := net.ParseCIDR(c.Status.Network.ClusterNetwork.V6)
		ipv6 := netw.IP.To16()
		ipv6[9] = byte(1)
		connSubnet := &net.IPNet{
			IP:   ipv6,
			Mask: net.CIDRMask(80, 128),
		}

		c.Status.Network.WgConnSubnet.V6 = connSubnet.String()
	}
}

func setQUICConnectionSubnet(c *corev1.ClusterConfig) {
	c.Status.Network.QuicConnSubnet = &metav1.DualStackNetwork{}
	if c.Status.Network.ClusterNetwork.V4 != "" {
		_, netw, _ := net.ParseCIDR(c.Status.Network.ClusterNetwork.V4)

		ipv4 := netw.IP.To4()

		connSubnet := &net.IPNet{
			IP:   net.IPv4(ipv4[0], ipv4[1]+byte(2), 0, 0),
			Mask: net.CIDRMask(16, 32),
		}

		c.Status.Network.QuicConnSubnet.V4 = connSubnet.String()
	}

	if c.Status.Network.ClusterNetwork.V6 != "" {
		_, netw, _ := net.ParseCIDR(c.Status.Network.ClusterNetwork.V6)
		ipv6 := netw.IP.To16()
		ipv6[9] = byte(2)
		connSubnet := &net.IPNet{
			IP:   ipv6,
			Mask: net.CIDRMask(80, 128),
		}

		c.Status.Network.QuicConnSubnet.V6 = connSubnet.String()
	}
}
