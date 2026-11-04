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
	"encoding/binary"
	"net/netip"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

func SetClusterSubnets(clusterCfg *corev1.ClusterConfig) error {
	if clusterCfg == nil || clusterCfg.Status == nil {
		return errors.Errorf("ClusterConfig status is required")
	}
	network := clusterCfg.Status.Network
	allocated := false
	for _, ranges := range [][]string{
		{network.GetClusterNetwork().GetV4(), network.GetServiceSubnet().GetV4(), network.GetWgConnSubnet().GetV4(), network.GetQuicConnSubnet().GetV4()},
		{network.GetClusterNetwork().GetV6(), network.GetServiceSubnet().GetV6(), network.GetWgConnSubnet().GetV6(), network.GetQuicConnSubnet().GetV6()},
	} {
		count := 0
		for _, value := range ranges {
			if value != "" {
				count++
			}
		}
		if count != 0 && count != len(ranges) {
			return errors.Errorf("Cannot replace partially allocated Cluster network ranges")
		}
		allocated = allocated || count != 0
	}
	if allocated {
		return nil
	}
	if err := validateNetworkConfig(clusterCfg); err != nil {
		return err
	}

	cidr := clusterCfg.Status.GetNetworkConfig().GetV4().GetClusterNetwork()
	if cidr == "" {
		cidr = "100.64.0.0/10"
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return errors.Errorf("network.v4.clusterNetwork must be a valid IPv4 CIDR: %q", cidr)
	}
	if prefix != prefix.Masked() {
		return errors.Errorf("network.v4.clusterNetwork must be a network address: use %s", prefix.Masked())
	}
	if prefix.Bits() > 14 {
		return errors.Errorf("network.v4.clusterNetwork must be /14 or broader to contain three /16 subnets")
	}

	if network == nil {
		network = &corev1.ClusterConfig_Status_Network{}
	} else {
		network = proto.Clone(network).(*corev1.ClusterConfig_Status_Network)
	}
	v6 := [16]byte{0xfd, 0xee}
	if len(network.V6RangePrefix) >= 4 {
		copy(v6[2:6], network.V6RangePrefix[:4])
	}
	network.ClusterNetwork = &metav1.DualStackNetwork{
		V4: prefix.String(), V6: netip.PrefixFrom(netip.AddrFrom16(v6), 64).String(),
	}
	v4 := prefix.Addr().As4()
	base := uint64(binary.BigEndian.Uint32(v4[:]))
	for index, target := range []**metav1.DualStackNetwork{&network.ServiceSubnet, &network.WgConnSubnet, &network.QuicConnSubnet} {
		offset := base + (uint64(index) << 16)
		if offset >= 1<<32 {
			return errors.Errorf("Cluster subnet allocation overflows IPv4")
		}
		binary.BigEndian.PutUint32(v4[:], uint32(offset))
		addr := netip.AddrFrom4(v4)
		if !prefix.Contains(addr) {
			return errors.Errorf("Cluster subnet allocation exceeds network.v4.clusterNetwork")
		}
		v6[9] = byte(index)
		*target = &metav1.DualStackNetwork{
			V4: netip.PrefixFrom(addr, 16).String(), V6: netip.PrefixFrom(netip.AddrFrom16(v6), 80).String(),
		}
	}
	clusterCfg.Status.Network = network
	return nil
}

func validateNetworkConfig(c *corev1.ClusterConfig) error {
	config := c.Status.NetworkConfig
	switch config.GetMode() {
	case corev1.ClusterConfig_Status_NetworkConfig_MODE_DEFAULT, corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK,
		corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY, corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY:
	default:
		return errors.Errorf("Unsupported network.mode: %d", config.GetMode())
	}
	if ucorev1.ToClusterConfig(c).HasV4() {
		regionBits, gatewayBits := uint64(config.GetV4().GetRegionBits()), uint64(config.GetV4().GetGatewayBits())
		if regionBits == 0 {
			regionBits = 4
		}
		if gatewayBits == 0 {
			gatewayBits = 4
		}
		if regionBits+gatewayBits > 8 {
			return errors.Errorf("network.v4.regionBits and gatewayBits, including defaults of 4, must total at most 8 for the /16 Service subnet")
		}
	}

	minimumMTU := uint32(576)
	if ucorev1.ToClusterConfig(c).HasV6() {
		minimumMTU = 1280
	}
	for _, transport := range []struct {
		name      string
		port, mtu uint32
	}{
		{"wireguard", config.GetWireguard().GetGatewayPort(), config.GetWireguard().GetMtu()},
		{"quicv0", config.GetQuicv0().GetGatewayPort(), config.GetQuicv0().GetMtu()},
	} {
		if transport.port > 65535 {
			return errors.Errorf("network.%s.gatewayPort must be between 1 and 65535, or 0 for the default", transport.name)
		}
		if transport.mtu != 0 && (transport.mtu < minimumMTU || transport.mtu > 65535) {
			return errors.Errorf("network.%s.mtu must be between %d and 65535, or 0 for the default", transport.name, minimumMTU)
		}
	}
	if config.GetQuicv0().GetEnable() && ucorev1.ToClusterConfig(c).GetGatewayPortWireGuard() == ucorev1.ToClusterConfig(c).GetGatewayPortQUICv0() {
		return errors.Errorf("network.wireguard.gatewayPort and network.quicv0.gatewayPort must differ when QUICv0 is enabled")
	}
	return nil
}
