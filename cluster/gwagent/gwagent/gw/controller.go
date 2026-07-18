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
	"fmt"
	"math/big"
	"net"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rlockv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	k8scorev1 "k8s.io/api/core/v1"
)

const (
	gatewayIndexLockTTLSeconds  = 60
	gatewayIndexLockWaitSeconds = 15

	maxGatewaysPerRegionV6 = 65536
)

func getGatewayIndexLockKey(regionRef *metav1.ObjectReference) []byte {
	return []byte(fmt.Sprintf("gateway-index:%s", regionRef.Uid))
}

func durationSeconds(n uint32) *metav1.Duration {
	return &metav1.Duration{
		Type: &metav1.Duration_Seconds{
			Seconds: n,
		},
	}
}

func InitGateway(ctx context.Context,
	publicIPs []string,
	node *k8scorev1.Node,

	octeliumC octeliumc.ClientInterface,
	regionIdx int, regionRef *metav1.ObjectReference, privateKey wgtypes.Key) error {

	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	{
		gw, err := doUpdateGateway(ctx, octeliumC, cc, node, publicIPs, regionIdx, privateKey)
		if err != nil {
			return err
		}
		if gw != nil {
			return addCNI(gw, cc)
		}
	}

	lockKey := getGatewayIndexLockKey(regionRef)

	lockRes, err := octeliumC.LockC().Lock(ctx, &rlockv1.LockRequest{
		Key:  lockKey,
		Ttl:  durationSeconds(gatewayIndexLockTTLSeconds),
		Wait: durationSeconds(gatewayIndexLockWaitSeconds),
	})
	if err != nil {
		return errors.Errorf("Could not acquire the Gateway index lock: %+v", err)
	}
	if !lockRes.Acquired {
		return errors.Errorf("Could not acquire the Gateway index lock for the Region: %s", regionRef.Name)
	}

	defer func() {
		if _, err := octeliumC.LockC().Unlock(context.Background(), &rlockv1.UnlockRequest{
			Key:     lockKey,
			LeaseID: lockRes.LeaseID,
		}); err != nil {
			zap.L().Warn("Could not release the Gateway index lock", zap.Error(err))
		}
	}()

	zap.L().Debug("Acquired the Gateway index lock", zap.String("region", regionRef.Name))

	{
		gw, err := doUpdateGateway(ctx, octeliumC, cc, node, publicIPs, regionIdx, privateKey)
		if err != nil {
			return err
		}
		if gw != nil {
			return addCNI(gw, cc)
		}
	}

	nodeIdx, err := getAvailableGatewayIndex(ctx, octeliumC, cc, regionIdx, regionRef)
	if err != nil {
		return err
	}

	zap.L().Debug("Found an available Gateway index",
		zap.Int("index", nodeIdx), zap.String("node", node.Name))

	gwObject, err := getGateway(nodeIdx, publicIPs, node, &privateKey, cc, regionIdx, regionRef)
	if err != nil {
		return errors.Errorf("Could not create gw for node: %s: %+v", node.Name, err)
	}

	gw, err := octeliumC.CoreC().CreateGateway(ctx, gwObject)
	if err != nil {
		return err
	}

	if err := addCNI(gw, cc); err != nil {
		return err
	}

	return nil
}

func doUpdateGateway(ctx context.Context,
	octeliumC octeliumc.ClientInterface,
	cc *corev1.ClusterConfig,
	node *k8scorev1.Node,
	publicIPs []string,
	regionIdx int,
	privateKey wgtypes.Key) (*corev1.Gateway, error) {

	gw, err := octeliumC.CoreC().GetGateway(ctx, &rmetav1.GetOptions{Name: k8sutils.GetGatewayName(node)})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	zap.L().Debug("Gateway already exists. Just updating the WG public key and public IP addrs",
		zap.Any("gw", gw), zap.Strings("publicIPs", publicIPs))

	if gw.Status.Wireguard == nil {
		gw.Status.Wireguard = &corev1.Gateway_Status_WireGuard{}
	}
	gw.Status.Wireguard.PublicKey = privateKey.PublicKey().String()
	gw.Status.Wireguard.KeyRotatedAt = pbutils.Now()

	if len(publicIPs) > 0 {
		gw.Status.PublicIPs = publicIPs
	}

	if gw.Status.Index == nil {
		nodeIdx, err := inferGatewayIndexFromCIDR(cc, gw.Status.Cidr, regionIdx)
		if err != nil {
			zap.L().Warn("Could not infer the Gateway index from its CIDR",
				zap.String("gw", gw.Metadata.Name), zap.Error(err))
		} else {
			zap.L().Debug("Backfilling the Gateway index",
				zap.String("gw", gw.Metadata.Name), zap.Int("index", nodeIdx))
			gw.Status.Index = new(int32(nodeIdx))
		}
	}

	gw, err = octeliumC.CoreC().UpdateGateway(ctx, gw)
	if err != nil {
		return nil, err
	}

	return gw, nil
}

func getGatewayIndex(cc *corev1.ClusterConfig, gw *corev1.Gateway, regionIdx int) (int, error) {
	if gw.Status == nil {
		return 0, errors.Errorf("Gateway has no status")
	}

	if gw.Status.Index != nil {
		return int(gw.Status.GetIndex()), nil
	}

	return inferGatewayIndexFromCIDR(cc, gw.Status.Cidr, regionIdx)
}

func inferGatewayIndexFromCIDR(cc *corev1.ClusterConfig,
	cidr *metav1.DualStackNetwork, regionIdx int) (int, error) {

	if cidr == nil {
		return 0, errors.Errorf("Gateway has no CIDR")
	}

	if cidr.V4 != "" {
		return inferGatewayIndexV4(cc, cidr.V4, regionIdx)
	}

	if cidr.V6 != "" {
		return inferGatewayIndexV6(cidr.V6, regionIdx)
	}

	return 0, errors.Errorf("Gateway CIDR has neither a v4 nor a v6 range")
}

func inferGatewayIndexV4(cc *corev1.ClusterConfig, cidrV4 string, regionIdx int) (int, error) {

	serviceSubnet := serviceSubnetV4(cc)
	if serviceSubnet == "" {
		return 0, errors.Errorf("IPv4 Service subnet is empty")
	}

	_, base, err := net.ParseCIDR(serviceSubnet)
	if err != nil {
		return 0, err
	}

	_, sub, err := net.ParseCIDR(cidrV4)
	if err != nil {
		return 0, err
	}

	combinedIdx, err := subnetIndex(base, gatewayPrefixLenV4, sub)
	if err != nil {
		return 0, err
	}

	regionBits, gatewayBits := gatewayAllocationBitsV4(cc)

	gotRegionIdx := combinedIdx >> uint(gatewayBits)
	nodeIdx := combinedIdx & ((uint64(1) << uint(gatewayBits)) - 1)

	if gotRegionIdx >= (uint64(1) << uint(regionBits)) {
		return 0, errors.Errorf("Inferred Region index %d is out of range", gotRegionIdx)
	}

	if gotRegionIdx != uint64(regionIdx) {
		return 0, errors.Errorf(
			"The Gateway CIDR %s belongs to the Region index %d, not %d",
			cidrV4, gotRegionIdx, regionIdx)
	}

	return int(nodeIdx), nil
}

func inferGatewayIndexV6(cidrV6 string, regionIdx int) (int, error) {

	_, sub, err := net.ParseCIDR(cidrV6)
	if err != nil {
		return 0, err
	}

	ones, bits := sub.Mask.Size()
	if bits != 128 {
		return 0, errors.Errorf("The Gateway CIDR %s is not a valid IPv6 range", cidrV6)
	}
	if ones != gatewayPrefixLenV6 {
		return 0, errors.Errorf(
			"The Gateway CIDR %s prefix /%d does not match the Gateway prefix /%d",
			cidrV6, ones, gatewayPrefixLenV6)
	}

	ip := sub.IP.To16()
	if ip == nil {
		return 0, errors.Errorf("The Gateway CIDR %s is not a valid IPv6 range", cidrV6)
	}

	gotRegionIdx := int(ip[10])<<8 | int(ip[11])
	nodeIdx := int(ip[12])<<8 | int(ip[13])

	if gotRegionIdx != regionIdx {
		return 0, errors.Errorf(
			"The Gateway CIDR %s belongs to the Region index %d, not %d",
			cidrV6, gotRegionIdx, regionIdx)
	}

	return nodeIdx, nil
}

func subnetIndex(base *net.IPNet, newPrefix int, sub *net.IPNet) (uint64, error) {
	if base == nil || sub == nil {
		return 0, errors.Errorf("Nil network")
	}

	ones, bits := base.Mask.Size()
	if bits == 0 {
		return 0, errors.Errorf("Invalid base network mask")
	}

	subOnes, subBits := sub.Mask.Size()
	if subBits != bits {
		return 0, errors.Errorf("Address bit width mismatch: %d and %d", bits, subBits)
	}
	if subOnes != newPrefix {
		return 0, errors.Errorf("Subnet prefix /%d does not match the expected prefix /%d", subOnes, newPrefix)
	}
	if newPrefix < ones {
		return 0, errors.Errorf("new prefix /%d is shorter than base prefix /%d", newPrefix, ones)
	}

	var baseIP net.IP
	var subIP net.IP

	switch bits {
	case 32:
		baseIP = base.IP.To4()
		subIP = sub.IP.To4()
	case 128:
		baseIP = base.IP.To16()
		subIP = sub.IP.To16()
	default:
		return 0, errors.Errorf("Unsupported address bit width: %d", bits)
	}

	if baseIP == nil || subIP == nil {
		return 0, errors.Errorf("Invalid network address family")
	}

	baseInt := new(big.Int).SetBytes(baseIP)
	subInt := new(big.Int).SetBytes(subIP)

	if subInt.Cmp(baseInt) < 0 {
		return 0, errors.Errorf("The subnet is outside of the base network")
	}

	offset := new(big.Int).Sub(subInt, baseInt)

	shift := uint(bits - newPrefix)

	idx := new(big.Int).Rsh(offset, shift)

	if new(big.Int).Lsh(idx, shift).Cmp(offset) != 0 {
		return 0, errors.Errorf("The subnet is not aligned to the /%d boundary", newPrefix)
	}

	if !idx.IsUint64() {
		return 0, errors.Errorf("The subnet index is too large")
	}

	return idx.Uint64(), nil
}

func getMaxGatewaysPerRegion(cc *corev1.ClusterConfig) int {
	if ucorev1.ToClusterConfig(cc).HasV4() {
		_, gatewayBits := gatewayAllocationBitsV4(cc)
		return 1 << uint(gatewayBits)
	}

	return maxGatewaysPerRegionV6
}

func getAvailableGatewayIndex(ctx context.Context,
	octeliumC octeliumc.ClientInterface,
	cc *corev1.ClusterConfig,
	regionIdx int, regionRef *metav1.ObjectReference) (int, error) {

	gwList, err := octeliumC.CoreC().ListGateway(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterFieldEQValStr("status.regionRef.uid", regionRef.Uid),
		},
	})
	if err != nil {
		return 0, err
	}

	takenIdx := make(map[int]string)
	takenV4 := make(map[string]string)
	takenV6 := make(map[string]string)

	for _, gw := range gwList.Items {
		if gw.Status == nil {
			continue
		}

		if nodeIdx, err := getGatewayIndex(cc, gw, regionIdx); err == nil {
			takenIdx[nodeIdx] = gw.Metadata.Name
		} else {
			zap.L().Warn("Could not resolve the index of an existing Gateway",
				zap.String("gw", gw.Metadata.Name), zap.Error(err))
		}

		if gw.Status.Cidr == nil {
			continue
		}

		if gw.Status.Cidr.V4 != "" {
			takenV4[gw.Status.Cidr.V4] = gw.Metadata.Name
		}
		if gw.Status.Cidr.V6 != "" {
			takenV6[gw.Status.Cidr.V6] = gw.Metadata.Name
		}
	}

	maxIdx := getMaxGatewaysPerRegion(cc)

	for nodeIdx := 0; nodeIdx < maxIdx; nodeIdx++ {
		if gwName, ok := takenIdx[nodeIdx]; ok {
			zap.L().Debug("Gateway index is already taken",
				zap.Int("index", nodeIdx), zap.String("gw", gwName))
			continue
		}

		gwNet, err := getGatewaySubnet(cc, nodeIdx, regionIdx)
		if err != nil {
			return 0, err
		}

		if gwNet.V4 != nil {
			if gwName, ok := takenV4[gwNet.V4.String()]; ok {
				zap.L().Debug("Gateway v4 CIDR is already taken",
					zap.Int("index", nodeIdx), zap.String("gw", gwName))
				continue
			}
		}

		if gwNet.V6 != nil {
			if gwName, ok := takenV6[gwNet.V6.String()]; ok {
				zap.L().Debug("Gateway v6 CIDR is already taken",
					zap.Int("index", nodeIdx), zap.String("gw", gwName))
				continue
			}
		}

		return nodeIdx, nil
	}

	return 0, errors.Errorf(
		"Could not find an available Gateway index in the Region: %s. All %d indexes are taken",
		regionRef.Name, maxIdx)
}

func getGateway(nodeIdx int, publicIPs []string, node *k8scorev1.Node, privateKey *wgtypes.Key, cc *corev1.ClusterConfig, regionIdx int, regionRef *metav1.ObjectReference) (*corev1.Gateway, error) {

	gwCIDR := &metav1.DualStackNetwork{}

	gwNet, err := getGatewaySubnet(cc, nodeIdx, regionIdx)
	if err != nil {
		return nil, err
	}

	if gwNet.V4 != nil {
		gwCIDR.V4 = gwNet.V4.String()
	}
	if gwNet.V6 != nil {
		gwCIDR.V6 = gwNet.V6.String()
	}

	gwID := utilrand.GetRandomStringCanonical(8)

	ret := &corev1.Gateway{
		Metadata: &metav1.Metadata{
			Name: k8sutils.GetGatewayName(node),
		},

		Spec: &corev1.Gateway_Spec{},

		Status: &corev1.Gateway_Status{
			RegionRef: regionRef,
			NodeRef: &metav1.ObjectReference{
				ApiVersion: "k8s/core/v1",
				Kind:       "Node",
				Name:       node.Name,
				Uid:        string(node.UID),
			},
			Cidr:  gwCIDR,
			Index: new(int32(nodeIdx)),
			Wireguard: &corev1.Gateway_Status_WireGuard{
				PublicKey:    privateKey.PublicKey().String(),
				KeyRotatedAt: pbutils.Now(),
				Port:         int32(ucorev1.ToClusterConfig(cc).GetGatewayPortWireGuard()),
			},
			Quicv0: &corev1.Gateway_Status_QUICV0{
				Port: int32(ucorev1.ToClusterConfig(cc).GetGatewayPortQUICv0()),
			},

			PublicIPs: publicIPs,
			Id:        gwID,
			Hostname:  fmt.Sprintf("_gw-%s.%s", gwID, cc.Status.Domain),
		},
	}

	zap.L().Debug("Created Gateway", zap.Any("gw", ret))

	return ret, nil
}

type subnet struct {
	V4 *net.IPNet
	V6 *net.IPNet
}

const (
	gatewayPrefixLenV4   = 24
	gatewayPrefixLenV6   = 112
	defaultRegionBitsV4  = 4
	defaultGatewayBitsV4 = 4
)

func serviceSubnetV4(c *corev1.ClusterConfig) string {
	return c.GetStatus().GetNetwork().GetServiceSubnet().GetV4()
}

func serviceSubnetV6(c *corev1.ClusterConfig) string {
	return c.GetStatus().GetNetwork().GetServiceSubnet().GetV6()
}

func gatewayAllocationBitsV4(c *corev1.ClusterConfig) (regionBits, gatewayBits int) {
	regionBits = defaultRegionBitsV4
	gatewayBits = defaultGatewayBitsV4

	v4 := c.GetStatus().GetNetworkConfig().GetV4()
	if v4 == nil {
		return regionBits, gatewayBits
	}

	if v4.GetRegionBits() > 0 {
		regionBits = int(v4.GetRegionBits())
	}
	if v4.GetGatewayBits() > 0 {
		gatewayBits = int(v4.GetGatewayBits())
	}

	return regionBits, gatewayBits
}

func nthSubnet(base *net.IPNet, newPrefix int, index uint64) (*net.IPNet, error) {
	if base == nil {
		return nil, errors.Errorf("Base network is nil")
	}

	ones, bits := base.Mask.Size()
	if bits == 0 {
		return nil, errors.Errorf("Invalid base network mask")
	}
	if newPrefix < ones {
		return nil, errors.Errorf("new prefix /%d is shorter than base prefix /%d", newPrefix, ones)
	}
	if newPrefix > bits {
		return nil, errors.Errorf("new prefix /%d exceeds address bit width %d", newPrefix, bits)
	}

	childBits := newPrefix - ones
	if childBits >= 64 {
		return nil, errors.Errorf("Too many child subnet bits: %d", childBits)
	}

	maxChildren := uint64(1) << uint(childBits)
	if index >= maxChildren {
		return nil, errors.Errorf("Subnet index %d exceeds available child subnet count %d", index, maxChildren)
	}

	ip := base.IP

	switch bits {
	case 32:
		v4 := ip.To4()
		if v4 == nil {
			return nil, errors.Errorf("Base network is not IPv4")
		}
		ip = v4

	case 128:
		v6 := ip.To16()
		if v6 == nil || ip.To4() != nil {
			return nil, errors.Errorf("Base network is not IPv6")
		}
		ip = v6

	default:
		return nil, errors.Errorf("Unsupported address bit width: %d", bits)
	}

	offset := new(big.Int).Lsh(
		new(big.Int).SetUint64(index),
		uint(bits-newPrefix),
	)

	ipInt := new(big.Int).Add(new(big.Int).SetBytes(ip), offset)

	out := make([]byte, bits/8)
	if len(ipInt.Bytes()) > len(out) {
		return nil, errors.Errorf("Allocated subnet overflows address width")
	}

	ipInt.FillBytes(out)

	return &net.IPNet{
		IP:   net.IP(out),
		Mask: net.CIDRMask(newPrefix, bits),
	}, nil
}

func getGatewaySubnetV4(c *corev1.ClusterConfig, nodeIdx, regionIdx int) (*net.IPNet, error) {
	if c == nil {
		return nil, errors.Errorf("ClusterConfig is nil")
	}
	if regionIdx < 0 {
		return nil, errors.Errorf("Region index cannot be negative: %d", regionIdx)
	}
	if nodeIdx < 0 {
		return nil, errors.Errorf("Gateway index cannot be negative: %d", nodeIdx)
	}

	serviceSubnet := serviceSubnetV4(c)
	if serviceSubnet == "" {
		return nil, errors.Errorf("IPv4 Service subnet is empty")
	}

	_, base, err := net.ParseCIDR(serviceSubnet)
	if err != nil {
		return nil, err
	}

	ones, bits := base.Mask.Size()
	if bits != 32 {
		return nil, errors.Errorf("Service subnet %s is not a valid IPv4 range", serviceSubnet)
	}
	if ones > gatewayPrefixLenV4 {
		return nil, errors.Errorf(
			"IPv4 service subnet prefix /%d is longer than fixed gateway subnet prefix /%d",
			ones,
			gatewayPrefixLenV4,
		)
	}

	regionBits, gatewayBits := gatewayAllocationBitsV4(c)

	if regionBits < 0 || gatewayBits < 0 {
		return nil, errors.Errorf("Region/Gateway bit widths cannot be negative")
	}
	if regionBits > 30 || gatewayBits > 30 {
		return nil, errors.Errorf(
			"Region/Gateway bit widths are too large.",
		)
	}

	availableBits := gatewayPrefixLenV4 - ones
	allocationBits := regionBits + gatewayBits

	if allocationBits > availableBits {
		return nil, errors.Errorf(
			"Gateway allocation does not fit",
		)
	}

	maxRegions := 1 << uint(regionBits)
	maxGatewaysPerRegion := 1 << uint(gatewayBits)

	if regionIdx >= maxRegions {
		return nil, errors.Errorf(
			"Region index %d exceeds the maximum of %d regions allowed by %d region bits",
			regionIdx,
			maxRegions,
			regionBits,
		)
	}
	if nodeIdx >= maxGatewaysPerRegion {
		return nil, errors.Errorf(
			"Gateway index %d exceeds the maximum of %d Gateways per region allowed by %d Gateway bits",
			nodeIdx,
			maxGatewaysPerRegion,
			gatewayBits,
		)
	}

	index := (uint64(regionIdx) << uint(gatewayBits)) | uint64(nodeIdx)

	return nthSubnet(base, gatewayPrefixLenV4, index)
}

func getGatewaySubnet(c *corev1.ClusterConfig, nodeIdx, regionIdx int) (*subnet, error) {
	ret := &subnet{}

	if ucorev1.ToClusterConfig(c).HasV4() {
		v4Net, err := getGatewaySubnetV4(c, nodeIdx, regionIdx)
		if err != nil {
			return nil, err
		}
		ret.V4 = v4Net
	}

	if ucorev1.ToClusterConfig(c).HasV6() {
		_, v6Net, err := net.ParseCIDR(serviceSubnetV6(c))
		if err != nil {
			return nil, err
		}

		v6IP := make(net.IP, len(v6Net.IP))
		copy(v6IP, v6Net.IP)

		v6IP[11] = byte(regionIdx % 256)
		v6IP[10] = byte(regionIdx / 256)
		v6IP[13] = byte(nodeIdx % 256)
		v6IP[12] = byte(nodeIdx / 256)

		ret.V6 = &net.IPNet{
			IP:   v6IP,
			Mask: net.CIDRMask(gatewayPrefixLenV6, 128),
		}
	}

	return ret, nil
}
