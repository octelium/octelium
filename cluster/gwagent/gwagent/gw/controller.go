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
	"net"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
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
		gw, err := octeliumC.CoreC().GetGateway(ctx, &rmetav1.GetOptions{Name: k8sutils.GetGatewayName(node)})
		if err == nil {
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

			if _, err := octeliumC.CoreC().UpdateGateway(ctx, gw); err != nil {
				return err
			}
			return nil
		} else {
			if !grpcerr.IsNotFound(err) {
				return err
			}
		}
	}

	gwList, err := octeliumC.CoreC().ListGateway(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterFieldEQValStr("status.regionRef.uid", regionRef.Uid),
		},
	})
	if err != nil {
		return err
	}

	nodeIdx := len(gwList.Items)

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

/*
func handleDeleteNetwork(ctx context.Context, net *corev1.Namespace, wg *wg.Wg) error {
	if err := deleteCNI(net); err != nil {
		return err
	}

	if err := wg.RemoveNetwork(ctx, net); err != nil {
		return err
	}

	l, err := netlink.LinkByName(getBridgeName(net))
	if err != nil {
		return err
	}
	err = netlink.LinkDel(l)
	if err != nil {
		return err
	}

	return nil
}
*/

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
			Cidr: gwCIDR,
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

func getGatewaySubnet(c *corev1.ClusterConfig, nodeIdx, regionIdx int) (*subnet, error) {

	ret := &subnet{}

	if ucorev1.ToClusterConfig(c).HasV4() {
		_, clusterNet, err := net.ParseCIDR(c.Status.Network.ServiceSubnet.V4)
		if err != nil {
			return nil, err
		}

		clusterNetIP := clusterNet.IP.To4()
		octetNo2 := byte((regionIdx%16)<<16) + byte(nodeIdx%16)

		ret.V4 = &net.IPNet{
			IP:   net.IPv4(clusterNetIP[0], clusterNetIP[1], octetNo2, 0),
			Mask: net.CIDRMask(24, 32),
		}
	}

	if ucorev1.ToClusterConfig(c).HasV6() {
		_, v6Net, err := net.ParseCIDR(c.Status.Network.ServiceSubnet.V6)
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
			Mask: net.CIDRMask(112, 128),
		}
	}

	return ret, nil
}
