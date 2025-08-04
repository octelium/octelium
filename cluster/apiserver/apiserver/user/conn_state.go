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

package user

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func getConnectionState(ctx context.Context, octeliumC octeliumc.ClientInterface,
	sess *corev1.Session, cc *corev1.ClusterConfig, privK wgtypes.Key, ed25519Priv ed25519.PrivateKey) (*userv1.ConnectResponse, error) {

	if sess.Status == nil || sess.Status.Connection == nil {
		return nil, grpcutils.InvalidArg("Conn not set in Session")
	}

	conn := sess.Status.Connection

	dnsSvc, err := octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
		Name: "dns.octelium",
	})
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	var dnsIPs []string

	for _, addr := range dnsSvc.Status.Addresses {
		if ucorev1.ToSession(sess).HasV4() && addr.DualStackIP.Ipv4 != "" {
			dnsIPs = append(dnsIPs, addr.DualStackIP.Ipv4)
		}
		if ucorev1.ToSession(sess).HasV6() && addr.DualStackIP.Ipv6 != "" {
			dnsIPs = append(dnsIPs, addr.DualStackIP.Ipv6)
		}
	}

	ret := &userv1.ConnectionState{
		X25519Key:  privK[:],
		Ed25519Key: ed25519Priv[:],
		Mtu: func() int32 {
			switch conn.Type {
			case corev1.Session_Status_Connection_QUICV0:
				return int32(ucorev1.ToClusterConfig(cc).GetDevMTUQUIV0())
			case corev1.Session_Status_Connection_WIREGUARD:
				return int32(ucorev1.ToClusterConfig(cc).GetDevMTUWireGuard())
			default:
				return 1280
			}
		}(),
		Addresses: func() []*metav1.DualStackNetwork {
			ret := []*metav1.DualStackNetwork{}
			for _, addr := range conn.Addresses {
				ret = append(ret, &metav1.DualStackNetwork{
					V4: addr.V4,
					V6: addr.V6,
				})
			}
			return ret
		}(),

		Dns: &userv1.DNS{
			Servers: dnsIPs,
		},

		Cidr: &metav1.DualStackNetwork{
			V4: cc.Status.Network.ServiceSubnet.V4,
			V6: cc.Status.Network.ServiceSubnet.V6,
		},

		L3Mode: func() userv1.ConnectionState_L3Mode {
			switch conn.L3Mode {
			case corev1.Session_Status_Connection_V4:
				return userv1.ConnectionState_V4
			case corev1.Session_Status_Connection_V6:
				return userv1.ConnectionState_V6
			case corev1.Session_Status_Connection_BOTH:
				return userv1.ConnectionState_BOTH
			default:
				return userv1.ConnectionState_BOTH
			}
		}(),
	}

	gws, err := octeliumC.CoreC().ListGateway(ctx, &rmetav1.ListOptions{})
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	gateways := []*userv1.Gateway{}

	for _, gw := range gws.Items {
		gateways = append(gateways, vutils.GatewayToUser(gw))
	}

	ret.Gateways = gateways

	if len(conn.Upstreams) > 0 {
		ret.ServiceOptions = &userv1.ConnectionState_ServiceOptions{
			Services: upstream.GetHostServicesFromConn(sess),
		}
	}

	if ca, err := sshutils.GetCAPublicKey(ctx, octeliumC); err == nil {

		ret.ServiceConfigs = append(ret.ServiceConfigs, &userv1.ConnectionState_ServiceConfig{
			Type: &userv1.ConnectionState_ServiceConfig_Ssh{
				Ssh: &userv1.ConnectionState_ServiceConfig_SSH{
					KnownHosts: []string{
						fmt.Sprintf("@cert-authority %s", knownhosts.Line([]string{"*"}, ca)),
					},
					AuthorizedKeys: []string{
						getAuthorizedKeyCALine(ca),
					},
				},
			},
		})
	} else {
		zap.L().Warn("Could not do GetCAPublicKey", zap.Error(err))
		return nil, serr.InternalWithErr(err)
	}

	return &userv1.ConnectResponse{
		Event: &userv1.ConnectResponse_State{
			State: ret,
		},
	}, nil
}

func getAuthorizedKeyCALine(k ssh.PublicKey) string {
	return fmt.Sprintf("cert-authority %s %s", k.Type(), base64.StdEncoding.EncodeToString(k.Marshal()))
}
