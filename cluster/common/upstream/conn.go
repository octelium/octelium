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

package upstream

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
)

func SetConnectionUpstreams(ctx context.Context, octeliumC octeliumc.ClientInterface, sess *corev1.Session, svc *corev1.Service) error {
	if err := setConnectionUpstreamsListener(ctx, octeliumC, sess, svc); err != nil {
		return err
	}

	return nil
}

func GetHostServicesFromUpstream(l *corev1.Session_Status_Connection_Upstream, sess *corev1.Session) *userv1.HostedService {

	conn := sess.Status.Connection

	if len(conn.Addresses) == 0 {
		return nil
	}

	return &userv1.HostedService{
		Name: l.ServiceRef.Name,
		// Namespace: l.NamespaceRef.Name,
		Port: uint32(l.Port),

		L4Type: userv1.HostedService_L4Type(l.L4Type),
		Upstream: &userv1.HostedService_Upstream{
			Host: l.Backend.Host,
			Port: int32(l.Backend.Port),
		},

		Mode: userv1.HostedService_Mode(l.Mode),

		Address: func() *metav1.DualStackIP {
			addrNet := conn.Addresses[0]
			return &metav1.DualStackIP{
				Ipv4: umetav1.ToDualStackNetwork(addrNet).ToIP().Ipv4,
				Ipv6: umetav1.ToDualStackNetwork(addrNet).ToIP().Ipv6,
			}
		}(),
	}
}

func GetHostServicesFromConn(sess *corev1.Session) []*userv1.HostedService {
	var ret []*userv1.HostedService
	if sess.Status.Connection == nil {
		return nil
	}
	conn := sess.Status.Connection

	if len(conn.Addresses) == 0 {
		return nil
	}

	for _, l := range conn.Upstreams {

		ret = append(ret, GetHostServicesFromUpstream(l, sess))
	}

	return ret
}

func RemoveConnectionUpstreams(ctx context.Context, octeliumC octeliumc.ClientInterface, sess *corev1.Session, svc *corev1.Service) error {
	conn := sess.Status.Connection
	if conn == nil {
		return nil
	}
	for upstreamIdx := len(conn.Upstreams) - 1; upstreamIdx >= 0; upstreamIdx-- {
		upstream := conn.Upstreams[upstreamIdx]
		if upstream.ServiceRef.Uid == svc.Metadata.Uid {
			conn.Upstreams = append(conn.Upstreams[0:upstreamIdx], conn.Upstreams[upstreamIdx+1:]...)
		}
	}

	return nil
}
