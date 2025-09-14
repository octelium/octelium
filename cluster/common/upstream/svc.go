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
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func SetServiceUpstreams(ctx context.Context, octeliumC octeliumc.ClientInterface,
	svc *corev1.Service) ([]*corev1.Session, error) {

	zap.L().Debug("starting checking service listeners to update user connection IPs",
		zap.String("svc", svc.Metadata.Name))

	var svcConns []*corev1.Session

	inList := func(c *corev1.Session) (bool, int) {
		for i, itm := range svcConns {
			if itm.Metadata.Uid == c.Metadata.Uid {
				return true, i
			}
		}
		return false, 0
	}

	isUserListener := func() bool {
		eps := ucorev1.ToService(svc).GetAllUpstreamEndpoints()
		for _, ep := range eps {
			if ep.User != "" {
				return true
			}
		}
		return false
	}

	{
		lSpec := svc.Spec

		if !isUserListener() {
			return nil, nil
		}

		doSet := func(ep *corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint) error {
			conns, err := getCandidateConnections(ctx, ep, lSpec, svc, octeliumC)
			if err != nil {
				return err
			}

			zap.L().Debug("Found candidate conns", zap.Int("len", len(conns)))

			for _, conn := range conns {

				if conn == nil {
					continue
				}

				zap.L().Debug("doing setConnectionUpstreamsListener", zap.Any("conn", conn))

				if err := setConnectionUpstreamsListener(ctx, octeliumC, conn, svc); err != nil {
					return err
				}

				if isInList, listIdx := inList(conn); isInList {
					svcConns[listIdx] = conn
				} else {
					svcConns = append(svcConns, conn)
				}
			}

			return nil
		}

		eps := ucorev1.ToService(svc).GetAllUpstreamEndpoints()
		for _, ep := range eps {
			if ep.User != "" {
				if err := doSet(ep); err != nil {
					return nil, err
				}
			}
		}

	}

	zap.L().Debug("Done setting Service upstreams", zap.String("svc", svc.Metadata.Name))

	return svcConns, nil
}

func getCandidateConnections(ctx context.Context, ep *corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint, lSpec *corev1.Service_Spec,
	svc *corev1.Service, octeliumC octeliumc.ClientInterface) ([]*corev1.Session, error) {

	conns, err := octeliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterFieldEQValStr("status.userRef.name", ep.User),
			urscsrv.FilterFieldEQValStr("status.type", corev1.Session_Status_CLIENT.String()),
		},
	})

	if err != nil {
		return nil, err
	}

	var candidateConns []*corev1.Session

	for _, conn := range conns.Items {
		if conn.Status.Type != corev1.Session_Status_CLIENT {
			continue
		}

		if ServeService(svc, conn) {
			candidateConns = append(candidateConns, conn)
		}
	}

	return candidateConns, nil
}

func ServeService(svc *corev1.Service, sess *corev1.Session) bool {
	conn := sess.Status.Connection
	if conn == nil {
		return false
	}

	opts := conn.ServiceOptions
	if opts == nil {
		return false
	}

	if opts.ServeAll {
		return true
	}

	for _, reqSvc := range opts.RequestedServices {
		if reqSvc.ServiceRef.Uid == svc.Metadata.Uid {
			return true
		}
	}

	return false
}

func GetServiceHostConns(ctx context.Context, octeliumC octeliumc.ClientInterface, svc *corev1.Service) ([]*corev1.Session, error) {
	var ret []*corev1.Session

	isInList := func(itm *corev1.Session) bool {
		for _, i := range ret {
			if i.Metadata.Uid == itm.Metadata.Uid {
				return true
			}
		}
		return false
	}

	doAppend := func(u *metav1.ObjectReference) error {
		sessL, err := octeliumC.CoreC().ListSession(ctx, urscsrv.FilterByUserRef(u))
		if err != nil {
			return err
		}

		for _, sess := range sessL.Items {
			if sess.Status.Type != corev1.Session_Status_CLIENT {
				continue
			}
			if sess.Status.Connection == nil {
				continue
			}

			for _, connUpstream := range sess.Status.Connection.Upstreams {

				if svc.Metadata.Uid == connUpstream.ServiceRef.Uid {
					if !isInList(sess) {
						ret = append(ret, sess)
					}
				}

			}
		}
		return nil
	}

	eps := ucorev1.ToService(svc).GetAllUpstreamEndpoints()
	for _, ep := range eps {
		if ep.User != "" {
			if userRef, err := ucorev1.ToService(svc).GetHostUserRef(ep.User); err == nil {
				if err := doAppend(userRef); err != nil {
					return nil, err
				}
			}
			/*
				if err := doAppend(umetav1.ToMetadata(svc.Metadata).GetCoreUserRef(ep.User)); err != nil {
					return nil, err
				}
			*/
		}
	}

	return ret, nil
}

func GetServiceHostConnsByUser(ctx context.Context, octeliumC octeliumc.ClientInterface,
	svc *corev1.Service, userRef *metav1.ObjectReference) ([]*corev1.Session, error) {
	var ret []*corev1.Session

	if userRef == nil {
		return nil, errors.Errorf("Could not GetServiceHostConnsByUser. UserRef cannot be nil")
	}

	isInList := func(itm *corev1.Session) bool {
		for _, i := range ret {
			if i.Metadata.Uid == itm.Metadata.Uid {
				return true
			}
		}
		return false
	}

	sessL, err := octeliumC.CoreC().ListSession(ctx, urscsrv.FilterByUserRef(userRef))
	if err != nil {
		return nil, err
	}

	for _, sess := range sessL.Items {
		if sess.Status.Type != corev1.Session_Status_CLIENT {
			continue
		}
		if sess.Status.Connection == nil {
			continue
		}

		for _, connUpstream := range sess.Status.Connection.Upstreams {

			if svc.Metadata.Uid == connUpstream.ServiceRef.Uid {
				if !isInList(sess) {
					ret = append(ret, sess)
				}
			}

		}
	}

	return ret, nil
}
