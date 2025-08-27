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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
)

func (s *Server) ListService(ctx context.Context, req *userv1.ListServiceOptions) (*userv1.ServiceList, error) {

	var ns *corev1.Namespace
	var err error
	if req.Namespace != "" {
		ns, err = s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{
			Name: req.Namespace,
		})
		if err != nil {
			return nil, err
		}

		if err := apivalidation.CheckIsUserHidden(ns); err != nil {
			return nil, err
		}
	}

	listOpts := urscsrv.GetUserPublicListOptions(req)

	if ns != nil {
		listOpts.Filters = append(listOpts.Filters, urscsrv.FilterStatusNamespaceUID(ns.Metadata.Uid))
	}

	svcList, err := s.octeliumC.CoreC().ListService(ctx, listOpts)
	if err != nil {
		return nil, err
	}

	ret := &userv1.ServiceList{
		ApiVersion:       "user/v1",
		Kind:             "ServiceList",
		ListResponseMeta: svcList.ListResponseMeta,
	}
	for _, svc := range svcList.Items {
		ret.Items = append(ret.Items, ServiceTo(svc))
	}

	return ret, nil
}

func (s *Server) GetService(ctx context.Context, req *metav1.GetOptions) (*userv1.Service, error) {

	if err := apivalidation.CheckGetOptions(req, &apivalidation.CheckGetOptionsOpts{
		ParentsMax: 1,
	}); err != nil {
		return nil, err
	}

	svc, err := s.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: vutils.GetServiceFullNameFromName(req.Name),
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsUserHidden(svc); err != nil {
		return nil, err
	}

	return ServiceTo(svc), nil
}
