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
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/pkg/grpcerr"
	"google.golang.org/protobuf/proto"
)

func (s *Server) DoListService(ctx context.Context, req *userv1.ListServiceOptions, user *corev1.User) (*userv1.ServiceList, error) {

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

func (s *Server) ListService(ctx context.Context, req *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
	i, err := userctx.GetUserCtx(ctx)
	if err != nil {
		return nil, err
	}

	if req.Namespace != "" {
		_, err := s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{
			Name: req.Namespace,
		})
		if err != nil {
			if grpcerr.IsNotFound(err) {
				return nil, grpcutils.NotFound("This Namespace does not exist")
			}
			return nil, grpcutils.InternalWithErr(err)
		}
	}

	usr := proto.Clone(i.User).(*corev1.User)
	return s.DoListService(ctx, req, usr)
}
