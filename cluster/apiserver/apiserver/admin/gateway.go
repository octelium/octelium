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

package admin

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	apisrvcommon "github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/urscsrv"
)

func (s *Server) ListGateway(ctx context.Context, req *corev1.ListGatewayOptions) (*corev1.GatewayList, error) {

	var listOpts []*rmetav1.ListOptions_Filter

	if req.RegionRef != nil {
		if err := apivalidation.CheckObjectRef(req.RegionRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
			return nil, err
		}

		rgn, err := s.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
			Uid:  req.RegionRef.Uid,
			Name: req.RegionRef.Name,
		})
		if err != nil {
			return nil, err
		}

		listOpts = append(listOpts, urscsrv.FilterFieldEQValStr("status.regionRef.uid", rgn.Metadata.Uid))
	}

	lst, err := s.octeliumC.CoreC().ListGateway(ctx, urscsrv.GetPublicListOptions(req, listOpts...))
	if err != nil {
		return nil, err
	}

	return lst, nil
}

func (s *Server) GetGateway(ctx context.Context, req *metav1.GetOptions) (*corev1.Gateway, error) {
	if err := apisrvcommon.CheckGetOrDeleteOptions(req); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetGateway(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	return ret, nil
}
