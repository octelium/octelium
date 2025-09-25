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
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/pkg/utils/ldflags"
)

func (s *Server) ListDevice(ctx context.Context, req *corev1.ListDeviceOptions) (*corev1.DeviceList, error) {

	var listOpts []*rmetav1.ListOptions_Filter

	if req.UserRef != nil {
		if err := apivalidation.CheckObjectRef(req.UserRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
			return nil, err
		}
		usr, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid:  req.UserRef.Uid,
			Name: req.UserRef.Name,
		})
		if err != nil {
			return nil, err
		}
		listOpts = append(listOpts, urscsrv.FilterStatusUserUID(usr.Metadata.Uid))
	}

	vDevices, err := s.octeliumC.CoreC().ListDevice(ctx, urscsrv.GetPublicListOptions(req, listOpts...))
	if err != nil {
		return nil, err
	}

	return vDevices, nil
}

func (s *Server) DeleteDevice(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	dev, err := s.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{
		Name: req.Name,
		Uid:  req.Uid,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if _, err := s.octeliumC.CoreC().DeleteDevice(ctx, &rmetav1.DeleteOptions{Uid: dev.Metadata.Uid}); err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) GetDevice(ctx context.Context, req *metav1.GetOptions) (*corev1.Device, error) {
	if err := apivalidation.CheckGetOptions(req, nil); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	return ret, nil
}

func (s *Server) UpdateDevice(ctx context.Context, req *corev1.Device) (*corev1.Device, error) {

	if err := s.validateDevice(ctx, req); err != nil {
		return nil, serr.InvalidArgWithErr(err)
	}

	item, err := s.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if !ldflags.IsTest() {
		i, err := userctx.GetUserCtx(ctx)
		if err != nil {
			return nil, err
		}

		if i.Device != nil && i.Device.Metadata.Uid == item.Metadata.Uid {
			switch req.Spec.State {
			case corev1.Device_Spec_PENDING, corev1.Device_Spec_REJECTED:
				return nil, grpcutils.Unauthorized("You cannot deactivate your own Device")
			}
		}
	}

	item.Spec = req.Spec

	item, err = s.octeliumC.CoreC().UpdateDevice(ctx, item)
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	return item, nil
}

func (s *Server) validateDevice(ctx context.Context, itm *corev1.Device) error {
	if err := apivalidation.ValidateCommon(itm, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
		},
	}); err != nil {
		return err
	}

	if itm.Spec == nil {
		return grpcutils.InvalidArg("You must provide spec")
	}

	switch itm.Spec.State {
	case corev1.Device_Spec_STATE_UNKNOWN:
		return grpcutils.InvalidArg("State cannot be UNKNOWN")
	}

	if err := s.validatePolicyOwner(ctx, itm.Spec.Authorization); err != nil {
		return err
	}

	return nil
}
