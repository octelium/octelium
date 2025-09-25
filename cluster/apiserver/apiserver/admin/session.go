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
	"time"

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

func (s *Server) ListSession(ctx context.Context, req *corev1.ListSessionOptions) (*corev1.SessionList, error) {

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

	itemList, err := s.octeliumC.CoreC().ListSession(ctx, urscsrv.GetPublicListOptions(req, listOpts...))
	if err != nil {
		return nil, err
	}

	return itemList, nil
}

func (s *Server) DeleteSession(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	sess, err := s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
		Name: req.Name,
		Uid:  req.Uid,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(sess); err != nil {
		return nil, err
	}

	{
		i, err := userctx.GetUserCtx(ctx)
		if err != nil {
			return nil, err
		}

		if i.Session.Metadata.Uid == sess.Metadata.Uid {
			return nil, grpcutils.Unauthorized("Cannot delete own Session")
		}
	}

	if _, err := s.octeliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{Uid: sess.Metadata.Uid}); err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) GetSession(ctx context.Context, req *metav1.GetOptions) (*corev1.Session, error) {
	if err := apivalidation.CheckGetOptions(req, nil); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	return ret, nil
}

func (s *Server) UpdateSession(ctx context.Context, req *corev1.Session) (*corev1.Session, error) {
	if err := apivalidation.ValidateCommon(req, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{},
	}); err != nil {
		return nil, err
	}

	if err := s.validateSession(req); err != nil {
		return nil, grpcutils.InvalidArgWithErr(err)
	}

	ret, err := s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
		Uid:  req.Metadata.Uid,
		Name: req.Metadata.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(ret); err != nil {
		return nil, err
	}

	if !ldflags.IsTest() {
		i, err := userctx.GetUserCtx(ctx)
		if err != nil {
			return nil, err
		}

		if i.Session.Metadata.Uid == ret.Metadata.Uid {
			switch req.Spec.State {
			case corev1.Session_Spec_PENDING, corev1.Session_Spec_REJECTED:
				return nil, grpcutils.Unauthorized("You cannot deactivate your own Session")
			}
		}
	}

	ret.Spec = req.Spec

	ret, err = s.octeliumC.CoreC().UpdateSession(ctx, ret)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return ret, nil
}

func (s *Server) validateSession(itm *corev1.Session) error {

	if itm.Spec == nil {
		return grpcutils.InvalidArg("You must provide spec")
	}

	spec := itm.Spec

	switch spec.State {
	case corev1.Session_Spec_STATE_UNKNOWN:
		return grpcutils.InvalidArg("State cannot be UNKNOWN")
	}

	if !spec.ExpiresAt.IsValid() {
		return grpcutils.InvalidArg("ExpiresAt must be set")
	}

	if time.Now().After(spec.ExpiresAt.AsTime()) {
		return grpcutils.InvalidArg("expiresAt already exceeded")
	}

	return nil
}
