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
	"github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/grpcerr"
)

func (s *Server) CreateGroup(ctx context.Context, req *corev1.Group) (*corev1.Group, error) {

	if err := s.validateGroup(ctx, req); err != nil {
		return nil, grpcutils.InvalidArgWithErr(err)
	}

	_, err := s.octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err == nil {
		return nil, grpcutils.AlreadyExists("The Group %s already exists", req.Metadata.Name)
	}

	if !grpcerr.IsNotFound(err) {
		return nil, serr.K8sInternal(err)
	}

	item := &corev1.Group{
		Metadata: common.MetadataFrom(req.Metadata),
		Spec:     req.Spec,
		Status:   &corev1.Group_Status{},
	}

	item, err = s.octeliumC.CoreC().CreateGroup(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return item, nil
}

func (s *Server) UpdateGroup(ctx context.Context, req *corev1.Group) (*corev1.Group, error) {

	if err := s.validateGroup(ctx, req); err != nil {
		return nil, grpcutils.InvalidArgWithErr(err)
	}

	item, err := s.octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err != nil {
		return nil, err
	}

	if err := apivalidation.CheckIsSystem(item); err != nil {
		return nil, err
	}

	common.MetadataUpdate(item.Metadata, req.Metadata)
	item.Spec = req.Spec

	item, err = s.octeliumC.CoreC().UpdateGroup(ctx, item)
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	return item, nil
}

func (s *Server) ListGroup(ctx context.Context, req *corev1.ListGroupOptions) (*corev1.GroupList, error) {

	itemList, err := s.octeliumC.CoreC().ListGroup(ctx, urscsrv.GetPublicListOptions(req))
	if err != nil {
		return nil, err
	}

	return itemList, nil
}

func (s *Server) DeleteGroup(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	g, err := s.octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{Name: req.Name, Uid: req.Uid})
	if err != nil {
		return nil, err
	}

	if err := apivalidation.CheckIsSystem(g); err != nil {
		return nil, err
	}

	usrs, err := s.octeliumC.CoreC().ListUser(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterFieldIncludesValStr("spec.groups", g.Metadata.Name),
		},
	})
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	if len(usrs.Items) > 0 {
		return nil, serr.InvalidArg("There are Users belonging to this Group. You must delete all its Users first.")
	}

	_, err = s.octeliumC.CoreC().DeleteGroup(ctx, &rmetav1.DeleteOptions{Uid: g.Metadata.Uid})
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) GetGroup(ctx context.Context, req *metav1.GetOptions) (*corev1.Group, error) {
	if err := apivalidation.CheckGetOptions(req, nil); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	return ret, nil
}

func (s *Server) validateGroup(ctx context.Context, itm *corev1.Group) error {

	if err := apivalidation.ValidateCommon(itm, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
		},
	}); err != nil {
		return err
	}

	if itm.Spec == nil {
		return grpcutils.InvalidArg("Nil spec")
	}

	if err := apivalidation.ValidateAttrs(itm.Spec.Attrs); err != nil {
		return err
	}

	if err := s.validatePolicyOwner(ctx, itm.Spec.Authorization); err != nil {
		return err
	}

	return nil
}
