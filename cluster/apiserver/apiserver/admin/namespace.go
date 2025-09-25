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
	"fmt"
	"strings"

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

func (s *Server) UpdateNamespace(ctx context.Context, req *corev1.Namespace) (*corev1.Namespace, error) {
	if err := s.validateNamespace(ctx, req); err != nil {
		return nil, serr.InvalidArgWithErr(err)
	}

	item, err := s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(item); err != nil {
		return nil, err
	}

	common.MetadataUpdate(item.Metadata, req.Metadata)
	item.Spec = req.Spec

	item, err = s.octeliumC.CoreC().UpdateNamespace(ctx, item)
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	return item, nil
}

func (s *Server) CreateNamespace(ctx context.Context, req *corev1.Namespace) (*corev1.Namespace, error) {
	if err := s.validateNamespace(ctx, req); err != nil {
		return nil, serr.InvalidArgWithErr(err)
	}

	if err := checkInvalidServiceNamespaceNames(req.Metadata.Name); err != nil {
		return nil, err
	}

	if _, err := s.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
		Name: fmt.Sprintf("%s.default", req.Metadata.Name),
	}); err == nil {
		return nil, grpcutils.InvalidArg("Cannot use the name: %s while having a Service with the same name in the default Namespace",
			req.Metadata.Name)
	} else if !grpcerr.IsNotFound(err) {
		return nil, err
	}

	_, err := s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err == nil {
		return nil, grpcutils.AlreadyExists("The Namespace %s already exists", req.Metadata.Name)
	}
	if !grpcerr.IsNotFound(err) {
		return nil, err
	}

	item := &corev1.Namespace{
		Metadata: common.MetadataFrom(req.Metadata),
		Spec:     req.Spec,
		Status:   &corev1.Namespace_Status{},
	}

	item, err = s.octeliumC.CoreC().CreateNamespace(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return item, nil
}

func (s *Server) DeleteNamespace(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	ns, err := s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{Name: req.Name, Uid: req.Uid})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(ns); err != nil {
		return nil, err
	}

	if _, err := s.octeliumC.CoreC().DeleteNamespace(ctx, &rmetav1.DeleteOptions{Uid: ns.Metadata.Uid}); err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) ListNamespace(ctx context.Context, req *corev1.ListNamespaceOptions) (*corev1.NamespaceList, error) {
	itemList, err := s.octeliumC.CoreC().ListNamespace(ctx, urscsrv.GetPublicListOptions(req))
	if err != nil {
		return nil, err
	}

	return itemList, nil
}

func (s *Server) GetNamespace(ctx context.Context, req *metav1.GetOptions) (*corev1.Namespace, error) {
	if err := apivalidation.CheckGetOptions(req, nil); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystemHidden(ret); err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *Server) validateNamespace(ctx context.Context, itm *corev1.Namespace) error {
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

func checkInvalidServiceNamespaceNames(arg string) error {
	invalidPrefixes := []string{
		"octelium",
		"local",
	}

	for _, prefix := range invalidPrefixes {
		if strings.HasPrefix(arg, prefix) {
			return grpcutils.InvalidArg("This name is reserved and cannot be used: %s", arg)
		}
	}

	return nil
}
