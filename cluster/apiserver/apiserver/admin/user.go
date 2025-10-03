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

	"github.com/asaskevich/govalidator"
	"github.com/gosimple/slug"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/pkg/common/rgx"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
)

func (s *Server) CreateUser(ctx context.Context, req *corev1.User) (*corev1.User, error) {
	if err := s.validateUser(ctx, req); err != nil {
		return nil, serr.InvalidArgWithErr(err)
	}

	_, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err == nil {
		return nil, grpcutils.AlreadyExists("The User %s already exists", req.Metadata.Name)
	}
	if !grpcerr.IsNotFound(err) {
		return nil, grpcutils.InternalWithErr(err)
	}

	item := &corev1.User{
		Metadata: common.MetadataFrom(req.Metadata),
		Spec:     req.Spec,
		Status:   &corev1.User_Status{},
	}

	if err := s.CheckAndSetUser(ctx, s.octeliumC, item, false); err != nil {
		return nil, err
	}

	nUsr, err := s.octeliumC.CoreC().CreateUser(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return nUsr, nil
}

func (s *Server) UpdateUser(ctx context.Context, req *corev1.User) (*corev1.User, error) {
	if err := s.validateUser(ctx, req); err != nil {
		return nil, serr.InvalidArgWithErr(err)
	}

	item, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(item); err != nil {
		return nil, err
	}

	common.MetadataUpdate(item.Metadata, req.Metadata)
	item.Spec = req.Spec

	if err := s.CheckAndSetUser(ctx, s.octeliumC, item, false); err != nil {
		return nil, err
	}

	if !ldflags.IsTest() {
		i, err := userctx.GetUserCtx(ctx)
		if err != nil {
			return nil, err
		}

		if i.User.Metadata.Uid == item.Metadata.Uid {
			if item.Spec.IsDisabled {
				return nil, grpcutils.Unauthorized("You cannot disable yourself")
			}
		}
	}

	item, err = s.octeliumC.CoreC().UpdateUser(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return item, nil
}

func (s *Server) ListUser(ctx context.Context, req *corev1.ListUserOptions) (*corev1.UserList, error) {

	itemList, err := s.octeliumC.CoreC().ListUser(ctx, urscsrv.GetPublicListOptions(req))
	if err != nil {
		return nil, err
	}

	return itemList, nil
}

func (s *Server) DeleteUser(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	usr, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Name: req.Name, Uid: req.Uid})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(usr); err != nil {
		return nil, err
	}

	_, err = s.octeliumC.CoreC().DeleteUser(ctx, &rmetav1.DeleteOptions{Uid: usr.Metadata.Uid})
	if err != nil {
		return nil, err
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) CheckAndSetUser(ctx context.Context, octeliumC octeliumc.ClientInterface, req *corev1.User, isSystem bool) error {

	specLabels := make(map[string]string)

	if req.Spec.Authorization != nil {

		for _, inlinePolicy := range req.Spec.Authorization.InlinePolicies {
			if err := s.validatePolicySpec(ctx, inlinePolicy.Spec); err != nil {
				return err
			}
		}

		for _, p := range req.Spec.Authorization.Policies {
			_, err := s.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{
				Name: p,
			})
			if grpcerr.IsNotFound(err) {
				return grpcutils.InvalidArg("The Policy %s is not found", p)
			}
		}
	}

	for _, g := range req.Spec.Groups {
		_, err := octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{Name: g})
		if err != nil {
			if grpcerr.IsNotFound(err) {
				return serr.InvalidArg("The Group %s does not exist", g)
			}
			return serr.InternalWithErr(err)
		}
	}

	if req.Spec.Email != "" {
		usrs, err := octeliumC.CoreC().ListUser(ctx, &rmetav1.ListOptions{
			SpecLabels: map[string]string{
				"email": slug.Make(req.Spec.Email),
			},
		})
		if err != nil {
			return serr.InternalWithErr(err)
		}

		if len(usrs.Items) > 0 && (usrs.Items[0].Metadata.Name != req.Metadata.Name) {
			return serr.InvalidArg("The email `%s` already exists for another User", req.Spec.Email)
		}

		// specLabels["email"] = slug.Make(req.Spec.Email)
	}

	if req.Spec.Authentication != nil {
		for _, acc := range req.Spec.Authentication.Identities {

			_, err := octeliumC.CoreC().GetIdentityProvider(ctx, &rmetav1.GetOptions{
				Name: acc.IdentityProvider,
			})
			if err != nil {
				if grpcerr.IsNotFound(err) {
					return serr.InvalidArg("The Identity Provider %s does not exist", acc.IdentityProvider)
				}
				return serr.InternalWithErr(err)
			}

			specLabels[fmt.Sprintf("auth-%s", acc.IdentityProvider)] = slug.Make(acc.Identifier)

			usrs, err := octeliumC.CoreC().ListUser(ctx, &rmetav1.ListOptions{
				SpecLabels: map[string]string{
					fmt.Sprintf("auth-%s", acc.IdentityProvider): slug.Make(acc.Identifier),
				},
			})
			if err != nil {
				return serr.InternalWithErr(err)
			}

			if len(usrs.Items) > 0 && (usrs.Items[0].Metadata.Name != req.Metadata.Name) {
				return serr.InvalidArg("The identifier `%s` for the IdentityProvider `%s` already exists for another User", acc.Identifier, acc.IdentityProvider)
			}

		}
	}

	req.Metadata.SpecLabels = specLabels

	return nil
}

func (s *Server) GetUser(ctx context.Context, req *metav1.GetOptions) (*corev1.User, error) {
	if err := apivalidation.CheckGetOptions(req, nil); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
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

func (s *Server) validateUser(ctx context.Context, itm *corev1.User) error {

	if err := apivalidation.ValidateCommon(itm, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
		},
	}); err != nil {
		return err
	}

	if itm.Spec == nil {
		return grpcutils.InvalidArg("Nil Spec")
	}

	if err := apivalidation.ValidateAttrs(itm.Spec.Attrs); err != nil {
		return err
	}

	if itm.Spec.Type == corev1.User_Spec_TYPE_UNKNOWN {
		return grpcutils.InvalidArg("You must set the User type (i.e. either `HUMAN` or `WORKLOAD`)")
	}

	if itm.Spec.Email != "" {
		if itm.Spec.Type != corev1.User_Spec_HUMAN {
			return grpcutils.InvalidArg("Email is only allowed for HUMAN Users")
		}

		if !govalidator.IsEmail(itm.Spec.Email) {
			return grpcutils.InvalidArg("Invalid email: %s", itm.Spec.Email)
		}
		if !govalidator.IsASCII(itm.Spec.Email) {
			return grpcutils.InvalidArg("Invalid email. Must be ascii: %s", itm.Spec.Email)
		}
		if !govalidator.IsLowerCase(itm.Spec.Email) {
			return grpcutils.InvalidArg("Email must be lowercase: %s", itm.Spec.Email)
		}
		if len(itm.Spec.Email) > 150 {
			return grpcutils.InvalidArg("Email is too long: %s", itm.Spec.Email)
		}
	}

	if itm.Spec.Authentication != nil {
		if len(itm.Spec.Authentication.Identities) > 100 {
			return grpcutils.InvalidArg("Too many identities")
		}

		for _, acc := range itm.Spec.Authentication.Identities {
			if acc.Identifier == "" {
				return grpcutils.InvalidArg("Empty identifier")
			}

			if acc.IdentityProvider == "" {
				return grpcutils.InvalidArg("Empty Identity Provider")
			}
		}
	}

	for _, g := range itm.Spec.Groups {
		if !rgx.NameMain.MatchString(g) {
			return grpcutils.InvalidArg("Invalid Group name: %s", g)
		}
	}

	if itm.Spec.Session != nil {
		if err := apivalidation.ValidateDuration(itm.Spec.Session.ClientDuration); err != nil {
			return err
		}

		if err := apivalidation.ValidateDuration(itm.Spec.Session.ClientlessDuration); err != nil {
			return err
		}
	}

	if err := s.validatePolicyOwner(ctx, itm.Spec.Authorization); err != nil {
		return err
	}

	return nil
}
