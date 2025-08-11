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

package authserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

const maxAuthenticatorPerUser = 32

func (s *server) doCreateAuthenticator(ctx context.Context, req *authv1.CreateAuthenticatorRequest) (*authv1.Authenticator, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	if !ucorev1.ToSession(sess).HasValidAccessToken() {
		return nil, s.errPermissionDenied("Old Access Token. Please re-authenticate")
	}

	if len(req.DisplayName) > 120 {
		return nil, s.errInvalidArg("displayName is too long")
	}
	if !govalidator.IsUTFLetterNumeric(req.DisplayName) {
		return nil, s.errInvalidArg("displayName is invalid")
	}

	switch req.Type {
	case authv1.Authenticator_Status_FIDO:
		if usr.Spec.Type != corev1.User_Spec_HUMAN {
			return nil, s.errPermissionDenied("FIDO Authenticators require a HUMAN User")
		}
		if !sess.Status.IsBrowser {
			return nil, s.errPermissionDenied("FIDO Authenticators require Browser-based Sessions")
		}
	case authv1.Authenticator_Status_TOTP:
		if usr.Spec.Type != corev1.User_Spec_HUMAN {
			return nil, s.errPermissionDenied("TOTP Authenticators require a HUMAN User")
		}
	case authv1.Authenticator_Status_TPM:
		if sess.Status.Type == corev1.Session_Status_CLIENTLESS {
			return nil, s.errPermissionDenied("TPM Authenticators require CLIENT-based Sessions")
		}
	case authv1.Authenticator_Status_TYPE_UNKNOWN:
		return nil, s.errInvalidArg("Unknown type")
	}

	{
		itmList, err := s.octeliumC.CoreC().ListAuthenticator(ctx, urscsrv.FilterByUser(usr))
		if err != nil {
			return nil, err
		}
		if len(itmList.Items) >= maxAuthenticatorPerUser {
			return nil, s.errPermissionDenied("Limit for Authenticators exceeded")
		}

	}

	authenticator := &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s-%s",
				strings.ToLower(req.Type.String()), utilrand.GetRandomStringLowercase(6)),
		},
		Spec: &corev1.Authenticator_Spec{
			DisplayName: req.DisplayName,
		},
		Status: &corev1.Authenticator_Status{
			UserRef: umetav1.GetObjectReference(usr),
			Type:    corev1.Authenticator_Status_Type(req.Type),
		},
	}
	authenticator, err = s.octeliumC.CoreC().CreateAuthenticator(ctx, authenticator)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	return s.toAuthenticator(authenticator), nil
}

func (s *server) toAuthenticator(i *corev1.Authenticator) *authv1.Authenticator {
	return &authv1.Authenticator{
		Metadata: &metav1.Metadata{
			Uid:  i.Metadata.Uid,
			Name: i.Metadata.Name,
		},
		Spec: &authv1.Authenticator_Spec{
			DisplayName: i.Spec.DisplayName,
		},
		Status: &authv1.Authenticator_Status{
			Type:         authv1.Authenticator_Status_Type(i.Status.Type),
			IsRegistered: i.Status.IsRegistered,
		},
	}
}

func (s *server) doListAuthenticator(ctx context.Context, req *authv1.ListAuthenticatorOptions) (*authv1.AuthenticatorList, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	itmList, err := s.octeliumC.CoreC().ListAuthenticator(ctx, &rmetav1.ListOptions{
		Paginate:     true,
		Page:         req.Page,
		ItemsPerPage: req.ItemsPerPage,
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterStatusUserUID(usr.Metadata.Uid),
		},
	})
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	ret := &authv1.AuthenticatorList{
		ApiVersion:       "auth/v1",
		Kind:             "AuthenticatorList",
		ListResponseMeta: itmList.ListResponseMeta,
	}

	for _, itm := range itmList.Items {
		ret.Items = append(ret.Items, s.toAuthenticator(itm))
	}

	return ret, nil
}

func (s *server) doDeleteAuthenticator(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	if !ucorev1.ToSession(sess).HasValidAccessToken() {
		return nil, s.errPermissionDenied("Old Access Token. Please re-authenticate")
	}

	if err := apivalidation.CheckDeleteOptions(req, &apivalidation.CheckGetOptionsOpts{}); err != nil {
		return nil, s.errInvalidArgErr(err)
	}

	authn, err := s.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil, s.errNotFound("This Authenticator does not exist")
		}
		return nil, s.errInternalErr(err)
	}

	if authn.Status.UserRef.Uid != usr.Metadata.Uid {
		return nil, s.errNotFound("This Authenticator does not exist")
	}

	_, err = s.octeliumC.CoreC().DeleteAuthenticator(ctx, &rmetav1.DeleteOptions{
		Uid:  authn.Metadata.Uid,
		Name: authn.Metadata.Name,
	})
	if err != nil {
		if !grpcerr.IsNotFound(err) {
			return nil, s.errInternalErr(err)
		}
	}

	return &metav1.OperationResult{}, nil
}

func (s *server) doGetAuthenticator(ctx context.Context, req *metav1.GetOptions) (*authv1.Authenticator, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	if err := apivalidation.CheckGetOptions(req, &apivalidation.CheckGetOptionsOpts{}); err != nil {
		return nil, s.errInvalidArgErr(err)
	}

	authn, err := s.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil, s.errNotFound("This Authenticator does not exist")
		}
		return nil, s.errInternalErr(err)
	}

	if authn.Status.UserRef.Uid != usr.Metadata.Uid {
		return nil, s.errNotFound("This Authenticator does not exist")
	}

	return s.toAuthenticator(authn), nil
}
