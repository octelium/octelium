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
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

const maxAuthenticatorPerUser = 32

func (s *server) doCreateAuthenticator(ctx context.Context,
	req *authv1.CreateAuthenticatorRequest) (*authv1.Authenticator, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	if err := s.checkSessionValid(sess); err != nil {
		return nil, err
	}

	switch sess.Status.AuthenticatorAction {
	case corev1.Session_Status_AUTHENTICATION_REQUIRED:
		return nil, s.errPermissionDenied("Cannot modify Authenticators")
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

	if err := s.validateAuthenticatorSpec(authenticator); err != nil {
		return nil, err
	}

	authenticator, err = s.octeliumC.CoreC().CreateAuthenticator(ctx, authenticator)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	return s.toAuthenticator(authenticator), nil
}

func (s *server) toAuthenticator(i *corev1.Authenticator) *authv1.Authenticator {
	if i == nil {
		return nil
	}

	return &authv1.Authenticator{
		Metadata: &metav1.Metadata{
			Uid:       i.Metadata.Uid,
			Name:      i.Metadata.Name,
			CreatedAt: i.Metadata.CreatedAt,
		},
		Spec: &authv1.Authenticator_Spec{
			DisplayName: i.Spec.DisplayName,
		},
		Status: &authv1.Authenticator_Status{
			Type:         authv1.Authenticator_Status_Type(i.Status.Type),
			IsRegistered: i.Status.IsRegistered,
			Description:  i.Status.Description,
		},
	}
}

func (s *server) doListAuthenticator(ctx context.Context,
	req *authv1.ListAuthenticatorOptions) (*authv1.AuthenticatorList, error) {
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

func (s *server) doDeleteAuthenticator(ctx context.Context,
	req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.checkSessionValid(sess); err != nil {
		return nil, err
	}

	switch sess.Status.AuthenticatorAction {
	case corev1.Session_Status_AUTHENTICATION_REQUIRED:
		return nil, s.errPermissionDenied("Cannot modify Authenticators")
	}

	if err := apivalidation.CheckDeleteOptions(req, &apivalidation.CheckGetOptionsOpts{}); err != nil {
		return nil, s.errInvalidArgErr(err)
	}

	authn, err := s.getAuthenticator(ctx, &metav1.ObjectReference{
		Uid:  req.Uid,
		Name: req.Name,
	}, sess)
	if err != nil {
		return nil, err
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

	authn, err := s.getAuthenticator(ctx, &metav1.ObjectReference{
		Uid:  req.Uid,
		Name: req.Name,
	}, sess)
	if err != nil {
		return nil, err
	}

	return s.toAuthenticator(authn), nil
}

func (s *server) doGetAvailableAuthenticator(ctx context.Context,
	_ *authv1.GetAvailableAuthenticatorRequest) (*authv1.GetAvailableAuthenticatorResponse, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	resp, err := s.getAvailableAuthenticators(ctx, sess, usr)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	ret := &authv1.GetAvailableAuthenticatorResponse{}

	if resp.MainAuthenticator != nil {
		ret.MainAuthenticator = s.toAuthenticator(resp.MainAuthenticator)
	}

	for _, itm := range resp.AvailableAuthenticators {
		ret.AvailableAuthenticators = append(ret.AvailableAuthenticators, s.toAuthenticator(itm))
	}

	return ret, nil
}

func (s *server) doUpdateAuthenticator(ctx context.Context,
	req *authv1.Authenticator) (*authv1.Authenticator, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.checkSessionValid(sess); err != nil {
		return nil, err
	}

	switch sess.Status.AuthenticatorAction {
	case corev1.Session_Status_AUTHENTICATION_REQUIRED:
		return nil, s.errPermissionDenied("Cannot modify Authenticators")
	}

	if err := apivalidation.ValidateMetadata(req.Metadata, &apivalidation.ValidateMetadataOpts{}); err != nil {
		return nil, s.errInvalidArgErr(err)
	}

	authn, err := s.getAuthenticator(ctx, &metav1.ObjectReference{
		Uid:  req.Metadata.Uid,
		Name: req.Metadata.Name,
	}, sess)
	if err != nil {
		return nil, err
	}
	if req.Spec == nil {
		return nil, s.errInvalidArg("Nil spec")
	}

	authn.Spec.DisplayName = req.Spec.DisplayName

	if err := s.validateAuthenticatorSpec(authn); err != nil {
		return nil, err
	}

	authn, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
	if err != nil {
		if !grpcerr.IsNotFound(err) {
			return nil, s.errInternalErr(err)
		}
	}

	return s.toAuthenticator(authn), nil
}

func (s *server) validateAuthenticatorSpec(req *corev1.Authenticator) error {

	if req.Spec == nil {
		return s.errInvalidArg("Nil spec")
	}

	if len(req.Spec.DisplayName) > 120 {
		return s.errInvalidArg("displayName is too long")
	}

	if !govalidator.IsASCII(req.Spec.DisplayName) {
		return s.errInvalidArg("Invalid display name")
	}

	return nil
}

type getAvailableAuthenticatorsResp struct {
	MainAuthenticator       *corev1.Authenticator
	AvailableAuthenticators []*corev1.Authenticator
}

func (s *server) getAvailableAuthenticators(ctx context.Context,
	sess *corev1.Session, usr *corev1.User) (*getAvailableAuthenticatorsResp, error) {

	ret := &getAvailableAuthenticatorsResp{}

	if sess == nil || usr == nil {
		return nil, s.errInvalidArg("Session and User must be provided")
	}

	if sess.Status.RequiredAuthenticatorRef != nil {
		authn, err := s.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
			Uid: sess.Status.RequiredAuthenticatorRef.Uid,
		})
		if err != nil {
			return nil, err
		}

		ret.MainAuthenticator = authn
		ret.AvailableAuthenticators = []*corev1.Authenticator{
			authn,
		}

		return ret, nil
	}

	if sess.Status.InitialAuthentication != nil &&
		sess.Status.InitialAuthentication.Info != nil &&
		sess.Status.InitialAuthentication.Info.GetAuthenticator() != nil &&
		sess.Status.InitialAuthentication.Info.GetAuthenticator().Type == corev1.Authenticator_Status_FIDO {
		authn, err := s.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
			Uid: sess.Status.InitialAuthentication.Info.GetAuthenticator().AuthenticatorRef.Uid,
		})
		if err != nil {
			return nil, err
		}

		ret.MainAuthenticator = authn
		ret.AvailableAuthenticators = []*corev1.Authenticator{
			authn,
		}

		return ret, nil
	}

	itmList, err := s.octeliumC.CoreC().ListAuthenticator(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterStatusUserUID(usr.Metadata.Uid),
			urscsrv.FilterFieldBooleanTrue("status.isRegistered"),
		},
	})
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	for _, itm := range itmList.Items {
		if !itm.Status.IsRegistered {
			continue
		}

		switch sess.Status.Type {
		case corev1.Session_Status_CLIENT:
			switch itm.Status.Type {
			case corev1.Authenticator_Status_TPM, corev1.Authenticator_Status_TOTP:
			default:
				continue
			}
			if itm.Status.DeviceRef != nil && sess.Status.DeviceRef != nil &&
				itm.Status.DeviceRef.Uid == sess.Status.DeviceRef.Uid {
				ret.MainAuthenticator = itm
				ret.AvailableAuthenticators = []*corev1.Authenticator{itm}

				return ret, nil
			}
		case corev1.Session_Status_CLIENTLESS:
			if !sess.Status.IsBrowser {
				continue
			}
			switch itm.Status.Type {
			case corev1.Authenticator_Status_FIDO, corev1.Authenticator_Status_TOTP:
			default:
				continue
			}
		}

		ret.AvailableAuthenticators = append(ret.AvailableAuthenticators, itm)
	}

	return ret, nil
}
