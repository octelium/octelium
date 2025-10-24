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
	"net/http"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/oscope"
	"github.com/octelium/octelium/cluster/common/sessionc"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func (s *server) generateSessionTokenResponse(ctx context.Context, sess *corev1.Session) (*authv1.SessionToken, error) {

	accessToken, err := s.generateAccessToken(sess)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	refreshToken, err := s.generateRefreshToken(sess)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	ret := &authv1.SessionToken{
		ExpiresIn:             umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToSeconds(),
		RefreshTokenExpiresIn: umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToSeconds(),
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
	}

	if sess.Status.Type == corev1.Session_Status_CLIENTLESS &&
		sess.Status.IsBrowser {

		accessTokenCookie := &http.Cookie{
			Name:     "octelium_auth",
			Value:    ret.AccessToken,
			Secure:   true,
			HttpOnly: true,
			Domain:   s.domain,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToGo()),
		}

		refreshTokenCookie := &http.Cookie{
			Name:     "octelium_rt",
			Value:    ret.RefreshToken,
			Secure:   true,
			HttpOnly: true,
			Domain:   s.domain,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
			Expires:  time.Now().Add(umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToGo()),
		}

		if err := s.setCookiesGRPC(ctx, []*http.Cookie{
			accessTokenCookie,
			refreshTokenCookie,
		}); err != nil {
			zap.L().Warn("Could not setCookiesGRPC", zap.Error(err))
		}

		ret = &authv1.SessionToken{}
	}

	return ret, nil
}

func (s *server) doAuthenticateWithAuthenticationToken(ctx context.Context, req *authv1.AuthenticateWithAuthenticationTokenRequest) (*authv1.SessionToken, error) {

	if err := oscope.VerifyScopes(req.Scopes); err != nil {
		return nil, s.errInvalidArgErr(err)
	}

	tkn, err := s.getCredentialFromToken(ctx, req.AuthenticationToken)
	if err != nil {
		return nil, err
	}

	if tkn.Spec.Type != corev1.Credential_Spec_AUTH_TOKEN {
		return nil, s.errUnauthenticated("Not an AUTH TOKEN")
	}

	usr, err := s.getUserFromUserRef(ctx, tkn.Status.UserRef)
	if err != nil {
		return nil, err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	scopes, err := oscope.GetScopes(req.Scopes)
	if err != nil {
		// already verified in the request body validation
		return nil, s.errInvalidArgErr(err)
	}

	sessType := func() corev1.Session_Status_Type {
		if tkn.Spec.SessionType != corev1.Session_Status_TYPE_UNKNOWN {
			return tkn.Spec.SessionType
		}

		return s.mustGetSessionTypeFromUserAgent(ctx)
	}()

	if err := s.checkMaxSessionsPerUser(ctx, usr, cc); err != nil {
		return nil, err
	}

	sess, err := sessionc.CreateSession(ctx, &sessionc.CreateSessionOpts{
		OcteliumC:     s.octeliumC,
		ClusterConfig: cc,
		Usr:           usr,

		CredentialRef: umetav1.GetObjectReference(tkn),

		SessType: sessType,

		Scopes: scopes,
		AuthenticationInfo: &corev1.Session_Status_Authentication_Info{
			Type: corev1.Session_Status_Authentication_Info_CREDENTIAL,
			Details: &corev1.Session_Status_Authentication_Info_Credential_{
				Credential: &corev1.Session_Status_Authentication_Info_Credential{
					CredentialRef: umetav1.GetObjectReference(tkn),
					Type:          tkn.Spec.Type,
					TokenID:       tkn.Status.TokenID,
				},
			},
		},

		Authorization: func() *corev1.Session_Spec_Authorization {
			if tkn.Spec.Authorization == nil {
				return nil
			}
			return &corev1.Session_Spec_Authorization{
				Policies:       tkn.Spec.Authorization.Policies,
				InlinePolicies: tkn.Spec.Authorization.InlinePolicies,
			}
		}(),

		UserAgent: grpcutils.GetHeaderValueMust(ctx, "user-agent"),
		XFF:       grpcutils.GetHeaderValueMust(ctx, "x-forwarded-for"),
	})
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	ret, err := s.generateSessionTokenResponse(ctx, sess)
	if err != nil {
		return nil, err
	}

	if err := s.updateAndAutoDeleteCredential(ctx, tkn); err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *server) updateAndAutoDeleteCredential(ctx context.Context, tkn *corev1.Credential) error {
	tkn.Status.TotalAuthentications = tkn.Status.TotalAuthentications + 1

	if _, err := s.octeliumC.CoreC().UpdateCredential(ctx, tkn); err != nil {
		return err
	}

	if !tkn.Spec.AutoDelete {
		return nil
	}
	if tkn.Spec.MaxAuthentications == 0 {
		return nil
	}

	if tkn.Status.TotalAuthentications < tkn.Spec.MaxAuthentications {
		return nil
	}

	if _, err := s.octeliumC.CoreC().DeleteCredential(ctx, &rmetav1.DeleteOptions{Uid: tkn.Metadata.Uid}); err != nil {
		return s.errInternalErr(err)
	}

	return nil
}

func (s *server) doAuthenticateWithAssertion(ctx context.Context, req *authv1.AuthenticateWithAssertionRequest) (*authv1.SessionToken, error) {

	if req.IdentityProviderRef == nil {
		return nil, s.errUnauthenticated("No IdentityProviderRef")
	}

	if err := apivalidation.CheckObjectRef(req.IdentityProviderRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
		return nil, s.errUnauthenticatedErr(err)
	}

	if req.Assertion == "" {
		return nil, s.errUnauthenticated("Empty assertion")
	}

	if !govalidator.IsASCII(req.Assertion) {
		return nil, s.errUnauthenticated("Invalid assertion")
	}

	if len(req.Assertion) > 5000 {
		return nil, s.errInvalidArg("Invalid assertion")
	}

	if err := oscope.VerifyScopes(req.Scopes); err != nil {
		return nil, s.errUnauthenticatedErr(err)
	}

	provider, err := s.getAssertionProviderFromName(req.IdentityProviderRef.Name)
	if err != nil {
		return nil, s.errUnauthenticated("Invalid IdentityProvider")
	}

	if provider.Provider().Spec.IsDisabled {
		return nil, s.errUnauthenticated("IdentityProvider is disabled")
	}
	if provider.Provider().Status.IsLocked {
		return nil, s.errUnauthenticated("IdentityProvider is locked")
	}

	usr, info, err := provider.AuthenticateAssertion(ctx, req)
	if err != nil {
		return nil, s.errUnauthenticatedErr(err)
	}

	if usr.Spec.Type != corev1.User_Spec_WORKLOAD {
		return nil, s.errPermissionDenied("User is not WORKLOAD")
	}

	if usr.Spec.IsDisabled {
		return nil, s.errPermissionDenied("User is deactivated")
	}

	if err := s.doPostAuthenticationRules(ctx, provider.Provider(), usr, info); err != nil {
		return nil, s.errPermissionDenied("denied by postAuthenticationRules")
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	scopes, err := oscope.GetScopes(req.Scopes)
	if err != nil {
		// already verified in the request body validation
		return nil, s.errInvalidArgErr(err)
	}

	sessType := s.mustGetSessionTypeFromUserAgent(ctx)

	if err := s.checkMaxSessionsPerUser(ctx, usr, cc); err != nil {
		return nil, err
	}
	sess, err := sessionc.CreateSession(ctx, &sessionc.CreateSessionOpts{
		OcteliumC:     s.octeliumC,
		ClusterConfig: cc,
		Usr:           usr,

		SessType: sessType,

		Scopes:             scopes,
		AuthenticationInfo: info,

		UserAgent: grpcutils.GetHeaderValueMust(ctx, "user-agent"),
		XFF:       grpcutils.GetHeaderValueMust(ctx, "X-Forwarded-For"),
	})
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	ret, err := s.generateSessionTokenResponse(ctx, sess)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *server) doAuthenticateWithRefreshToken(ctx context.Context, _ *authv1.AuthenticateWithRefreshTokenRequest) (*authv1.SessionToken, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	if sess.Status.IsBrowser {
		zap.L().Debug("refreshToken flow is not allowed for Browsers")
		return nil, s.errPermissionDenied("Invalid Session type")
	}

	zap.L().Debug("Got Session from creds", zap.Any("sess", sess))

	if !s.needsReAuth(sess) {
		return nil, s.errAlreadyExists("The Session is valid and does not need a refresh")
	}

	if sess.Status.RequiredAuthenticatorRef != nil {
		return nil, s.errPermissionDenied("This Session has a required Authenticator")
	}

	_, err = s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	s.setCurrAuthenticationGRPC(ctx, sess, cc, &corev1.Session_Status_Authentication_Info{
		Type: corev1.Session_Status_Authentication_Info_REFRESH_TOKEN,
	})

	if _, err := s.octeliumC.CoreC().UpdateSession(ctx, sess); err != nil {
		return nil, s.errInternalErr(err)
	}

	ret, err := s.generateSessionTokenResponse(ctx, sess)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *server) getSessionFromGRPCCtx(ctx context.Context) (*corev1.Session, error) {

	var refreshToken string

	if val := grpcutils.GetHeaderValueMust(ctx, "x-octelium-refresh-token"); val != "" {
		refreshToken = val
	} else if val := grpcutils.GetHeaderValueAll(ctx, "cookie"); len(val) > 0 {
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			return nil, s.errInternalErr(err)
		}

		req.Header.Add("Cookie", strings.Join(val, ";"))

		if cookie, err := req.Cookie("octelium_rt"); err == nil {
			refreshToken = cookie.Value
		}
	}

	if refreshToken == "" {
		return nil, s.errUnauthenticated("Could not find refresh token")
	}

	return s.getSessionFromRefreshToken(ctx, refreshToken)
}

func (s *server) getWebSessionFromHTTPRefreshCookie(r *http.Request) (*corev1.Session, error) {

	ctx := r.Context()

	cookie, err := r.Cookie("octelium_rt")
	if err != nil {
		return nil, err
	}

	sess, err := s.getSessionFromRefreshToken(ctx, cookie.Value)
	if err != nil {
		return nil, err
	}

	if !sess.Status.IsBrowser {
		return nil, s.errInvalidArg("Not a WEB Session")
	}

	return sess, nil
}

func (s *server) getUserFromSession(ctx context.Context, sess *corev1.Session) (*corev1.User, error) {
	return s.getUserFromUserRef(ctx, sess.Status.UserRef)
}

func (s *server) getUserFromUserRef(ctx context.Context, usrRef *metav1.ObjectReference) (*corev1.User, error) {
	usr, err := s.octeliumC.CoreC().GetUser(ctx,
		&rmetav1.GetOptions{Uid: usrRef.Uid})
	if err != nil {
		if !grpcerr.IsNotFound(err) {
			return nil, s.errInternalErr(err)
		}
		return nil, s.errUnauthenticatedErr(err)
	}

	if usr.Spec.IsDisabled {
		return nil, s.errPermissionDenied("User is deactivated")
	}

	if usr.Status.IsLocked {
		return nil, s.errPermissionDenied("User is locked")
	}

	return usr, nil
}

func (s *server) errUnauthenticated(format string, a ...any) error {
	s.logGRPCErr(errors.Errorf(format, a...))
	return grpcutils.Unauthenticated("")
}

func (s *server) errUnauthenticatedErr(err error) error {
	s.logGRPCErr(err)
	return grpcutils.Unauthenticated("")
}

func (s *server) errInvalidArg(format string, a ...any) error {
	s.logGRPCErr(errors.Errorf(format, a...))
	return grpcutils.InvalidArg("")
}

func (s *server) errInvalidArgErr(err error) error {
	s.logGRPCErr(err)
	return grpcutils.InvalidArg("")
}

func (s *server) errPermissionDenied(format string, a ...any) error {
	s.logGRPCErr(errors.Errorf(format, a...))
	return grpcutils.PermissionDenied("")
}

func (s *server) errPermissionDeniedErr(err error) error {
	s.logGRPCErr(err)
	return grpcutils.PermissionDenied("")
}

func (s *server) errAlreadyExists(format string, a ...any) error {
	s.logGRPCErr(errors.Errorf(format, a...))
	return grpcutils.AlreadyExists("")
}

func (s *server) errAlreadyExistsErr(err error) error {
	s.logGRPCErr(err)
	return grpcutils.AlreadyExists("")
}

func (s *server) errInternal(format string, a ...any) error {
	s.logGRPCErr(errors.Errorf(format, a...))
	return grpcutils.Internal("")
}

func (s *server) errInternalErr(err error) error {
	s.logGRPCErr(err)
	return grpcutils.Internal("")
}

func (s *server) errNotFound(format string, a ...any) error {
	s.logGRPCErr(errors.Errorf(format, a...))
	return grpcutils.NotFound("")
}

func (s *server) errNotFoundErr(err error) error {
	s.logGRPCErr(err)
	return grpcutils.NotFound("")
}

func (s *server) logGRPCErr(err error) {
	zap.L().Debug("grpcErr", zap.Error(err), zap.String("errCode", status.Code(err).String()))
}

func (s *server) setCookiesGRPC(ctx context.Context, cookies []*http.Cookie) error {
	md := make(metadata.MD)
	var cookieStrs []string
	for _, cookie := range cookies {
		cookieStrs = append(cookieStrs, cookie.String())
	}
	md["set-cookie"] = cookieStrs

	if err := grpc.SetHeader(ctx, md); err != nil {
		return err
	}

	return nil
}

func (s *server) doAuthenticateWithAuthenticator(ctx context.Context,
	req *authv1.AuthenticateWithAuthenticatorRequest) (*authv1.SessionToken, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.validateChallengeResponse(req.ChallengeResponse); err != nil {
		return nil, err
	}

	if !s.needsReAuth(sess) {
		return nil, s.errAlreadyExists("The Session is valid and does not need a authenticatorFinish")
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	authInfo, err := s.doAuthenticateAuthenticator(ctx, cc, req, usr, sess)
	if err != nil {
		return nil, err
	}

	authn, err := s.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
		Uid: authInfo.GetAuthenticator().AuthenticatorRef.Uid,
	})
	if err != nil {
		return nil, err
	}

	switch {
	case authn.Status.DeviceRef != nil && sess.Status.DeviceRef == nil:
		sess.Status.DeviceRef = authn.Status.DeviceRef
	case authn.Status.DeviceRef != nil && sess.Status.DeviceRef != nil:
		if authn.Status.DeviceRef.Uid != sess.Status.DeviceRef.Uid {
			return nil, grpcutils.PermissionDenied("Invalid Device")
		}
	case authn.Status.DeviceRef == nil && sess.Status.DeviceRef != nil:
		authn.Status.DeviceRef = sess.Status.DeviceRef
		_, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
		if err != nil {
			return nil, grpcutils.InternalWithErr(err)
		}
	}

	s.setCurrAuthenticationGRPC(ctx, sess, cc, authInfo)
	sess.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET

	if sess.Status.RequiredAuthenticatorRef == nil {
		switch authn.Status.Type {
		case corev1.Authenticator_Status_TPM, corev1.Authenticator_Status_FIDO:
			sess.Status.RequiredAuthenticatorRef = umetav1.GetObjectReference(authn)
		}
	}

	if _, err := s.octeliumC.CoreC().UpdateSession(ctx, sess); err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	ret, err := s.generateSessionTokenResponse(ctx, sess)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *server) mustGetSessionTypeFromUserAgent(ctx context.Context) corev1.Session_Status_Type {

	if ua := grpcutils.GetHeaderValueMust(ctx, "User-Agent"); ua != "" {
		switch {
		case strings.HasPrefix(ua, "octelium-cli"):
			return corev1.Session_Status_CLIENT
		case strings.HasPrefix(ua, "octelium-sdk"):
			return corev1.Session_Status_CLIENTLESS
		}
	}

	return corev1.Session_Status_CLIENTLESS
}
