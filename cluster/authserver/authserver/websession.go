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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/sessionc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"go.uber.org/zap"
)

func (s *server) createOrUpdateSessWeb(r *http.Request,
	usr *corev1.User, authResp *corev1.Session_Status_Authentication_Info,
	cc *corev1.ClusterConfig, idp *corev1.IdentityProvider) (*corev1.Session, error) {
	ctx := r.Context()

	doCreate := func() (*corev1.Session, error) {
		return s.createWebSession(ctx,
			usr, authResp, cc, idp,
			r.Header.Get("User-Agent"), r.Header.Get("X-Forwarded-For"))
	}

	sess, err := s.getWebSessionFromHTTPRefreshCookie(r)
	if err != nil {
		zap.L().Debug("Could not get Session from refresh token. Creating a new webSession", zap.Error(err))
		return doCreate()
	}

	deleteSess := func() {

		_, err := s.octeliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{
			Uid: sess.Metadata.Uid,
		})
		if err != nil {
			zap.L().Debug("Could not delete old web Session",
				zap.String("name", sess.Metadata.Name), zap.Error(err))
		}
	}

	if authResp.GetIdentityProvider() == nil || authResp.GetIdentityProvider().IdentityProviderRef == nil ||
		sess.Status.InitialAuthentication == nil || sess.Status.InitialAuthentication.Info.GetIdentityProvider() == nil ||
		sess.Status.InitialAuthentication.Info.GetIdentityProvider().IdentityProviderRef == nil {
		// This shouldn't be happening in production
		deleteSess()
		return doCreate()
	}
	if authResp.GetIdentityProvider().IdentityProviderRef.Uid !=
		sess.Status.InitialAuthentication.Info.GetIdentityProvider().IdentityProviderRef.Uid {
		deleteSess()
		return doCreate()
	}

	zap.L().Debug("Rotating the token for the Session",
		zap.String("sess", sess.Metadata.Name))
	s.setCurrAuthentication(sess, authResp, r.Header.Get("User-Agent"), cc, r.Header.Get("X-Forwarded-For"))

	if authResp.GetIdentityProvider() != nil && authResp.GetIdentityProvider().PicURL != "" {
		sess.Metadata.PicURL = authResp.GetIdentityProvider().PicURL
	}

	authenticatorAction, err := s.getAuthenticatorAction(ctx, cc, idp, usr, sess)
	if err != nil {
		return nil, err
	}

	sess.Status.AuthenticatorAction = authenticatorAction

	sess, err = s.octeliumC.CoreC().UpdateSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	return sess, nil
}

func (s *server) createWebSession(ctx context.Context, usr *corev1.User,
	authRespInfo *corev1.Session_Status_Authentication_Info,
	cc *corev1.ClusterConfig, idp *corev1.IdentityProvider, userAgent string, xff string) (*corev1.Session, error) {

	var err error
	if err := s.checkMaxSessionsPerUser(ctx, usr, cc); err != nil {
		return nil, err
	}

	opts := &sessionc.CreateSessionOpts{
		OcteliumC:          s.octeliumC,
		ClusterConfig:      cc,
		Usr:                usr,
		AuthenticationInfo: authRespInfo,
		SessType:           corev1.Session_Status_CLIENTLESS,
		IsBrowser:          true,
		UserAgent:          userAgent,
		XFF:                xff,
		RequiredAuthenticatorRef: func() *metav1.ObjectReference {
			if authRespInfo != nil &&
				authRespInfo.GetAuthenticator() != nil &&
				authRespInfo.GetAuthenticator().Type == corev1.Authenticator_Status_FIDO &&
				authRespInfo.GetAuthenticator().Mode ==
					corev1.Session_Status_Authentication_Info_Authenticator_PASSKEY {
				return authRespInfo.GetAuthenticator().AuthenticatorRef
			}

			return nil
		}(),
	}

	initSess, err := sessionc.NewSession(ctx, opts)
	if err != nil {
		return nil, err
	}

	authenticatorAction, err := s.getAuthenticatorAction(ctx, cc, idp, usr, initSess)
	if err != nil {
		return nil, err
	}

	initSess.Status.AuthenticatorAction = authenticatorAction

	sess, err := s.octeliumC.CoreC().CreateSession(ctx, initSess)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	return sess, nil
}

func (s *server) getAuthenticatorAction(ctx context.Context,
	cc *corev1.ClusterConfig,
	idp *corev1.IdentityProvider,
	usr *corev1.User,
	sess *corev1.Session) (corev1.Session_Status_AuthenticatorAction, error) {
	if cc.Spec.Authenticator == nil {
		return corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, nil
	}

	if len(cc.Spec.Authenticator.AuthenticationEnforcementRules) == 0 &&
		len(cc.Spec.Authenticator.RegistrationEnforcementRules) == 0 {
		return corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, nil
	}

	r, err := s.getAvailableAuthenticators(ctx, sess, usr)
	if err != nil {
		return corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, err
	}

	authnList, err := s.octeliumC.CoreC().ListAuthenticator(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterStatusUserUID(usr.Metadata.Uid),
		},
	})
	if err != nil {
		return corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, s.errInternalErr(err)
	}

	if len(r.AvailableAuthenticators) > 0 {
		if len(cc.Spec.Authenticator.AuthenticationEnforcementRules) > 0 {
			switch s.doAuthenticatorEnforcementRule(ctx,
				cc.Spec.Authenticator.AuthenticationEnforcementRules, idp, usr, sess, authnList) {
			case corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE:
				return corev1.Session_Status_AUTHENTICATION_REQUIRED, nil
			case corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_IGNORE:
				return corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, nil
			case corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_RECOMMEND:
				return corev1.Session_Status_AUTHENTICATION_RECOMMENDED, nil
			default:
				return corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, nil
			}
		}
		return corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, nil
	}

	if len(cc.Spec.Authenticator.RegistrationEnforcementRules) > 0 {
		switch s.doAuthenticatorEnforcementRule(ctx,
			cc.Spec.Authenticator.RegistrationEnforcementRules, idp, usr, sess, authnList) {
		case corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE:
			return corev1.Session_Status_REGISTRATION_REQUIRED, nil
		case corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_IGNORE:
			return corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, nil
		case corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_RECOMMEND:
			return corev1.Session_Status_REGISTRATION_RECOMMENDED, nil
		default:
			return corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, nil
		}
	}

	return corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET, nil
}

func (s *server) setCurrAuthenticationGRPC(ctx context.Context, sess *corev1.Session, cc *corev1.ClusterConfig, authInfo *corev1.Session_Status_Authentication_Info) {
	s.setCurrAuthentication(sess, authInfo,
		grpcutils.GetHeaderValueMust(ctx, "User-Agent"), cc,
		grpcutils.GetHeaderValueMust(ctx, "X-Forwarded-For"))
}

func (s *server) setCurrAuthentication(sess *corev1.Session, authInfo *corev1.Session_Status_Authentication_Info, userAgent string, cc *corev1.ClusterConfig, xff string) {
	sessionc.SetCurrAuthentication(&sessionc.SetCurrAuthenticationOpts{
		Session:       sess,
		ClusterConfig: cc,
		AuthInfo:      authInfo,
		UserAgent:     userAgent,
		XFF:           xff,
	})
}
