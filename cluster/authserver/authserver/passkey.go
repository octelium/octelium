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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators/fido"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (s *server) doAuthenticateWithPasskey(ctx context.Context,
	req *authv1.AuthenticateWithPasskeyRequest) (*authv1.SessionToken, error) {

	if err := s.checkGRPCRequestIsWeb(ctx); err != nil {
		return nil, err
	}

	cc := s.ccCtl.Get()
	if cc.Spec.Authenticator == nil || !cc.Spec.Authenticator.EnablePasskeyLogin {
		return nil, s.errPermissionDenied("Passkey login is not enabled")
	}

	usr, authn, cred, query, err := s.doAuthenticationWithPasskey(ctx, req.Response)
	if err != nil {
		zap.L().Debug("Could not doAuthenticationWithPasskey", zap.Error(err))
		return nil, grpcutils.Unauthorized("Invalid authentication")
	}

	authInfo := &corev1.Session_Status_Authentication_Info{
		Type: corev1.Session_Status_Authentication_Info_AUTHENTICATOR,
		Details: &corev1.Session_Status_Authentication_Info_Authenticator_{
			Authenticator: &corev1.Session_Status_Authentication_Info_Authenticator{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
				Type:             corev1.Authenticator_Status_FIDO,
				Info: &corev1.Session_Status_Authentication_Info_Authenticator_Info{
					Type: &corev1.Session_Status_Authentication_Info_Authenticator_Info_Fido{
						Fido: s.getSessionAuthenticatorInfoFIDO(cred, authn),
					},
				},
				Mode: corev1.Session_Status_Authentication_Info_Authenticator_PASSKEY,
			},
		},
	}

	if err := s.doPostAuthenticatorAuthenticationRules(ctx, cc, authn, nil, usr, authInfo); err != nil {
		return nil, s.errPermissionDeniedErr(err)
	}

	if err := s.checkMaxSessionsPerUser(ctx, usr, cc); err != nil {
		return nil, err
	}

	sess, err := s.createWebSession(ctx,
		usr, authInfo, cc, nil,
		grpcutils.GetHeaderValueMust(ctx, "user-agent"),
		grpcutils.GetHeaderValueMust(ctx, "x-forwarded-for"))
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	if query != "" {
		zap.L().Debug("Got query in doAuthenticateWithPasskey", zap.String("val", query))
		callbackURL, isApp, err := s.generateCallbackURL(query)
		if err == nil {
			if err := s.saveAuthenticatorCallbackState(ctx, sess, &loginState{
				CallbackURL: callbackURL,
				IsApp:       isApp,
			}); err != nil {
				zap.L().Warn("Could not saveAuthenticatorCallbackState", zap.Error(err))
			}
		} else {
			zap.L().Debug("Could not generateCallbackURL", zap.Error(err))
		}
	}

	zap.L().Debug("doAuthenticateWithPasskey is successful",
		zap.Any("sess", sess), zap.Any("authn", authn))

	return s.generateSessionTokenResponse(ctx, sess)
}

func (s *server) doAuthenticateWithPasskeyBegin(ctx context.Context,
	req *authv1.AuthenticateWithPasskeyBeginRequest) (*authv1.AuthenticateWithPasskeyBeginResponse, error) {

	if req.Query != "" {
		if err := validateLoginQuery(req.Query); err != nil {
			return nil, s.errInvalidArg("Invalid query")
		}
	}

	if err := s.checkGRPCRequestIsWeb(ctx); err != nil {
		return nil, err
	}

	cc := s.ccCtl.Get()
	if cc.Spec.Authenticator == nil || !cc.Spec.Authenticator.EnablePasskeyLogin {
		return nil, s.errPermissionDenied("Passkey login is not enabled")
	}

	assertion, sess, err := s.passkeyCtl.BeginDiscoverableLogin()
	if err != nil {
		return nil, err
	}
	requestOptsBytes, err := json.Marshal(assertion.Response)
	if err != nil {
		return nil, err
	}

	if err := s.savePasskeyState(ctx, &passkeyState{
		Session: sess,
		Query:   req.Query,
	}); err != nil {
		return nil, err
	}

	return &authv1.AuthenticateWithPasskeyBeginResponse{
		Request: string(requestOptsBytes),
	}, nil
}

func (s *server) checkGRPCRequestIsWeb(ctx context.Context) error {

	if grpcutils.GetHeaderValueMust(ctx, "origin") != s.rootURL {
		return s.errInvalidArg("Invalid origin")
	}

	if err := apivalidation.ValidateBrowserUserAgent(grpcutils.GetHeaderValueMust(ctx, "user-agent")); err != nil {
		return s.errInvalidArg("Invalid User Agent")
	}

	return nil
}

func (s *server) doAuthenticationWithPasskey(ctx context.Context,
	response string) (*corev1.User, *corev1.Authenticator, *webauthn.Credential, string, error) {

	retErr := func(err error) (*corev1.User, *corev1.Authenticator, *webauthn.Credential, string, error) {
		return nil, nil, nil, "", err
	}

	lenResp := len(response)
	if lenResp < 100 || lenResp > 5000 {
		return retErr(errors.Errorf("Invalid response length"))
	}
	if !govalidator.IsASCII(response) {
		return retErr(errors.Errorf("Invalid response"))
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(
		strings.NewReader(response))
	if err != nil {
		return retErr(err)
	}

	state, err := s.loadPasskeyState(ctx, parsedResponse.Response.CollectedClientData.Challenge)
	if err != nil {
		return retErr(err)
	}

	var authn *corev1.Authenticator
	var usr *corev1.User

	getWebauthnUser := func(rawID, userHandle []byte) (user webauthn.User, err error) {
		authn, err = s.rscCache.GetAuthenticatorByCredID(rawID)
		if err != nil {
			return nil, err
		}

		usr, err = s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid: authn.Status.UserRef.Uid,
		})
		if err != nil {
			return nil, err
		}

		webauthnUser := fido.NewWebAuthnUsr(authn, usr)

		if !utils.SecureBytesEqual(webauthnUser.WebAuthnID(), userHandle) {
			return nil, errors.Errorf("Incorrect userHandle")
		}

		return webauthnUser, nil
	}

	cred, err := s.passkeyCtl.ValidateDiscoverableLogin(getWebauthnUser, *state.Session, parsedResponse)
	if err != nil {
		return retErr(err)
	}

	if usr == nil {
		return retErr(errors.Errorf("User not set by getWebauthnUser"))
	}

	if authn == nil {
		return retErr(errors.Errorf("Authenticator not set by getWebauthnUser"))
	}

	return usr, authn, cred, state.Query, nil
}

type passkeyState struct {
	Session *webauthn.SessionData
	Query   string
}

func (s *server) savePasskeyState(ctx context.Context, state *passkeyState) error {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return err
	}

	if _, err := s.octeliumC.CacheC().SetCache(ctx, &rcachev1.SetCacheRequest{
		Key:  []byte(getPasskeyKey(state.Session.Challenge)),
		Data: stateBytes,
		Duration: &metav1.Duration{
			Type: &metav1.Duration_Minutes{
				Minutes: 2,
			},
		},
	}); err != nil {
		return err
	}

	return nil
}

func (s *server) loadPasskeyState(ctx context.Context, challenge string) (*passkeyState, error) {
	lenChallenge := len(challenge)

	if lenChallenge < 32 || lenChallenge > 64 {
		return nil, s.errInvalidArg("Invalid challenge length")
	}
	if !govalidator.IsASCII(challenge) {
		return nil, s.errInvalidArg("Invalid challenge")
	}

	res, err := s.octeliumC.CacheC().GetCache(ctx, &rcachev1.GetCacheRequest{
		Key:    []byte(getPasskeyKey(challenge)),
		Delete: true,
	})
	if err != nil {
		return nil, err
	}

	ret := &passkeyState{}
	if err := json.Unmarshal(res.Data, ret); err != nil {
		zap.L().Warn("Could not unmarshal json of loginState from cache", zap.Error(err))
		return nil, errors.Errorf("Invalid or expired state. Please try again.")
	}

	return ret, nil
}

func getPasskeyKey(challenge string) string {
	return fmt.Sprintf("octelium:passkey:%s", challenge)
}
