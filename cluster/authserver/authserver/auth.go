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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/gosimple/slug"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	vutils "github.com/octelium/octelium/pkg/utils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type postAuthReq struct {
	UID       string `json:"uid"`
	Query     string `json:"query"`
	UserAgent string `json:"userAgent"`
}

type postAuthResp struct {
	LoginURL string `json:"loginURL"`
}

func (s *server) validatePostAuthReq(i *postAuthReq) error {
	if i == nil {
		return errors.Errorf("Nil object")
	}

	if err := apivalidation.ValidateBrowserUserAgent(i.UserAgent); err != nil {
		return errors.Errorf("Invalid user agent")
	}

	if i.Query != "" {
		if err := validateLoginQuery(i.Query); err != nil {
			return err
		}
	}

	if err := apivalidation.DoCheckUID(i.UID); err != nil {
		return err
	}

	return nil
}

func validateLoginQuery(arg string) error {

	if len(arg) > 1000 {
		return errors.Errorf("Query is too long")
	}

	vals, err := url.ParseQuery(arg)
	if err != nil {
		return err
	}

	if val := vals.Get("octelium_req"); val != "" {
		if _, err := getLoginReq(val); err != nil {
			return err
		}
	}

	return nil
}

func getLoginReq(arg string) (*authv1.ClientLoginRequest, error) {
	if arg == "" {
		return nil, errors.Errorf("Empty login req")
	}
	if len(arg) > 512 {
		return nil, errors.Errorf("Invalid login req")
	}

	reqBytes, err := base64.RawURLEncoding.DecodeString(arg)
	if err != nil {
		return nil, err
	}
	ret := &authv1.ClientLoginRequest{}
	if err := pbutils.Unmarshal(reqBytes, ret); err != nil {
		return nil, err
	}

	if ret.ApiVersion != authv1.ClientLoginRequest_V1 {
		return nil, errors.Errorf("Unsupported API version")
	}
	if ret.CallbackPort < 20000 || ret.CallbackPort > 65000 {
		return nil, errors.Errorf("invalid callback port")
	}

	if !govalidator.IsASCII(ret.CallbackSuffix) || !govalidator.IsByteLength(ret.CallbackSuffix, 4, 8) {
		return nil, errors.Errorf("invalid callback suffix")
	}

	return ret, nil
}

func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	{
		hdr := r.Header.Get("X-Octelium-Origin")
		if hdr == "" {
			zap.L().Debug("X-Octelium-Origin header is not set")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if hdr != s.rootURL {
			zap.L().Debug("X-Octelium-Origin header does not match", zap.String("val", hdr))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(b) > 512 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var req postAuthReq
	if err := json.Unmarshal(b, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := s.validatePostAuthReq(&req); err != nil {
		zap.L().Debug("Could not validatePostAuthReq", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Header.Get("user-agent") != req.UserAgent {
		zap.L().Debug("user-agent header does not match")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	provider, err := s.getWebProviderFromUID(req.UID)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	loginState, err := s.doGenerateLoginState(ctx, provider, req.Query, w, r)
	if err != nil {
		if grpcerr.IsInternal(err) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(postAuthResp{
		LoginURL: loginState.LoginURL,
	})

}

func (s *server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {

	doRedirect := func(err error) {
		zap.L().Debug("Auth callback error", zap.Error(err))

		http.Redirect(w, r, s.rootURL, http.StatusSeeOther)
	}

	ctx := r.Context()

	userState, err := s.getLoginStateFromCallback(r)
	if err != nil {
		zap.L().Debug("Could not get login state", zap.Error(err))
		doRedirect(err)
		return
	}

	zap.L().Debug("Got login state", zap.Any("loginState", userState))

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		doRedirect(err)
		return
	}

	provider, err := s.getWebProviderFromUID(userState.UID)
	if err != nil {
		doRedirect(err)
		return
	}

	idp := provider.Provider()

	authInfo, err := provider.HandleCallback(r, userState.RequestID)
	if err != nil {
		zap.L().Debug("Could not handleCallback", zap.Error(err))
		doRedirect(err)
		return
	}

	zap.L().Debug("Successful IdentityProvider authentication", zap.Any("authInfo", authInfo))

	usr, err := s.authenticateUser(ctx, authInfo, idp)
	if err != nil {
		zap.L().Debug("Could not authenticateUser", zap.Error(err))
		doRedirect(err)
		return
	}

	zap.L().Debug("Successful authenticateUser", zap.Any("user", usr))

	if err := s.doPostAuthenticationRules(ctx, idp, usr, authInfo); err != nil {
		doRedirect(err)
		return
	}

	sess, err := s.createOrUpdateSessWeb(r, usr, authInfo, cc, idp)
	if err != nil {
		doRedirect(err)
		return
	}

	if err := s.setAuthCallbackResponse(r, w, userState, sess); err != nil {
		zap.L().Debug("Could not setAuthCallbackResponse", zap.Error(err))
		doRedirect(err)
		return
	}
}

func (s *server) setAuthCallbackResponse(r *http.Request, w http.ResponseWriter,
	state *loginState, sess *corev1.Session) error {

	ctx := r.Context()
	accessToken, err := s.generateAccessToken(sess)
	if err != nil {
		return err
	}

	refreshToken, err := s.generateRefreshToken(sess)
	if err != nil {
		return err
	}

	switch sess.Status.AuthenticatorAction {
	case corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET:
	case corev1.Session_Status_AUTHENTICATION_REQUIRED,
		corev1.Session_Status_AUTHENTICATION_RECOMMENDED:
		if err := s.saveAuthenticatorCallbackState(ctx, sess, state); err != nil {
			return err
		}

		s.setLoginCookies(w, accessToken, refreshToken, sess)
		s.redirectToAuthenticatorAuthenticate(w, r)
		return nil
	case corev1.Session_Status_REGISTRATION_REQUIRED,
		corev1.Session_Status_REGISTRATION_RECOMMENDED:
		if err := s.saveAuthenticatorCallbackState(ctx, sess, state); err != nil {
			return err
		}

		s.setLoginCookies(w, accessToken, refreshToken, sess)
		s.redirectToAuthenticatorRegister(w, r)
	default:
		return errors.Errorf("Unhandled authenticatorAction")
	}

	if state != nil && !state.IsApp {
		s.setLoginCookies(w, accessToken, refreshToken, sess)
		if state.CallbackURL != "" {
			s.redirectToCallbackSuccess(w, r, state.CallbackURL)
		} else {
			s.redirectToCallbackSuccess(w, r, s.getPortalURL())
		}

		return nil
	}

	u, err := s.generateClientCallbackURL(ctx, sess, state.CallbackURL)
	if err != nil {
		return err
	}

	s.setLoginCookies(w, accessToken, refreshToken, sess)
	s.redirectToCallbackSuccess(w, r, u.String())
	return nil
}

func (s *server) generateClientCallbackURL(ctx context.Context,
	sess *corev1.Session, callbackURL string) (*url.URL, error) {
	srv := admin.NewServer(&admin.Opts{
		OcteliumC:  s.octeliumC,
		IsEmbedded: true,
	})

	cred, err := srv.CreateCredential(ctx, &corev1.Credential{
		Metadata: &metav1.Metadata{
			Name:           fmt.Sprintf("auth-token-%s", utilrand.GetRandomStringLowercase(8)),
			IsSystem:       true,
			IsSystemHidden: true,
			IsUserHidden:   true,
		},
		Spec: &corev1.Credential_Spec{
			MaxAuthentications: 1,
			ExpiresAt:          pbutils.Timestamp(time.Now().Add(1 * time.Minute)),
			User:               sess.Status.UserRef.Name,
			Type:               corev1.Credential_Spec_AUTH_TOKEN,
			SessionType:        corev1.Session_Status_CLIENT,
			AutoDelete:         true,
		},
	})
	if err != nil {
		return nil, err
	}

	tokenResp, err := srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
		CredentialRef: umetav1.GetObjectReference(cred),
	})
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(callbackURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()

	loginResp := &authv1.ClientLoginResponse{
		AuthenticationToken: tokenResp.GetAuthenticationToken().AuthenticationToken,
	}
	respBytes, err := pbutils.Marshal(loginResp)
	if err != nil {
		return nil, errors.Errorf("Could not generate JWT cookie %+v", err)
	}

	q.Set("octelium_response", base64.RawURLEncoding.EncodeToString(respBytes))
	u.RawQuery = q.Encode()

	return u, nil
}

func (s *server) authenticateUser(ctx context.Context,
	authInfo *corev1.Session_Status_Authentication_Info, idp *corev1.IdentityProvider) (*corev1.User, error) {

	info := authInfo.GetIdentityProvider()

	if info == nil {
		return nil, errors.Errorf("Nil IdentityProvider details")
	}

	if info.Identifier == "" {
		return nil, errors.Errorf("Empty identifier")
	}

	usrs, err := s.octeliumC.CoreC().ListUser(ctx, &rmetav1.ListOptions{
		SpecLabels: map[string]string{
			fmt.Sprintf("auth-%s", info.IdentityProviderRef.Name): slug.Make(info.Identifier),
		},
	})
	if err != nil {
		return nil, errors.Errorf("Internal error")
	}

	var usr *corev1.User

	switch len(usrs.Items) {
	case 1:
		usr = usrs.Items[0]
		userAccount := func() *corev1.User_Spec_Authentication_Identity {
			if usr.Spec.Authentication == nil {
				return nil
			}
			for _, acc := range usr.Spec.Authentication.Identities {
				if acc.IdentityProvider == info.IdentityProviderRef.Name {
					return acc
				}
			}
			return nil
		}()

		if userAccount == nil {
			return nil, errors.Errorf("The User authentication account does not exist")
		}

		if !vutils.SecureStringEqual(userAccount.Identifier, info.Identifier) {
			return nil, errors.Errorf("The User identifier does not match the account")
		}
	case 0:
		disableEmailAsIdentity := idp.Spec.DisableEmailAsIdentity
		if info.Email != "" && govalidator.IsEmail(info.Email) && !disableEmailAsIdentity {
			usrs, err := s.octeliumC.CoreC().ListUser(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{
					urscsrv.FilterFieldEQValStr("spec.email", info.Email),
				},
			})
			if err != nil {
				return nil, err
			}
			if len(usrs.Items) == 0 {
				return nil, errors.Errorf("This User does not exist")
			}
			if len(usrs.Items) != 1 {
				zap.L().Warn("Multiple Users are assigned to the same email", zap.Any("usrList", (usrs)))
				return nil, errors.Errorf("This User does not exist")
			}
			usr = usrs.Items[0]

			// Double check
			if usr.Spec.Email != info.Email {
				return nil, errors.Errorf("The User email does not match the provider info")
			}
		}
	default:
		zap.L().Warn("Multiple Users are assigned to the same identifier",
			zap.Any("usrList", (usrs)), zap.Any("idp", idp))
		return nil, errors.Errorf("This User does not exist")
	}

	if usr == nil {
		return nil, errors.Errorf("This User does not exist")
	}

	if usr.Spec.IsDisabled {
		return nil, errors.Errorf("Deactivated User")
	}

	if usr.Spec.Type != corev1.User_Spec_HUMAN {
		return nil, errors.Errorf("Invalid User type")
	}

	return usr, nil
}

func (s *server) setLoginCookies(w http.ResponseWriter, accessToken, refreshToken string, sess *corev1.Session) {

	http.SetCookie(w, &http.Cookie{
		Name:     "octelium_auth",
		Value:    accessToken,
		Secure:   true,
		HttpOnly: true,
		Domain:   s.domain,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToGo()),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "octelium_rt",
		Value:    refreshToken,
		Secure:   true,
		HttpOnly: true,
		Domain:   s.domain,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(umetav1.ToDuration(sess.Status.Authentication.RefreshTokenDuration).ToGo()),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "octelium_login_state",
		Value:    "",
		Secure:   true,
		HttpOnly: true,
		Domain:   s.domain,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
	})

}

func (s *server) setLogoutCookies(w http.ResponseWriter) {

	cookies := s.getLogoutCookies()
	for _, cookie := range cookies {
		http.SetCookie(w, cookie)
	}
}

func (s *server) getLogoutCookies() []*http.Cookie {
	return []*http.Cookie{

		{
			Name:     "octelium_auth",
			Value:    "",
			Secure:   true,
			Domain:   s.domain,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		},
		{
			Name:     "octelium_rt",
			Value:    "",
			Secure:   true,
			Domain:   s.domain,
			Path:     "/",
			SameSite: http.SameSiteLaxMode,
		},
		{
			Name:     "octelium_login_state",
			Value:    "",
			Secure:   true,
			HttpOnly: true,
			Domain:   s.domain,
			Path:     "/",
			SameSite: http.SameSiteNoneMode,
		},
	}
}

func (s *server) doGenerateLoginState(ctx context.Context,
	provider utils.Provider, query string, w http.ResponseWriter, r *http.Request) (*loginState, error) {

	state := utilrand.GetRandomString(36)

	loginURL, reqID, err := provider.LoginURL(state)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	userState := &loginState{
		ID:        state,
		UID:       provider.Provider().Metadata.Uid,
		RequestID: reqID,
		LoginURL:  loginURL,
	}

	if query == "" {
		query = r.URL.Query().Encode()
	}

	getRedirectURL := func(urlVals url.Values) string {
		if redirect := urlVals.Get("redirect"); redirect != "" && s.isURLSameClusterOrigin(redirect) {
			return redirect
		}

		return ""
	}

	if query != "" {
		queryVals, err := url.ParseQuery(query)
		if err != nil {
			return nil, grpcutils.InvalidArg("")
		}
		if val := queryVals.Get("octelium_req"); val != "" {
			loginReq, err := getLoginReq(val)
			if err != nil {
				return nil, grpcutils.InvalidArg("")
			}

			userState.CallbackURL = fmt.Sprintf("http://localhost:%d/callback/success/%s",
				loginReq.CallbackPort, loginReq.CallbackSuffix)

			userState.IsApp = true
		}

		if userState.CallbackURL == "" {
			userState.CallbackURL = getRedirectURL(queryVals)
		}
	}

	if userState.CallbackURL == "" {
		userState.CallbackURL = getRedirectURL(r.URL.Query())
	}

	zap.L().Debug("Creating a new login state", zap.Any("state", userState))

	if err := s.saveLoginState(ctx, userState); err != nil {
		return nil, err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "octelium_login_state",
		Value:    state,
		Secure:   true,
		HttpOnly: true,
		Domain:   s.domain,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
		Expires:  time.Now().Add(time.Minute * 15),
	})

	return userState, nil
}

func (s *server) generateCallbackURL(query string) (string, bool, error) {
	getRedirectURL := func(urlVals url.Values) string {
		if redirect := urlVals.Get("redirect"); redirect != "" && s.isURLSameClusterOrigin(redirect) {
			return redirect
		}

		return ""
	}

	if query == "" {
		return "", false, nil
	}

	var callbackURL string
	var isApp bool

	queryVals, err := url.ParseQuery(query)
	if err != nil {
		return "", false, grpcutils.InvalidArg("Could not parse query: %s", query)
	}
	if val := queryVals.Get("octelium_req"); val != "" {
		loginReq, err := getLoginReq(val)
		if err != nil {
			return "", false, grpcutils.InvalidArg("Invalid octelium_req")
		}

		callbackURL = fmt.Sprintf("http://localhost:%d/callback/success/%s",
			loginReq.CallbackPort, loginReq.CallbackSuffix)

		isApp = true
	}

	if callbackURL == "" {
		callbackURL = getRedirectURL(queryVals)
	}

	return callbackURL, isApp, nil
}

func (s *server) handleAuthSuccess(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	sess, err := s.getWebSessionFromHTTPRefreshCookie(r)
	if err != nil {
		s.redirectToLogin(w, r)
		return
	}

	if sess.Status.Authentication != nil &&
		sess.Status.Authentication.Info != nil &&
		sess.Status.Authentication.Info.GetAuthenticator() != nil {
		zap.L().Debug("Starting loadAuthenticatorCallbackState")
		if state, err := s.loadAuthenticatorCallbackState(ctx, sess); err == nil {
			if !state.IsApp {
				if state.CallbackURL != "" {
					s.redirectToCallbackSuccess(w, r, state.CallbackURL)
				} else {
					s.redirectToCallbackSuccess(w, r, s.getPortalURL())
				}
				return
			}

			u, err := s.generateClientCallbackURL(ctx, sess, state.CallbackURL)
			if err != nil {
				zap.L().Debug("Could not generateClientCallbackURL", zap.Error(err))
				s.redirectToCallbackSuccess(w, r, s.getPortalURL())
				return
			}

			s.redirectToCallbackSuccess(w, r, u.String())
			return
		} else {
			zap.L().Debug("Could not loadAuthenticatorCallbackState", zap.Error(err))
		}
	}

	redirectURL := r.FormValue("redirect")
	if redirectURL == "" {
		s.redirectToPortal(w, r)
		return
	}

	if !s.isURLSameClusterOrigin(redirectURL) {
		u, err := url.Parse(redirectURL)
		if err != nil {
			s.redirectToPortal(w, r)
			return
		}

		if u.Hostname() != "localhost" {
			s.redirectToPortal(w, r)
			return
		}
	}

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (s *server) doPostAuthenticationRules(ctx context.Context,
	idp *corev1.IdentityProvider, usr *corev1.User, authInfo *corev1.Session_Status_Authentication_Info) error {

	if len(idp.Spec.PostAuthenticationRules) == 0 {
		return nil
	}
	inputMap := map[string]any{
		"ctx": map[string]any{
			"user":               pbutils.MustConvertToMap(usr),
			"identityProvider":   pbutils.MustConvertToMap(idp),
			"authenticationInfo": pbutils.MustConvertToMap(authInfo),
		},
	}

	for _, rule := range idp.Spec.PostAuthenticationRules {
		isMatched, err := s.celEngine.EvalCondition(ctx, rule.Condition, inputMap)
		if err != nil {
			zap.L().Debug("Could not eval postAuthentication condition", zap.Error(err))
			continue
		}

		if isMatched {
			switch rule.Effect {
			case corev1.IdentityProvider_Spec_PostAuthenticationRule_ALLOW:
				return nil
			case corev1.IdentityProvider_Spec_PostAuthenticationRule_DENY:
				return errors.Errorf("Denied by postAuthentication rule")
			}
		}
	}

	return nil
}

func (s *server) handleAuthenticatorAuthenticate(w http.ResponseWriter, r *http.Request) {
	sess, err := s.getWebSessionFromHTTPRefreshCookie(r)
	if err != nil {
		s.redirectToLogin(w, r)
		return
	}

	switch sess.Status.AuthenticatorAction {
	case corev1.Session_Status_AUTHENTICATION_REQUIRED:
		s.renderLoggedIn(w)
	case corev1.Session_Status_REGISTRATION_REQUIRED:
		s.redirectToAuthenticatorRegister(w, r)
	default:
		// s.redirectToPortal(w, r)
		s.renderLoggedIn(w)
	}
}

func (s *server) handleAuthenticatorList(w http.ResponseWriter, r *http.Request) {
	_, err := s.getWebSessionFromHTTPRefreshCookie(r)
	if err != nil {
		s.redirectToLogin(w, r)
		return
	}

	s.renderLoggedIn(w)
}

func (s *server) handleDenied(w http.ResponseWriter, r *http.Request) {
	_, err := s.getWebSessionFromHTTPRefreshCookie(r)
	if err != nil {
		s.redirectToLogin(w, r)
		return
	}

	s.renderLoggedIn(w)
}

func (s *server) handleAuthenticatorRegister(w http.ResponseWriter, r *http.Request) {
	sess, err := s.getWebSessionFromHTTPRefreshCookie(r)
	if err != nil {
		s.redirectToLogin(w, r)
		return
	}

	switch sess.Status.AuthenticatorAction {
	case corev1.Session_Status_REGISTRATION_REQUIRED:
		s.renderLoggedIn(w)
	case corev1.Session_Status_AUTHENTICATION_REQUIRED:
		s.redirectToAuthenticatorAuthenticate(w, r)
	default:
		s.renderLoggedIn(w)
	}
}

func (s *server) doAuthenticatorEnforcementRule(ctx context.Context,
	rules []*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule,
	idp *corev1.IdentityProvider,
	usr *corev1.User, sess *corev1.Session,
	authnList *corev1.AuthenticatorList) corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_Effect {

	inputMap := map[string]any{
		"ctx": map[string]any{
			"user":              pbutils.MustConvertToMap(usr),
			"identityProvider":  pbutils.MustConvertToMap(idp),
			"session":           pbutils.MustConvertToMap(sess),
			"authenticatorList": pbutils.MustConvertToMap(authnList),
		},
	}

	for _, rule := range rules {
		isMatched, err := s.celEngine.EvalCondition(ctx, rule.Condition, inputMap)
		if err != nil {
			zap.L().Debug("Could not eval postAuthentication condition", zap.Error(err))
			continue
		}

		if isMatched {
			return rule.Effect
		}
	}

	return corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_EFFECT_UNKNOWN
}

func (s *server) checkSessionValid(sess *corev1.Session) error {
	if !ucorev1.ToSession(sess).IsValid() {
		return s.errPermissionDenied("Old Access Token. Please re-authenticate")
	}

	if sess.Status.IsLocked {
		return s.errPermissionDenied("Session is locked")
	}

	switch sess.Status.AuthenticatorAction {
	case corev1.Session_Status_AUTHENTICATION_REQUIRED:
		return s.errPermissionDenied("Authenticator authentication is required")
	}

	return nil
}
