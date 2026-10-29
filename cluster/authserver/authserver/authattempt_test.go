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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rpubsubv1"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/authevents"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

type authFailureSub struct {
	ch chan *authevents.Failure
}

func newAuthFailureSub(t *testing.T, srv *server) *authFailureSub {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stream, err := srv.octeliumC.PubSubC().Subscribe(ctx, &rpubsubv1.SubscribeRequest{
		Topic: []byte(authevents.TopicFailure),
		Group: []byte(utilrand.GetRandomStringCanonical(8)),
	})
	assert.Nil(t, err)

	_, err = stream.Recv()
	assert.Nil(t, err)

	ret := &authFailureSub{
		ch: make(chan *authevents.Failure, 100),
	}

	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				return
			}

			for _, msg := range resp.Messages {
				failure, err := authevents.ParseFailure(msg)
				if err != nil {
					continue
				}
				ret.ch <- failure
			}
		}
	}()

	srv.authEvents.Run(ctx)

	return ret
}

func (s *authFailureSub) next(t *testing.T) *authevents.Failure {
	t.Helper()

	select {
	case failure := <-s.ch:
		return failure
	case <-time.After(10 * time.Second):
		t.Fatalf("Timed out while waiting for an authentication failure")
		return nil
	}
}

func (s *authFailureSub) none(t *testing.T) {
	t.Helper()

	select {
	case failure := <-s.ch:
		t.Fatalf("Unexpected authentication failure: %+v", failure)
	case <-time.After(1 * time.Second):
	}
}

func getAuthFailureCtx(refreshToken string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{
		"x-octelium-refresh-token": refreshToken,
		"user-agent":               "octelium-cli/1.2.3 linux",
	}))
}

func TestAuthFailureRefreshToken(t *testing.T) {
	ctx := context.Background()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	authSrv := &authMainSvc{s: srv}
	sub := newAuthFailureSub(t, srv)

	{
		_, err := authSrv.AuthenticateWithRefreshToken(getAuthFailureCtx("invalid"),
			&authv1.AuthenticateWithRefreshTokenRequest{})
		assert.NotNil(t, err)
		sub.none(t)
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		testInvalidateAccessToken(t, srv.octeliumC, usrT.Session)

		resp, err := authSrv.AuthenticateWithRefreshToken(getAuthFailureCtx(usrT.GetAccessToken().RefreshToken),
			&authv1.AuthenticateWithRefreshTokenRequest{})
		assert.Nil(t, err)
		sub.none(t)

		_, err = authSrv.AuthenticateWithRefreshToken(getAuthFailureCtx(usrT.GetAccessToken().RefreshToken),
			&authv1.AuthenticateWithRefreshTokenRequest{})
		assert.NotNil(t, err)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonRevokedCredential, failure.Reason)
		assert.Equal(t, corev1.Session_Status_Authentication_Info_REFRESH_TOKEN, failure.Info.GetType())
		assert.Equal(t, usrT.Session.Metadata.Uid, failure.SessionRef.GetUid())
		assert.Equal(t, usrT.Usr.Metadata.Uid, failure.UserRef.GetUid())
		assert.Equal(t, "octelium-cli/1.2.3 linux", failure.Info.GetDownstream().GetUserAgent())
		assert.Equal(t, "1.2.3", failure.Info.GetDownstream().GetClientVersion())
		assert.True(t, time.Since(failure.CreatedAt) < time.Minute)

		sess, err := srv.getSessionFromRefreshToken(ctx, resp.RefreshToken)
		assert.Nil(t, err)
		sess.Status.IsLocked = true
		_, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = authSrv.AuthenticateWithRefreshToken(getAuthFailureCtx(resp.RefreshToken),
			&authv1.AuthenticateWithRefreshTokenRequest{})
		assert.NotNil(t, err)

		failure = sub.next(t)
		assert.Equal(t, authevents.ReasonRevokedCredential, failure.Reason)
		assert.Equal(t, sess.Metadata.Uid, failure.SessionRef.GetUid())
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		usrT.Usr.Spec.IsDisabled = true
		_, err = srv.octeliumC.CoreC().UpdateUser(ctx, usrT.Usr)
		assert.Nil(t, err)

		_, err = authSrv.AuthenticateWithRefreshToken(getAuthFailureCtx(usrT.GetAccessToken().RefreshToken),
			&authv1.AuthenticateWithRefreshTokenRequest{})
		assert.NotNil(t, err)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonUserDeactivated, failure.Reason)
		assert.Equal(t, usrT.Usr.Metadata.Uid, failure.UserRef.GetUid())
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		for range maxAuthenticationsPerHour {
			usrT.Session.Status.LastAuthentications = append(usrT.Session.Status.LastAuthentications,
				&corev1.Session_Status_Authentication{SetAt: pbutils.Now()})
		}
		_, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
		assert.Nil(t, err)

		_, err = authSrv.AuthenticateWithRefreshToken(getAuthFailureCtx(usrT.GetAccessToken().RefreshToken),
			&authv1.AuthenticateWithRefreshTokenRequest{})
		assert.NotNil(t, err)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonLimitExceeded, failure.Reason)
		assert.Equal(t, usrT.Session.Metadata.Uid, failure.SessionRef.GetUid())
	}
}

func TestAuthFailureAuthenticationToken(t *testing.T) {
	ctx := context.Background()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	authSrv := &authMainSvc{s: srv}
	sub := newAuthFailureSub(t, srv)

	usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
	assert.Nil(t, err)

	newToken := func(mutate func(*corev1.Credential)) (*corev1.Credential, string) {
		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usrT.Usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENT,
				ExpiresAt:   pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		if mutate != nil {
			cred, err = srv.octeliumC.CoreC().GetCredential(ctx,
				apivalidation.ObjectReferenceToRGetOptions(umetav1.GetObjectReference(cred)))
			assert.Nil(t, err)
			mutate(cred)
			cred, err = srv.octeliumC.CoreC().UpdateCredential(ctx, cred)
			assert.Nil(t, err)
		}

		return cred, tknResp.GetAuthenticationToken().AuthenticationToken
	}

	{
		_, err := authSrv.AuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: utilrand.GetRandomString(64),
		})
		assert.NotNil(t, err)
		sub.none(t)
	}

	{
		_, tkn := newToken(nil)
		_, err := authSrv.AuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: tkn,
		})
		assert.Nil(t, err)
		sub.none(t)
	}

	{
		cred, tkn := newToken(func(cred *corev1.Credential) {
			cred.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(-1 * time.Minute))
		})
		_, err := authSrv.AuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: tkn,
		})
		assert.NotNil(t, err)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonExpiredCredential, failure.Reason)
		assert.Equal(t, corev1.Session_Status_Authentication_Info_CREDENTIAL, failure.Info.GetType())
		assert.Equal(t, cred.Metadata.Uid, failure.Info.GetCredential().GetCredentialRef().GetUid())
		assert.Equal(t, cred.Metadata.Name, failure.Info.GetCredential().GetCredentialRef().GetName())
		assert.Equal(t, corev1.Credential_Spec_AUTH_TOKEN, failure.Info.GetCredential().GetType())
		assert.Equal(t, "", failure.Info.GetCredential().GetTokenID())
		assert.Equal(t, usrT.Usr.Metadata.Uid, failure.UserRef.GetUid())
		assert.Nil(t, failure.SessionRef)
	}

	{
		cred, tkn := newToken(func(cred *corev1.Credential) {
			cred.Spec.IsDisabled = true
		})
		_, err := authSrv.AuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: tkn,
		})
		assert.NotNil(t, err)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonRevokedCredential, failure.Reason)
		assert.Equal(t, cred.Metadata.Uid, failure.Info.GetCredential().GetCredentialRef().GetUid())
	}

	{
		cred, tkn := newToken(nil)
		_, err := srv.octeliumC.CoreC().DeleteCredential(ctx, apivalidation.ObjectToRDeleteOptions(cred))
		assert.Nil(t, err)

		_, err = authSrv.AuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: tkn,
		})
		assert.NotNil(t, err)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonRevokedCredential, failure.Reason)
		assert.Equal(t, cred.Metadata.Uid, failure.Info.GetCredential().GetCredentialRef().GetUid())
		assert.Nil(t, failure.UserRef)
	}
}

func TestAuthFailureAuthenticator(t *testing.T) {
	ctx := context.Background()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	authSrv := &authMainSvc{s: srv}
	sub := newAuthFailureSub(t, srv)

	usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
	assert.Nil(t, err)

	authn, err := srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Authenticator_Spec{
			State: corev1.Authenticator_Spec_ACTIVE,
		},
		Status: &corev1.Authenticator_Status{
			UserRef: umetav1.GetObjectReference(usrT.Usr),
			Type:    corev1.Authenticator_Status_TOTP,
		},
	})
	assert.Nil(t, err)

	_, err = authSrv.AuthenticateWithAuthenticator(getAuthFailureCtx(usrT.GetAccessToken().RefreshToken),
		&authv1.AuthenticateWithAuthenticatorRequest{
			AuthenticatorRef: umetav1.GetObjectReference(authn),
			ChallengeResponse: &authv1.ChallengeResponse{
				Type: &authv1.ChallengeResponse_Totp{
					Totp: &authv1.ChallengeResponse_TOTP{
						Response: "123456",
					},
				},
			},
		})
	assert.NotNil(t, err)

	failure := sub.next(t)
	assert.Equal(t, authevents.ReasonNotAllowed, failure.Reason)
	assert.Equal(t, corev1.Session_Status_Authentication_Info_AUTHENTICATOR, failure.Info.GetType())
	assert.Equal(t, authn.Metadata.Uid, failure.Info.GetAuthenticator().GetAuthenticatorRef().GetUid())
	assert.Equal(t, corev1.Authenticator_Status_TOTP, failure.Info.GetAuthenticator().GetType())
	assert.Equal(t, corev1.Session_Status_Authentication_Info_Authenticator_DEFAULT,
		failure.Info.GetAuthenticator().GetMode())
	assert.Equal(t, usrT.Session.Metadata.Uid, failure.SessionRef.GetUid())
	assert.Equal(t, usrT.Usr.Metadata.Uid, failure.UserRef.GetUid())

	_, err = authSrv.AuthenticateWithAuthenticator(getAuthFailureCtx(usrT.GetAccessToken().RefreshToken),
		&authv1.AuthenticateWithAuthenticatorRequest{
			AuthenticatorRef: umetav1.GetObjectReference(authn),
		})
	assert.NotNil(t, err)

	failure = sub.next(t)
	assert.Equal(t, authevents.ReasonInvalidCredential, failure.Reason)
	assert.Equal(t, usrT.Session.Metadata.Uid, failure.SessionRef.GetUid())
}

func TestAuthFailureCallback(t *testing.T) {
	ctx := context.Background()
	srv, adminSrv := newCallbackTestEnv(t)
	sub := newAuthFailureSub(t, srv)

	usrReq := tstuser.GenUserHuman(nil)
	usrReq.Spec.Email = fmt.Sprintf("%s@example.com", usrReq.Metadata.Name)
	usr, err := adminSrv.CreateUser(ctx, usrReq)
	assert.Nil(t, err)

	p := &callbackTestProvider{
		idp: &corev1.IdentityProvider{
			ApiVersion: "core/v1",
			Kind:       "IdentityProvider",
			Metadata:   &metav1.Metadata{Name: "test-idp", Uid: utilrand.GetRandomStringCanonical(36)},
			Spec:       &corev1.IdentityProvider_Spec{},
			Status:     &corev1.IdentityProvider_Status{Type: corev1.IdentityProvider_Status_OIDC},
		},
	}
	newState := func() *loginState {
		state := &loginState{
			ID:    newStateID(),
			UID:   p.idp.Metadata.Uid,
			Login: &utils.GetLoginResponse{},
		}
		assert.Nil(t, srv.saveLoginState(ctx, state))
		return state
	}

	doCallback := func(state *loginState, query string) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/callback?"+query, nil)
		req.AddCookie(&http.Cookie{Name: "octelium_login_state", Value: state.ID})
		req.Header.Set("User-Agent", "Mozilla/5.0")
		w := httptest.NewRecorder()
		srv.webProvidersC.Lock()
		srv.webProvidersC.connectors = []utils.Provider{p}
		srv.webProvidersC.Unlock()
		srv.handleAuthCallback(w, req)
		assert.Equal(t, http.StatusSeeOther, w.Code)
	}

	setInfo := func(identifier, email string) {
		p.err = nil
		p.info = &corev1.Session_Status_Authentication_Info{
			Type: corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER,
			Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
				IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
					IdentityProviderRef: umetav1.GetObjectReference(p.idp),
					Identifier:          identifier,
					Email:               email,
					Type:                corev1.IdentityProvider_Status_OIDC,
				},
			},
		}
	}

	{
		doCallback(&loginState{ID: newStateID()}, "state="+newStateID())
		sub.none(t)
	}

	{
		setInfo(usr.Metadata.Name, usr.Spec.Email)
		p.err = errors.New("invalid authorization code")
		state := newState()
		doCallback(state, "state="+state.ID)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonInvalidCredential, failure.Reason)
		assert.Equal(t, corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER, failure.Info.GetType())
		assert.Equal(t, p.idp.Metadata.Uid, failure.Info.GetIdentityProvider().GetIdentityProviderRef().GetUid())
		assert.Equal(t, corev1.IdentityProvider_Status_OIDC, failure.Info.GetIdentityProvider().GetType())
		assert.Equal(t, "", failure.Info.GetIdentityProvider().GetIdentifier())
		assert.Equal(t, "Mozilla/5.0", failure.Info.GetDownstream().GetUserAgent())
		assert.Nil(t, failure.UserRef)

		doCallback(state, "state="+state.ID)
		sub.none(t)
	}

	{
		setInfo("unknown", "unknown@example.com")
		state := newState()
		doCallback(state, "state="+state.ID)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonUserNotFound, failure.Reason)
		assert.Equal(t, "unknown", failure.Info.GetIdentityProvider().GetIdentifier())
		assert.Equal(t, "unknown@example.com", failure.Info.GetIdentityProvider().GetEmail())
		assert.Nil(t, failure.UserRef)
	}

	{
		usr.Spec.IsDisabled = true
		usr, err = srv.octeliumC.CoreC().UpdateUser(ctx, usr)
		assert.Nil(t, err)

		setInfo(usr.Metadata.Name, usr.Spec.Email)
		state := newState()
		doCallback(state, "state="+state.ID)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonUserDeactivated, failure.Reason)
		assert.Equal(t, usr.Metadata.Uid, failure.UserRef.GetUid())

		usr.Spec.IsDisabled = false
		usr, err = srv.octeliumC.CoreC().UpdateUser(ctx, usr)
		assert.Nil(t, err)
	}

	{
		state := newState()
		doCallback(state, url.Values{
			"state":             {state.ID},
			"error":             {"access_denied"},
			"error_description": {"The user denied the request"},
		}.Encode())

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonIdentityProviderError, failure.Reason)
		assert.Equal(t, p.idp.Metadata.Uid, failure.Info.GetIdentityProvider().GetIdentityProviderRef().GetUid())

		res, err := srv.getLoginStateFromStateID(ctx, state.ID)
		assert.Nil(t, err)
		assert.Equal(t, state.ID, res.ID)
	}

	{
		doCallback(&loginState{ID: newStateID()}, url.Values{
			"state": {newStateID()},
			"error": {"access_denied"},
		}.Encode())
		sub.none(t)
	}

	{
		setInfo(usr.Metadata.Name, usr.Spec.Email)
		state := newState()
		doCallback(state, "state="+state.ID)
		sub.none(t)
	}
}

func TestAuthFailureOAuth2(t *testing.T) {
	ctx := context.Background()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	sub := newAuthFailureSub(t, srv)

	usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
		corev1.User_Spec_WORKLOAD, corev1.Session_Status_CLIENTLESS)
	assert.Nil(t, err)

	cred, clientID, clientSecret := newOAuth2Credential(t, ctx, adminSrv, usrT.Usr.Metadata.Name)

	{
		res := doOAuth2TokenReq(t, srv, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {clientID},
			"client_secret": {utilrand.GetRandomString(64)},
		})
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
		sub.none(t)
	}

	{
		res := doOAuth2TokenReq(t, srv, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"invalid"},
			"client_secret": {clientSecret},
		})
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonInvalidCredential, failure.Reason)
		assert.Equal(t, corev1.Session_Status_Authentication_Info_CREDENTIAL, failure.Info.GetType())
		assert.Equal(t, cred.Metadata.Uid, failure.Info.GetCredential().GetCredentialRef().GetUid())
		assert.Equal(t, corev1.Credential_Spec_OAUTH2, failure.Info.GetCredential().GetType())
		assert.Equal(t, usrT.Usr.Metadata.Uid, failure.UserRef.GetUid())
	}

	{
		res := doOAuth2TokenReq(t, srv, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {clientID},
			"client_secret": {clientSecret},
		})
		assert.Equal(t, http.StatusOK, res.statusCode)
		sub.none(t)
	}

	{
		usrT.Usr.Status.IsLocked = true
		_, err := srv.octeliumC.CoreC().UpdateUser(ctx, usrT.Usr)
		assert.Nil(t, err)

		res := doOAuth2TokenReq(t, srv, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {clientID},
			"client_secret": {clientSecret},
		})
		assert.Equal(t, http.StatusBadRequest, res.statusCode)

		failure := sub.next(t)
		assert.Equal(t, authevents.ReasonUserLocked, failure.Reason)
		assert.Equal(t, usrT.Usr.Metadata.Uid, failure.UserRef.GetUid())
	}
}
