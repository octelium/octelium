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

package harness

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

const refreshTokenHeader = "x-octelium-refresh-token"

type AuthSessionOpts struct {
	User          *corev1.User
	UserType      corev1.User_Spec_Type
	SessionType   corev1.Session_Status_Type
	Authorization *corev1.User_Spec_Authorization
}

type AuthSession struct {
	h *H

	User       *corev1.User
	Credential *corev1.Credential

	name  string
	c     authv1.MainServiceClient
	token *authv1.SessionToken
}

func (h *H) NewAuthSession(t *testing.T, o AuthSessionOpts) *AuthSession {
	t.Helper()

	usr := o.User
	if usr == nil {
		usrType := o.UserType
		if usrType == corev1.User_Spec_TYPE_UNKNOWN {
			usrType = corev1.User_Spec_WORKLOAD
		}

		usr = h.CreateUser(t, &corev1.User{
			Spec: &corev1.User_Spec{
				Type:          usrType,
				Authorization: o.Authorization,
			},
		})
	}

	sessType := o.SessionType
	if sessType == corev1.Session_Status_TYPE_UNKNOWN {
		sessType = corev1.Session_Status_CLIENTLESS
	}

	cred := h.CreateCredential(t, CredentialOpts{
		User:        usr.Metadata.Name,
		Type:        corev1.Credential_Spec_AUTH_TOKEN,
		SessionType: sessType,
	})

	authnToken := h.CredentialToken(t, cred).GetAuthenticationToken()
	if authnToken == nil {
		t.Fatalf("The Credential %s did not yield an authentication token",
			cred.Metadata.Name)
	}

	ret := &AuthSession{
		h:          h,
		User:       usr,
		Credential: cred,
		c:          h.AuthC(t),
	}

	tkn, err := ret.c.AuthenticateWithAuthenticationToken(t.Context(),
		&authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: authnToken.AuthenticationToken,
		})
	if err != nil {
		t.Fatalf("Could not authenticate the User %s: %+v", usr.Metadata.Name, err)
	}
	if tkn.RefreshToken == "" {
		t.Fatalf("The User %s authenticated without a refresh token", usr.Metadata.Name)
	}
	ret.token = tkn
	ret.name = ret.resolveName(t)

	zap.L().Debug("Created AuthSession fixture",
		zap.String("user", usr.Metadata.Name),
		zap.String("session", ret.name),
		zap.String("sessionType", sessType.String()))

	return ret
}

func (a *AuthSession) resolveName(t *testing.T) string {
	t.Helper()

	for _, sess := range a.h.UserSessions(t, a.User) {
		if sess.Status.CredentialRef != nil &&
			sess.Status.CredentialRef.Uid == a.Credential.Metadata.Uid {
			return sess.Metadata.Name
		}
	}

	t.Fatalf("The Credential %s of the User %s did not create a Session",
		a.Credential.Metadata.Name, a.User.Metadata.Name)
	return ""
}

func (a *AuthSession) C() authv1.MainServiceClient { return a.c }

func (a *AuthSession) Token() *authv1.SessionToken { return a.token }

func (a *AuthSession) SetToken(tkn *authv1.SessionToken) { a.token = tkn }

func (a *AuthSession) Ctx(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, refreshTokenHeader, a.token.RefreshToken)
}

func (a *AuthSession) Name() string { return a.name }

func (a *AuthSession) Session(t *testing.T) *corev1.Session {
	t.Helper()

	return a.h.GetSession(t, a.name)
}
