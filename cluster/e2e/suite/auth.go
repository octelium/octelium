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

package suite

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

func testAuthenticationAssertion(t *testing.T, h *harness.H) {
	const issuer = "https://issuer.e2e.octelium.internal"

	audience := fmt.Sprintf("https://%s", h.Domain)

	oidc := harness.NewAssertionIssuer(t, issuer)

	idp := h.CreateIdentityProvider(t, &corev1.IdentityProvider{
		Spec: &corev1.IdentityProvider_Spec{
			DisplayName: "e2e assertion issuer",
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
					Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksContent{
						JwksContent: oidc.JWKS,
					},
					Issuer:   issuer,
					Audience: audience,
				},
			},
		},
	})

	subject := fmt.Sprintf("spiffe://e2e/%s", h.Name())

	usr := h.CreateUser(t, &corev1.User{
		Spec: &corev1.User_Spec{
			Type: corev1.User_Spec_WORKLOAD,
			Authentication: &corev1.User_Spec_Authentication{
				Identities: []*corev1.User_Spec_Authentication_Identity{
					{
						IdentityProvider: idp.Metadata.Name,
						Identifier:       subject,
					},
				},
			},
			Authorization: &corev1.User_Spec_Authorization{
				InlinePolicies: harness.InlineAllowAny("allow"),
			},
		},
	})

	svc := h.NewPublicService(t, "default")

	authC := h.AuthC(t)

	authenticate := func(ctx context.Context,
		assertion string, scopes []string) (*authv1.SessionToken, error) {
		return authC.AuthenticateWithAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
			Assertion: assertion,
			Scopes:    scopes,
		})
	}

	t.Run("ValidAssertion", func(t *testing.T) {
		tkn, err := authenticate(t.Context(), oidc.Token(t, harness.AssertionClaims{
			Subject:  subject,
			Audience: audience,
		}), nil)
		require.Nil(t, err, "a valid assertion should authenticate")
		require.NotEmpty(t, tkn.AccessToken)

		h.WaitAllowed(t, h.ServiceClient(svc, tkn.AccessToken))

		sessions := h.UserSessions(t, usr)
		require.True(t, len(sessions) > 0)

		sess := sessions[len(sessions)-1]
		info := sess.Status.Authentication.Info

		assert.Equal(t, corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER, info.Type)
		require.NotNil(t, info.GetIdentityProvider())
		assert.Equal(t, subject, info.GetIdentityProvider().Identifier)
		assert.Equal(t, idp.Metadata.Name, info.GetIdentityProvider().IdentityProviderRef.Name)
	})

	t.Run("WrongIssuerRejected", func(t *testing.T) {
		_, err := authenticate(t.Context(), oidc.Token(t, harness.AssertionClaims{
			Subject:  subject,
			Audience: audience,
			Issuer:   "https://attacker.example.com",
		}), nil)
		assert.NotNil(t, err, "an assertion from an unexpected issuer must be rejected")
	})

	t.Run("WrongAudienceRejected", func(t *testing.T) {
		_, err := authenticate(t.Context(), oidc.Token(t, harness.AssertionClaims{
			Subject:  subject,
			Audience: "https://somewhere.else.example.com",
		}), nil)
		assert.NotNil(t, err, "an assertion minted for another audience must be rejected")
	})

	t.Run("UnknownSubjectRejected", func(t *testing.T) {
		_, err := authenticate(t.Context(), oidc.Token(t, harness.AssertionClaims{
			Subject:  "spiffe://e2e/nobody",
			Audience: audience,
		}), nil)
		assert.NotNil(t, err, "an assertion for an unmapped identity must be rejected")
	})

	t.Run("ExpiredAssertionRejected", func(t *testing.T) {
		_, err := authenticate(t.Context(), oidc.Token(t, harness.AssertionClaims{
			Subject:  subject,
			Audience: audience,
			Expiry:   -10 * time.Minute,
		}), nil)
		assert.NotNil(t, err, "an expired assertion must be rejected")
	})

	t.Run("ForeignKeyRejected", func(t *testing.T) {
		other := harness.NewAssertionIssuer(t, issuer)

		_, err := authenticate(t.Context(), other.Token(t, harness.AssertionClaims{
			Subject:  subject,
			Audience: audience,
		}), nil)
		assert.NotNil(t, err, "an assertion signed by an untrusted key must be rejected")
	})

	t.Run("Scopes", func(t *testing.T) {
		other := h.NewPublicService(t, "default")

		other.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow-service"),
		}
		other = h.UpdateService(t, other)

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow-service"),
		}
		svc = h.UpdateService(t, svc)

		tkn, err := authenticate(t.Context(), oidc.Token(t, harness.AssertionClaims{
			Subject:  subject,
			Audience: audience,
		}), []string{fmt.Sprintf("service:%s", svc.Metadata.Name)})
		require.Nil(t, err)

		h.WaitAllowed(t, h.ServiceClient(svc, tkn.AccessToken))

		h.WaitDenied(t, h.ServiceClient(other, tkn.AccessToken))
	})
}

func testAuthenticationSession(t *testing.T, h *harness.H) {
	svc := h.NewPublicService(t, "default")

	usr := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
		InlinePolicies: harness.InlineAllowAny("allow"),
	})

	t.Run("Revocation", func(t *testing.T) {
		token := h.AccessToken(t, usr)
		c := h.ServiceClient(svc, token)

		h.WaitAllowed(t, c)

		sessions := h.UserSessions(t, usr)
		require.True(t, len(sessions) > 0)

		h.DeleteSession(t, sessions[len(sessions)-1])

		elapsed := h.Within(t, "the revoked Session to be rejected", harness.DecisionBudget,
			func(ctx context.Context) error {
				got, err := h.StatusOf(ctx, c, "/")
				if err != nil {
					return err
				}
				if got == http.StatusOK {
					return errStillAllowed
				}
				if got != http.StatusUnauthorized && got != http.StatusForbidden {
					return errors.Errorf("unexpected status %d after revocation", got)
				}
				return nil
			})

		zap.L().Info("Session revocation propagation", zap.Duration("elapsed", elapsed))
		assert.Less(t, elapsed, propagationBudget,
			"revoking a Session took %s, budget is %s", elapsed, propagationBudget)
	})

	t.Run("PendingByDefault", func(t *testing.T) {
		scoped := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow"),
		})

		scoped.Spec.Session = &corev1.User_Spec_Session{
			DefaultState: corev1.Session_Spec_PENDING,
		}
		scoped = h.UpdateUser(t, scoped)

		token := h.AccessToken(t, scoped)
		c := h.ServiceClient(svc, token)

		h.WaitDenied(t, c)

		sessions := h.UserSessions(t, scoped)
		require.True(t, len(sessions) > 0)

		sess := sessions[len(sessions)-1]
		assert.Equal(t, corev1.Session_Spec_PENDING, sess.Spec.State)

		sess.Spec.State = corev1.Session_Spec_ACTIVE
		h.UpdateSession(t, sess)

		h.WaitAllowed(t, c)
	})

	t.Run("MaxPerUser", func(t *testing.T) {
		scoped := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow"),
		})

		scoped.Spec.Session = &corev1.User_Spec_Session{MaxPerUser: 1}
		scoped = h.UpdateUser(t, scoped)

		newCredential := func(t *testing.T) *corev1.Credential {
			t.Helper()
			return h.CreateCredential(t, harness.CredentialOpts{
				User:        scoped.Metadata.Name,
				Type:        corev1.Credential_Spec_ACCESS_TOKEN,
				SessionType: corev1.Session_Status_CLIENTLESS,
			})
		}

		first := h.CredentialToken(t, newCredential(t))
		require.NotNil(t, first.GetAccessToken())

		h.WaitAllowed(t, h.ServiceClient(svc, first.GetAccessToken().AccessToken))

		require.Equal(t, 1, len(h.UserSessions(t, scoped)))

		_, err := h.CoreC().GenerateCredentialToken(t.Context(),
			&corev1.GenerateCredentialTokenRequest{
				CredentialRef: umetav1.GetObjectReference(newCredential(t)),
			})
		assert.NotNil(t, err, "exceeding maxPerUser should be refused")

		assert.Equal(t, 1, len(h.UserSessions(t, scoped)),
			"a refused authentication must not leave a Session behind")
	})
}

func testAuthenticationRefresh(t *testing.T, h *harness.H) {
	svc := h.NewPublicService(t, "default")

	usr := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
		InlinePolicies: harness.InlineAllowAny("allow"),
	})

	cred := h.CreateCredential(t, harness.CredentialOpts{
		User:        usr.Metadata.Name,
		Type:        corev1.Credential_Spec_AUTH_TOKEN,
		SessionType: corev1.Session_Status_CLIENTLESS,
	})

	credToken := h.CredentialToken(t, cred).GetAuthenticationToken()
	require.NotNil(t, credToken)

	authC := h.AuthC(t)
	first, err := authC.AuthenticateWithAuthenticationToken(t.Context(),
		&authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: credToken.AuthenticationToken,
		})
	require.Nil(t, err)
	require.NotEmpty(t, first.AccessToken)
	require.NotEmpty(t, first.RefreshToken)

	h.WaitAllowed(t, h.ServiceClient(svc, first.AccessToken))

	sessions := h.UserSessions(t, usr)
	require.Equal(t, 1, len(sessions))

	before := sessions[0]
	require.NotNil(t, before.Status)
	require.NotNil(t, before.Status.Authentication)

	refreshCtx := metadata.AppendToOutgoingContext(t.Context(),
		"x-octelium-refresh-token", first.RefreshToken)
	second, err := authC.AuthenticateWithRefreshToken(refreshCtx,
		&authv1.AuthenticateWithRefreshTokenRequest{})
	require.Nil(t, err)
	require.NotEmpty(t, second.AccessToken)
	require.NotEmpty(t, second.RefreshToken)
	assert.NotEqual(t, first.AccessToken, second.AccessToken)
	assert.NotEqual(t, first.RefreshToken, second.RefreshToken)

	h.WaitAllowed(t, h.ServiceClient(svc, second.AccessToken))

	rotated := h.Within(t, "the rotated access token to invalidate the previous token",
		harness.DecisionBudget, func(ctx context.Context) error {
			got, err := h.StatusOf(ctx, h.ServiceClient(svc, first.AccessToken), "/")
			if err != nil {
				return err
			}
			if got != http.StatusUnauthorized && got != http.StatusForbidden {
				return errors.Errorf("the previous access token returned status %d", got)
			}
			return nil
		})

	zap.L().Info("Access token rotation propagation", zap.Duration("elapsed", rotated))
	assert.Less(t, rotated, propagationBudget,
		"rotating an access token took %s, budget is %s", rotated, propagationBudget)

	_, err = authC.AuthenticateWithRefreshToken(refreshCtx,
		&authv1.AuthenticateWithRefreshTokenRequest{})
	require.NotNil(t, err)
	assert.True(t, grpcerr.IsUnauthenticated(err),
		"the previous refresh token returned an unexpected error: %+v", err)

	after := h.GetSession(t, before.Metadata.Name)
	require.NotNil(t, after.Status)
	require.NotNil(t, after.Status.Authentication)
	require.NotNil(t, after.Status.Authentication.Info)
	assert.Equal(t, corev1.Session_Status_Authentication_Info_REFRESH_TOKEN,
		after.Status.Authentication.Info.Type)
	assert.Equal(t, before.Status.TotalAuthentications+1,
		after.Status.TotalAuthentications)
	assert.NotEqual(t, before.Status.Authentication.TokenID,
		after.Status.Authentication.TokenID)
	require.True(t, len(after.Status.LastAuthentications) > 0)
	assert.Equal(t, before.Status.Authentication.TokenID,
		after.Status.LastAuthentications[0].TokenID)

	h.DeleteSession(t, after)

	newRefreshCtx := metadata.AppendToOutgoingContext(t.Context(),
		"x-octelium-refresh-token", second.RefreshToken)
	_, err = authC.AuthenticateWithRefreshToken(newRefreshCtx,
		&authv1.AuthenticateWithRefreshTokenRequest{})
	require.NotNil(t, err)
	assert.True(t, grpcerr.IsUnauthenticated(err),
		"a refresh token for a deleted Session returned an unexpected error: %+v", err)
}
