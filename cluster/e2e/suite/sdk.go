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
	"net/http"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/octelium-go"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const authzBudget = 20 * time.Second

func testSDK(t *testing.T, h *harness.H) {
	ctx := t.Context()

	usr := h.CreateWorkloadUser(t, nil)

	svc := h.CreateService(t, &corev1.Service{
		Spec: &corev1.Service_Spec{
			Mode:     corev1.Service_Spec_HTTP,
			IsPublic: true,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Container_{
						Container: &corev1.Service_Spec_Config_Upstream_Container{
							Image: "nginx",
							Port:  80,
						},
					},
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	cred := h.CreateCredential(t, harness.CredentialOpts{
		User:        usr.Metadata.Name,
		Type:        corev1.Credential_Spec_AUTH_TOKEN,
		SessionType: corev1.Session_Status_CLIENTLESS,
	})

	tkn := h.CredentialToken(t, cred)

	oC, err := octelium.NewClient(ctx,
		octelium.WithDomain(h.Domain),
		octelium.WithAuthenticator(
			octelium.AuthenticationToken(tkn.GetAuthenticationToken().AuthenticationToken)))
	require.Nil(t, err)

	grpcC, err := oC.Conn(ctx)
	require.Nil(t, err)

	uC := corev1.NewMainServiceClient(grpcC)

	setPolicies := func(t *testing.T, policies ...string) {
		t.Helper()

		usr.Spec.Authorization = &corev1.User_Spec_Authorization{Policies: policies}
		usr = h.UpdateUser(t, usr)
	}

	t.Run("UnauthorizedByDefault", func(t *testing.T) {
		_, err := uC.ListUser(ctx, &corev1.ListUserOptions{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthorized(err))
	})

	t.Run("ReadOnlyPolicy", func(t *testing.T) {
		setPolicies(t, "octelium-api-read-only")

		h.Eventually(t, "the read-only API Policy to take effect", authzBudget,
			func(ctx context.Context) error {
				_, err := uC.ListUser(ctx, &corev1.ListUserOptions{})
				return err
			})

		_, err := uC.CreateUser(ctx, &corev1.User{
			Metadata: newMetadata(),
			Spec:     &corev1.User_Spec{Type: corev1.User_Spec_WORKLOAD},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthorized(err))
	})

	t.Run("FullAccessPolicy", func(t *testing.T) {
		setPolicies(t, "octelium-api-full-access")

		h.Eventually(t, "the full-access API Policy to take effect", authzBudget,
			func(ctx context.Context) error {
				_, err := uC.CreateUser(ctx, &corev1.User{
					Metadata: newMetadata(),
					Spec:     &corev1.User_Spec{Type: corev1.User_Spec_WORKLOAD},
				})
				return err
			})
	})

	t.Run("DenyAllPolicy", func(t *testing.T) {
		setPolicies(t, "deny-all")

		h.Eventually(t, "the deny-all Policy to take effect", authzBudget,
			func(ctx context.Context) error {
				_, err := uC.ListUser(ctx, &corev1.ListUserOptions{})
				if err == nil {
					return errStillAllowed
				}
				if !grpcerr.IsUnauthorized(err) {
					return err
				}
				return nil
			})
	})

	t.Run("AccessTokenAgainstService", func(t *testing.T) {
		setPolicies(t, "allow-all")

		var accessToken string
		h.Eventually(t, "an access token for the allow-all User", authzBudget,
			func(ctx context.Context) error {
				var err error
				accessToken, err = oC.AccessToken(ctx)
				return err
			})

		h.Eventually(t, "the Service to allow the access token", authzBudget,
			func(ctx context.Context) error {
				res, err := h.HTTPPublicToken(svc.Metadata.Name, accessToken).R().Get("/")
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
				}
				return nil
			})

		t.Run("HTTPReadOnlyPolicy", func(t *testing.T) {
			setPolicies(t, "http-read-only")

			h.Eventually(t, "the http-read-only Policy to take effect", authzBudget,
				func(ctx context.Context) error {
					res, err := h.HTTPPublicToken(svc.Metadata.Name, accessToken).R().Post("/")
					if err != nil {
						return err
					}
					if res.StatusCode() != http.StatusForbidden {
						return errUnexpectedStatus(res.StatusCode(), http.StatusForbidden)
					}
					return nil
				})

			h.CheckPublicToken(t, svc.Metadata.Name, accessToken)

			for _, fn := range []func() (int, error){
				func() (int, error) {
					res, err := h.HTTPPublicToken(svc.Metadata.Name, accessToken).R().Put("/")
					return res.StatusCode(), err
				},
				func() (int, error) {
					res, err := h.HTTPPublicToken(svc.Metadata.Name, accessToken).R().Delete("/")
					return res.StatusCode(), err
				},
			} {
				code, err := fn()
				assert.Nil(t, err)
				assert.Equal(t, http.StatusForbidden, code)
			}
		})
	})
}
