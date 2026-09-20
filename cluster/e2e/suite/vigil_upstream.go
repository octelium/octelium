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
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

func bearerAuth(secretName string) *corev1.Service_Spec_Config_HTTP_Auth {
	return &corev1.Service_Spec_Config_HTTP_Auth{
		Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_{
			Bearer: &corev1.Service_Spec_Config_HTTP_Auth_Bearer{
				Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{
					FromSecret: secretName,
				},
			},
		},
	}
}

func basicAuth(username, secretName string) *corev1.Service_Spec_Config_HTTP_Auth {
	return &corev1.Service_Spec_Config_HTTP_Auth{
		Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
			Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
				Username: username,
				Password: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password{
					Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password_FromSecret{
						FromSecret: secretName,
					},
				},
			},
		},
	}
}

func testVigilSecretManager(t *testing.T, h *harness.H) {
	v := newVigilCtx(t, h)
	v.record(t, http.StatusOK, "")

	value := utilrand.GetRandomStringCanonical(24)
	secret := h.CreateSecret(t, "", value)

	waitAuthorization := func(t *testing.T, what, want string) {
		t.Helper()

		v.waitSeen(t, what, "/", func(r *seenRequest) error {
			if got := r.Header.Get("Authorization"); got != want {
				return errors.Errorf("the upstream saw the Authorization %q, want %q",
					got, want)
			}
			return nil
		})
	}

	t.Run("BearerFromSecret", func(t *testing.T) {
		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{Auth: bearerAuth(secret.Metadata.Name)})

		waitAuthorization(t, "the upstream to receive the bearer token of the Secret",
			fmt.Sprintf("Bearer %s", value))
	})

	t.Run("SecretRotation", func(t *testing.T) {
		rotated := utilrand.GetRandomStringCanonical(24)
		h.UpdateSecret(t, secret.Metadata.Name, rotated)

		waitAuthorization(t, "the upstream to receive the rotated bearer token",
			fmt.Sprintf("Bearer %s", rotated))
	})

	t.Run("BasicFromSecret", func(t *testing.T) {
		password := utilrand.GetRandomStringCanonical(24)
		h.UpdateSecret(t, secret.Metadata.Name, password)

		username := utilrand.GetRandomStringCanonical(8)
		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
			Auth: basicAuth(username, secret.Metadata.Name),
		})

		waitAuthorization(t, "the upstream to receive the basic credentials of the Secret",
			fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(
				[]byte(fmt.Sprintf("%s:%s", username, password)))))
	})
}

func testVigilLoadBalancer(t *testing.T, h *harness.H) {
	upstream := h.StartHTTPUpstream(t, nil)

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode:        corev1.Service_Spec_HTTP,
			IsPublic:    true,
			IsAnonymous: true,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
						Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
							Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
								{
									Url:  fmt.Sprintf("http://localhost:%d", upstream.Port),
									User: "root",
								},
							},
						},
					},
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	client := h.ServiceClient(svc, "")
	noRetry := h.HTTPNoRetry().SetBaseURL(h.ServiceURL(svc))

	t.Run("NoUpstream", func(t *testing.T) {
		h.Eventually(t, "the Service without a connected upstream to fail",
			harness.DecisionBudget, func(ctx context.Context) error {
				got, err := h.StatusOf(ctx, noRetry, "/")
				if err != nil {
					return err
				}
				if got != http.StatusBadGateway {
					return errUnexpectedStatus(got, http.StatusBadGateway)
				}
				return nil
			})
	})

	t.Run("SessionUpstream", func(t *testing.T) {
		upstream.SetServeFn(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("loadbalanced"))
		})

		conn := h.Connect(t, harness.ConnectOpts{Serve: []string{svc.Metadata.Name}})

		res := h.WaitGetStatus(t, client, "/", http.StatusOK)
		require.Equal(t, "loadbalanced", res.String())

		require.Nil(t, conn.Disconnect())

		h.Eventually(t, "the Service to fail again once its upstream disconnects",
			harness.DecisionBudget, func(ctx context.Context) error {
				got, err := h.StatusOf(ctx, noRetry, "/")
				if err != nil {
					return err
				}
				if got != http.StatusBadGateway {
					return errUnexpectedStatus(got, http.StatusBadGateway)
				}
				return nil
			})
	})
}
