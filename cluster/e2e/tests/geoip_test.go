//go:build e2e

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

package tests

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const mmdbPrefixURL = `https://raw.githubusercontent.com/maxmind/MaxMind-DB/refs/heads/main/test-data`

const geoipUSAddr = "214.78.120.1"

func testGeoIP(t *testing.T, h *harness.H) {
	ctx := t.Context()
	c := h.CoreC()

	zap.L().Debug("Starting the GeoIP phase")

	usr := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
		InlinePolicies: []*corev1.InlinePolicy{
			{
				Name: "geoip",
				Spec: &corev1.Policy_Spec{
					Rules: []*corev1.Policy_Spec_Rule{
						{
							Effect:   corev1.Policy_Spec_Rule_ALLOW,
							Priority: -1,
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `ctx.session.status.authentication.info.geoip.country.code == "US"`,
								},
							},
						},
						{
							Effect: corev1.Policy_Spec_Rule_DENY,
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{MatchAny: true},
							},
						},
					},
				},
			},
		},
	})

	oauth2Token := func(t *testing.T, clientAddr string) string {
		t.Helper()

		cred := h.CreateCredential(t, harness.CredentialOpts{
			User:        usr.Metadata.Name,
			Type:        corev1.Credential_Spec_OAUTH2,
			SessionType: corev1.Session_Status_CLIENTLESS,
		})

		tkn := h.CredentialToken(t, cred)

		var tokenResponse struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Scope       string `json:"scope,omitempty"`
		}

		r := h.HTTP().R().
			SetHeader("Content-Type", "application/x-www-form-urlencoded").
			SetFormData(map[string]string{
				"grant_type":    "client_credentials",
				"client_id":     tkn.GetOauth2Credentials().ClientID,
				"client_secret": tkn.GetOauth2Credentials().ClientSecret,
			}).
			SetResult(&tokenResponse)

		if clientAddr != "" {
			r = r.SetHeader("X-Forwarded-For", clientAddr)
		}

		resp, err := r.Post(h.ClusterURL() + "/oauth2/token")
		require.Nil(t, err)
		require.True(t, resp.IsSuccess(), "token endpoint returned %d", resp.StatusCode())

		return tokenResponse.AccessToken
	}

	sessions := func(t *testing.T) []*corev1.Session {
		t.Helper()

		sessList, err := c.ListSession(ctx, &corev1.ListSessionOptions{
			UserRef: umetav1.GetObjectReference(usr),
			Common: &metav1.CommonListOptions{
				OrderBy: &metav1.CommonListOptions_OrderBy{
					Type: metav1.CommonListOptions_OrderBy_CREATED_AT,
					Mode: metav1.CommonListOptions_OrderBy_ASC,
				},
			},
		})
		require.Nil(t, err)

		return sessList.Items
	}

	get := func(t *testing.T, accessToken, clientAddr string, want int) {
		t.Helper()

		r := h.HTTPPublicToken("demo-nginx", accessToken).R()
		if clientAddr != "" {
			r = r.SetHeader("X-Forwarded-For", clientAddr)
		}

		res, err := r.Get("/")
		assert.Nil(t, err)
		assert.Equal(t, want, res.StatusCode())
	}

	var untrustedToken string

	t.Run("XFFUntrustedByDefault", func(t *testing.T) {
		untrustedToken = oauth2Token(t, geoipUSAddr)

		get(t, untrustedToken, geoipUSAddr, http.StatusForbidden)
		get(t, untrustedToken, "", http.StatusForbidden)

		items := sessions(t)
		require.Equal(t, 1, len(items))

		sess := items[0]
		zap.L().Debug("Initial Session", zap.Any("info", sess.Status.Authentication.Info))
		assert.Nil(t, sess.Status.Authentication.Info.Geoip)
		assert.Equal(t, "", sess.Status.Authentication.Info.Downstream.IpAddress)
	})

	cc := h.ClusterConfig(t)

	t.Cleanup(func() {
		cc := h.ClusterConfig(t)
		cc.Spec.Authentication = nil
		cc.Spec.Ingress = nil

		if _, err := c.UpdateClusterConfig(context.Background(), cc); err != nil {
			zap.L().Warn("Could not restore the ClusterConfig", zap.Error(err))
		}
	})

	t.Run("EnableXFFAndGeolocation", func(t *testing.T) {
		cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{
			UseForwardedForHeader: true,
			XffNumTrustedHops:     1,
		}

		cc.Spec.Authentication = &corev1.ClusterConfig_Spec_Authentication{
			Geolocation: &corev1.ClusterConfig_Spec_Authentication_Geolocation{
				Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_Mmdb{
					Mmdb: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB{
						Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_{
							Upstream: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream{
								Url: mmdbPrefixURL + "/GeoIP2-City-Test.mmdb",
							},
						},
					},
				},
			},
		}

		cc = h.UpdateClusterConfig(t, cc)
	})

	var trustedToken string

	t.Run("SessionCarriesGeolocation", func(t *testing.T) {
		h.EventuallyEvery(t, "the Session to record the forwarded address and its geolocation",
			60*time.Second, 3*time.Second, func(ctx context.Context) error {
				trustedToken = oauth2Token(t, geoipUSAddr)

				items := sessions(t)
				sess := items[len(items)-1]

				zap.L().Debug("Session after enabling XFF",
					zap.Any("info", sess.Status.Authentication.Info),
					zap.Any("geoip", sess.Status.Authentication.Info.Geoip))

				if sess.Status.Authentication.Info.Geoip == nil {
					return errors.Errorf("the Session has no resolved geolocation yet")
				}
				if got := sess.Status.Authentication.Info.Downstream.IpAddress; got != geoipUSAddr {
					return errors.Errorf(
						"the Session recorded the downstream address %q, want %q",
						got, geoipUSAddr)
				}
				return nil
			})
	})

	unresolvedToken := oauth2Token(t, "")

	t.Run("PolicyFollowsGeolocation", func(t *testing.T) {
		get(t, trustedToken, geoipUSAddr, http.StatusOK)
		get(t, trustedToken, "", http.StatusForbidden)

		get(t, unresolvedToken, geoipUSAddr, http.StatusForbidden)
		get(t, unresolvedToken, "1.1.1.1", http.StatusForbidden)
	})

	t.Run("RemovingUserAuthorizationDenies", func(t *testing.T) {
		usr.Spec.Authorization = nil
		usr = h.UpdateUser(t, usr)

		get(t, trustedToken, "", http.StatusForbidden)
		get(t, unresolvedToken, geoipUSAddr, http.StatusForbidden)
	})

	t.Run("DisablingGeolocationRestoresAccess", func(t *testing.T) {
		cc.Spec.Authentication = nil
		cc.Spec.Ingress = nil
		cc = h.UpdateClusterConfig(t, cc)

		h.Eventually(t, "the Cluster to stop enforcing the geolocation Policy",
			authzBudget, func(ctx context.Context) error {
				res, err := h.HTTPPublicToken("demo-nginx", trustedToken).R().Get("/")
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
				}
				return nil
			})

		get(t, unresolvedToken, geoipUSAddr, http.StatusOK)
	})

	zap.L().Debug("Done with the GeoIP phase")
}
