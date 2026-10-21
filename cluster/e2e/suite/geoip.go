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
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
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

func testGeoIPConfigSources(t *testing.T, h *harness.H) {
	ctx := t.Context()
	c := h.CoreC()

	getDB := func(name string) []byte {
		res, err := h.HTTP().R().SetContext(ctx).Get(mmdbPrefixURL + "/" + name)
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, res.StatusCode())
		return res.Body()
	}
	cityDB := getDB("GeoIP2-City-Test.mmdb")
	countryDB := getDB("GeoIP2-Country-Test.mmdb")
	configData := func(data []byte) *corev1.Config_Data {
		return &corev1.Config_Data{Type: &corev1.Config_Data_ValueBytes{ValueBytes: data}}
	}
	createConfig := func(t *testing.T, name string, data []byte) *corev1.Config {
		t.Helper()
		cfg, err := c.CreateConfig(ctx, &corev1.Config{
			Metadata: &metav1.Metadata{Name: name},
			Spec:     &corev1.Config_Spec{},
			Data:     configData(data),
		})
		require.Nil(t, err)
		return cfg
	}
	cityName, countryName := h.Name(), h.Name()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		for _, name := range []string{cityName, countryName} {
			if _, err := c.DeleteConfig(ctx, &metav1.DeleteOptions{Name: name}); err != nil && !grpcerr.IsNotFound(err) {
				zap.L().Warn("Could not delete the Config", zap.String("name", name), zap.Error(err))
			}
		}
	})
	cityCfg := createConfig(t, cityName, cityDB)
	countryCfg := createConfig(t, countryName, countryDB)

	original := pbutils.Clone(h.ClusterConfig(t)).(*corev1.ClusterConfig)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cc, err := c.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
		if err != nil {
			zap.L().Warn("Could not get the ClusterConfig", zap.Error(err))
			return
		}
		cc.Spec.Authentication = original.Spec.Authentication
		cc.Spec.Ingress = original.Spec.Ingress
		if _, err := c.UpdateClusterConfig(ctx, cc); err != nil {
			zap.L().Warn("Could not restore the ClusterConfig", zap.Error(err))
		}
	})

	usr := h.CreateWorkloadUser(t, nil)
	cred := h.CreateCredential(t, harness.CredentialOpts{
		User:        usr.Metadata.Name,
		Type:        corev1.Credential_Spec_OAUTH2,
		SessionType: corev1.Session_Status_CLIENTLESS,
	})
	credentials := h.CredentialToken(t, cred).GetOauth2Credentials()
	require.NotNil(t, credentials)

	setSource := func(t *testing.T, source *corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB) {
		t.Helper()
		cc := h.ClusterConfig(t)
		cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{
			UseForwardedForHeader: true,
			XffNumTrustedHops:     1,
		}
		cc.Spec.Authentication = &corev1.ClusterConfig_Spec_Authentication{
			Geolocation: &corev1.ClusterConfig_Spec_Authentication_Geolocation{
				Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_Mmdb{Mmdb: source},
			},
		}
		h.UpdateClusterConfig(t, cc)
	}
	fromConfig := func(name string) *corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB {
		return &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB{
			Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_FromConfig{FromConfig: name},
		}
	}
	updateConfig := func(t *testing.T, cfg *corev1.Config, data []byte) *corev1.Config {
		t.Helper()
		cfg = pbutils.Clone(cfg).(*corev1.Config)
		cfg.Data = configData(data)
		ret, err := c.UpdateConfig(ctx, cfg)
		require.Nil(t, err)
		return ret
	}
	check := func(ctx context.Context, city bool) error {
		var tokenResponse struct {
			AccessToken string `json:"access_token"`
		}
		res, err := h.HTTPNoRetry().R().SetContext(ctx).
			SetHeader("X-Forwarded-For", geoipUSAddr).
			SetFormData(map[string]string{
				"grant_type":    "client_credentials",
				"client_id":     credentials.ClientID,
				"client_secret": credentials.ClientSecret,
			}).SetResult(&tokenResponse).Post(h.ClusterURL() + "/oauth2/token")
		if err != nil {
			return err
		}
		if !res.IsSuccess() || tokenResponse.AccessToken == "" {
			return errors.Errorf("token endpoint returned %d without an access token", res.StatusCode())
		}
		items, err := c.ListSession(ctx, &corev1.ListSessionOptions{UserRef: umetav1.GetObjectReference(usr)})
		if err != nil {
			return err
		}
		if len(items.Items) != 1 {
			return errors.Errorf("got %d Sessions, want 1", len(items.Items))
		}
		geoip := items.Items[0].GetStatus().GetAuthentication().GetInfo().GetGeoip()
		if geoip.GetIp() != geoipUSAddr || geoip.GetCountry().GetCode() != "US" {
			return errors.Errorf("the Session has unexpected geolocation: %+v", geoip)
		}
		if (geoip.GetCity() != nil) != city {
			return errors.Errorf("the Session has city data %t, want %t", geoip.GetCity() != nil, city)
		}
		return nil
	}
	wait := func(t *testing.T, city bool) {
		t.Helper()
		var stableAt time.Time
		h.EventuallyEvery(t, "authentication to use the selected MMDB source", 60*time.Second,
			500*time.Millisecond, func(ctx context.Context) error {
				if err := check(ctx, city); err != nil {
					stableAt = time.Time{}
					return err
				}
				if stableAt.IsZero() {
					stableAt = time.Now()
				}
				if time.Since(stableAt) < decisionSettle {
					return errors.Errorf("waiting for the selected MMDB source to settle")
				}
				return nil
			})
	}
	unchanged := func(t *testing.T) {
		t.Helper()
		h.Consistently(t, "obsolete Config events to preserve the upstream MMDB", 3*decisionSettle,
			func(ctx context.Context) error {
				return check(ctx, false)
			})
	}

	t.Run("FromConfig", func(t *testing.T) {
		setSource(t, fromConfig(cityCfg.Metadata.Name))
		wait(t, true)
		cityCfg = updateConfig(t, cityCfg, countryDB)
		wait(t, false)
		cityCfg = updateConfig(t, cityCfg, cityDB)
		wait(t, true)
	})

	t.Run("SwitchConfig", func(t *testing.T) {
		setSource(t, fromConfig(countryCfg.Metadata.Name))
		wait(t, false)
		countryCfg = updateConfig(t, countryCfg, cityDB)
		wait(t, true)
	})

	t.Run("SwitchToUpstream", func(t *testing.T) {
		setSource(t, &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB{
			Type: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream_{
				Upstream: &corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream{
					Url: mmdbPrefixURL + "/GeoIP2-Country-Test.mmdb",
				},
			},
		})
		wait(t, false)
		countryCfg = updateConfig(t, countryCfg, countryDB)
		countryCfg = updateConfig(t, countryCfg, cityDB)
		unchanged(t)
	})

	t.Run("DeleteObsoleteConfig", func(t *testing.T) {
		_, err := c.DeleteConfig(ctx, &metav1.DeleteOptions{Uid: countryCfg.Metadata.Uid})
		require.Nil(t, err)
		unchanged(t)
	})

	t.Run("RecreateObsoleteConfig", func(t *testing.T) {
		countryCfg = createConfig(t, countryName, cityDB)
		unchanged(t)
	})

	t.Run("SwitchBackToConfig", func(t *testing.T) {
		setSource(t, fromConfig(countryCfg.Metadata.Name))
		wait(t, true)
		countryCfg = updateConfig(t, countryCfg, countryDB)
		wait(t, false)
	})
}
