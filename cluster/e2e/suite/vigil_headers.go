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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const (
	forgedClientAddress = "203.0.113.9"

	keptRequestCookie  = "e2e_kept"
	keptResponseCookie = "e2e_upstream"
)

func forgedOcteliumHeaders(withAuthOverride bool) map[string]string {
	ret := map[string]string{
		"X-Octelium-Client-Address": forgedClientAddress,
		"X-Octelium-Origin":         "https://attacker.example.com",
		"X-Octelium-Session-Uid":    "forged-session",
		"X-Octelium-User-Uid":       "forged-user",
		"X-Octelium-Device-Uid":     "forged-device",
		"X-Octelium-Refresh-Token":  "forged-refresh-token",
	}

	if withAuthOverride {
		ret["X-Octelium-Auth"] = "forged-access-token"
	}

	return ret
}

func forgedCookieHeader(withAuthOverride bool) string {
	ret := []string{fmt.Sprintf("%s=kept", keptRequestCookie), "octelium_rt=forged"}

	if withAuthOverride {
		ret = append(ret, "octelium_auth=forged")
	}

	return strings.Join(ret, "; ")
}

func octeliumHeaders(hdr http.Header) []string {
	var ret []string
	for name := range hdr {
		if strings.HasPrefix(strings.ToLower(name), "x-octelium-") {
			ret = append(ret, name)
		}
	}
	return ret
}

func setCookieNames(res *resty.Response) []string {
	var ret []string
	for _, cookie := range res.Cookies() {
		ret = append(ret, cookie.Name)
	}
	return ret
}

func testVigilHeaderForgery(t *testing.T, h *harness.H) {
	upstream := h.StartHTTPUpstream(t, nil)

	var seen atomic.Pointer[seenRequest]

	upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(&seenRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Header: r.Header.Clone(),
		})

		zap.L().Debug("Upstream received request", zap.Any("headers", r.Header))

		http.SetCookie(w, &http.Cookie{Name: "octelium_auth", Value: "forged", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "octelium_rt", Value: "forged", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: keptResponseCookie, Value: "kept", Path: "/"})

		w.Write([]byte("ok"))
	})

	usr := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
		InlinePolicies: harness.InlineAllowAny("allow"),
	})
	token := h.AccessToken(t, usr)

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode:     corev1.Service_Spec_HTTP,
			IsPublic: true,
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Name: "e2e-forgery",
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								harness.MatchRule("deny-forged-address", 0,
									corev1.Policy_Spec_Rule_DENY,
									fmt.Sprintf(`ctx.request.ip == %q`, forgedClientAddress)),
								harness.MatchRule("deny-canary", 0,
									corev1.Policy_Spec_Rule_DENY,
									`"x-e2e-canary" in ctx.request.http.headers && `+
										`ctx.request.http.headers["x-e2e-canary"] == "deny"`),
							},
						},
					},
				},
			},
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstream.Port),
					},
					User: "root",
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	port := h.Port()
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{svc.Metadata.Name: port},
		Serve:   []string{svc.Metadata.Name},
	})

	request := func(c *resty.Client, withAuthOverride bool) *resty.Request {
		req := c.R().SetHeader("Cookie", forgedCookieHeader(withAuthOverride))
		for k, v := range forgedOcteliumHeaders(withAuthOverride) {
			req = req.SetHeader(k, v)
		}
		return req
	}

	forged := func(t *testing.T, c *resty.Client, url string,
		withAuthOverride, hasAuthorization bool) {
		t.Helper()

		var res *resty.Response

		h.Eventually(t, "the forged request to be served with the Session identity",
			harness.DecisionBudget,
			func(ctx context.Context) error {
				seen.Store(nil)

				got, err := request(c, withAuthOverride).SetContext(ctx).Get(url)
				if err != nil {
					return err
				}
				if got.StatusCode() != http.StatusOK {
					return errUnexpectedStatus(got.StatusCode(), http.StatusOK)
				}
				if seen.Load() == nil {
					return errors.New("the upstream has not been reached yet")
				}
				res = got
				return nil
			})

		up := seen.Load()

		assert.Empty(t, octeliumHeaders(up.Header),
			"the upstream must not receive any Octelium request header from the downstream")

		cookie := up.Header.Get("Cookie")
		assert.NotContains(t, cookie, "octelium_",
			"the upstream must not receive the Octelium cookies of the downstream")
		assert.Contains(t, cookie, keptRequestCookie,
			"the upstream must still receive the cookies of the downstream")

		if hasAuthorization {
			assert.Empty(t, up.Header.Get("Authorization"),
				"the upstream must not receive the Octelium access token")
		}

		names := setCookieNames(res)
		assert.NotContains(t, names, "octelium_auth",
			"a rogue upstream must not be able to set the Octelium session cookie")
		assert.NotContains(t, names, "octelium_rt",
			"a rogue upstream must not be able to set the Octelium refresh token cookie")
		assert.Contains(t, names, keptResponseCookie,
			"the upstream cookies must still reach the downstream")
	}

	t.Run("PolicyIsEnforced", func(t *testing.T) {
		h.Eventually(t, "the canary request to be denied", harness.DecisionBudget,
			func(ctx context.Context) error {
				got, err := h.HTTP().R().SetContext(ctx).
					SetHeader("X-E2E-Canary", "deny").
					Get(conn.URL(svc.Metadata.Name))
				if err != nil {
					return err
				}
				if got.StatusCode() != http.StatusForbidden {
					return errUnexpectedStatus(got.StatusCode(), http.StatusForbidden)
				}
				return nil
			})
	})

	t.Run("ClientBased", func(t *testing.T) {
		forged(t, h.HTTP(), conn.URL(svc.Metadata.Name), true, false)
	})

	t.Run("Clientless", func(t *testing.T) {
		h.Require(t, capHostPortIngress)

		forged(t, h.ServiceClient(svc, token), h.ServiceURL(svc), false, true)
	})
}
