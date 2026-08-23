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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func testAnonymousAuthorization(t *testing.T, h *harness.H) {
	zap.L().Debug("Starting the anonymous authorization phase")

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			IsPublic:    true,
			IsAnonymous: true,
			Mode:        corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://github.com",
					},
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	waitStatus := func(t *testing.T, path string, want int) {
		t.Helper()

		h.Eventually(t, fmt.Sprintf("GET %s to return %d", path, want), authzBudget,
			func(ctx context.Context) error {
				res, err := h.HTTPPublic(svc.Metadata.Name).R().Get(path)
				if err != nil {
					return err
				}
				if res.StatusCode() != want {
					return errUnexpectedStatus(res.StatusCode(), want)
				}
				return nil
			})
	}

	t.Run("AnonymousOpen", func(t *testing.T) {
		waitStatus(t, "/", http.StatusOK)
	})

	t.Run("ServiceConfigApplies", func(t *testing.T) {
		svc.Spec.Config.Type = &corev1.Service_Spec_Config_Http{
			Http: &corev1.Service_Spec_Config_HTTP{
				Header: &corev1.Service_Spec_Config_HTTP_Header{
					AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
						{
							Key: "X-E2E-Anonymous",
							Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
								Value: "on",
							},
						},
					},
				},
			},
		}
		svc = h.UpdateService(t, svc)

		h.Eventually(t, "the anonymous Service to apply its own Config", authzBudget,
			func(ctx context.Context) error {
				res, err := h.HTTPPublic(svc.Metadata.Name).R().SetContext(ctx).Get("/")
				if err != nil {
					return err
				}
				if got := res.Header().Get("X-E2E-Anonymous"); got != "on" {
					return errors.Errorf("the client saw X-E2E-Anonymous %q, want %q",
						got, "on")
				}
				return nil
			})
	})

	t.Run("AuthorizationClosesIt", func(t *testing.T) {
		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			EnableAnonymous: true,
		}
		svc = h.UpdateService(t, svc)

		waitStatus(t, "/", http.StatusForbidden)
	})

	t.Run("PolicyOpensOnePath", func(t *testing.T) {
		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			EnableAnonymous: true,
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `ctx.request.http.path.startsWith("/about")`,
									},
								},
								Effect: corev1.Policy_Spec_Rule_ALLOW,
							},
						},
					},
				},
			},
		}
		svc = h.UpdateService(t, svc)

		waitStatus(t, "/about", http.StatusOK)
		waitStatus(t, "/", http.StatusForbidden)
	})

	zap.L().Debug("Done with the anonymous authorization phase")
}
