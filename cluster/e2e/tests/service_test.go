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
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func testServiceHostHeader(t *testing.T, h *harness.H) {
	upstreamPort := h.Port()

	upstream := h.StartHTTPUpstream(t, &harness.TestSrvHTTP{Port: upstreamPort})

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstreamPort),
					},
					User: "root",
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	localPort := h.Port()
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{svc.Metadata.Name: localPort},
		Serve:   []string{svc.Metadata.Name},
	})

	expectHost := func(t *testing.T, want string) {
		t.Helper()

		var seen atomic.Pointer[string]
		upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
			zap.L().Debug("New request", zap.Any("host", r.Host))
			host := r.Host
			seen.Store(&host)
			w.WriteHeader(http.StatusOK)
		})

		h.Eventually(t, fmt.Sprintf("the upstream to receive the Host %q", want), authzBudget,
			func(ctx context.Context) error {
				res, err := h.HTTP().R().Get(conn.URL(svc.Metadata.Name))
				if err != nil {
					return err
				}
				if !res.IsSuccess() {
					return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
				}

				got := seen.Load()
				if got == nil {
					return errors.New("the upstream has not been reached yet")
				}
				if *got != want {
					return errors.Errorf("the upstream saw the Host %q, want %q", *got, want)
				}
				return nil
			})
	}

	t.Run("RewrittenByDefault", func(t *testing.T) {
		expectHost(t, fmt.Sprintf("localhost:%d", upstreamPort))
	})

	t.Run("Preserve", func(t *testing.T) {
		svc.Spec.Config.Type = &corev1.Service_Spec_Config_Http{
			Http: &corev1.Service_Spec_Config_HTTP{
				Header: &corev1.Service_Spec_Config_HTTP_Header{
					Host: &corev1.Service_Spec_Config_HTTP_Header_Host{
						Type: &corev1.Service_Spec_Config_HTTP_Header_Host_Preserve{
							Preserve: true,
						},
					},
				},
			},
		}
		svc = h.UpdateService(t, svc)

		expectHost(t, vutils.GetServicePublicFQDN(svc, h.Domain))
	})

	t.Run("FixedValue", func(t *testing.T) {
		want := fmt.Sprintf("%s.localhost", utilrand.GetRandomStringCanonical(16))

		svc.Spec.Config.Type = &corev1.Service_Spec_Config_Http{
			Http: &corev1.Service_Spec_Config_HTTP{
				Header: &corev1.Service_Spec_Config_HTTP_Header{
					Host: &corev1.Service_Spec_Config_HTTP_Header_Host{
						Type: &corev1.Service_Spec_Config_HTTP_Header_Host_Value{
							Value: want,
						},
					},
				},
			},
		}
		svc = h.UpdateService(t, svc)

		expectHost(t, want)
	})
}
