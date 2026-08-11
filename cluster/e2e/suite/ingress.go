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
	"crypto/tls"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testIngress(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)

	t.Run("UnknownHost", func(t *testing.T) {
		url := fmt.Sprintf("https://%s.%s", utilrand.GetRandomStringCanonical(10), h.Domain)
		h.GetStatus(t, h.HTTP(), url, http.StatusNotFound)
	})

	t.Run("PublicToggle", func(t *testing.T) {
		svc := h.CreateService(t, &corev1.Service{
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
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

		c := h.ServiceClient(svc, "")

		h.WaitStatus(t, c, "/", http.StatusNotFound)

		svc.Spec.IsPublic = true
		svc = h.UpdateService(t, svc)

		published := h.WaitStatus(t, c, "/", http.StatusUnauthorized)

		svc.Spec.IsPublic = false
		svc = h.UpdateService(t, svc)

		withdrawn := h.WaitStatus(t, c, "/", http.StatusNotFound)

		zap.L().Info("Ingress route propagation",
			zap.Duration("published", published), zap.Duration("withdrawn", withdrawn))

		assert.Less(t, published, propagationBudget,
			"publishing a Service took %s, budget is %s", published, propagationBudget)
		assert.Less(t, withdrawn, propagationBudget,
			"withdrawing a Service took %s, budget is %s", withdrawn, propagationBudget)
	})

	t.Run("NamespacedHostname", func(t *testing.T) {
		ns := h.EnsureTestNamespace(t)
		svc := h.NewPublicService(t, ns.Metadata.Name)

		assert.Equal(t, fmt.Sprintf("https://%s.%s", svc.Metadata.Name, h.Domain),
			h.ServiceURL(svc))

		h.WaitStatus(t, h.ServiceClient(svc, ""), "/", http.StatusUnauthorized)
	})

	t.Run("GlobalResponseHeaders", func(t *testing.T) {
		res, err := h.HTTP().R().Get(h.PublicURL("demo-nginx"))
		require.Nil(t, err)

		assert.Equal(t, "octelium", res.Header().Get("Server"))
		assert.Equal(t, "max-age=2592000", res.Header().Get("Strict-Transport-Security"))
	})

	t.Run("Certificate", func(t *testing.T) {
		conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", h.Domain), &tls.Config{
			ServerName: fmt.Sprintf("demo-nginx.%s", h.Domain),
		})
		require.Nil(t, err, "the Ingress certificate is not trusted by the host")
		defer conn.Close()

		certs := conn.ConnectionState().PeerCertificates
		require.True(t, len(certs) > 0)

		assert.Nil(t, certs[0].VerifyHostname(fmt.Sprintf("demo-nginx.%s", h.Domain)))
	})

	t.Run("AnonymousLargeBody", func(t *testing.T) {
		upstream := h.StartHTTPUpstream(t, nil)

		var got atomic.Int64
		upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
			var n int64
			buf := make([]byte, 32*1024)
			for {
				read, err := r.Body.Read(buf)
				n += int64(read)
				if err != nil {
					break
				}
			}
			got.Store(n)
			w.WriteHeader(http.StatusOK)
		})

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
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: fmt.Sprintf("http://localhost:%d", upstream.Port),
						},
						User: "root",
					},
				},
			},
		})

		h.MustWaitService(t, svc.Metadata.Name)

		h.Connect(t, harness.ConnectOpts{Serve: []string{svc.Metadata.Name}})

		body := utilrand.GetRandomBytesMust(4 * 1024 * 1024)

		h.Eventually(t, "the Ingress to carry a large body to the upstream",
			harness.DecisionBudget, func(ctx context.Context) error {
				got.Store(0)

				res, err := h.HTTP().R().SetContext(ctx).
					SetHeader("Content-Type", "application/octet-stream").
					SetBody(body).
					Post(h.ServiceURL(svc) + "/")
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
				}
				if got.Load() != int64(len(body)) {
					return errors.Errorf("the upstream received %d bytes, want %d",
						got.Load(), len(body))
				}
				return nil
			})
	})
}

func testIngressCertificateRotation(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)

	h.Eventually(t, "the Ingress to keep serving during a certificate reinstall",
		harness.DecisionBudget, func(ctx context.Context) error {
			res, err := h.HTTP().R().SetContext(ctx).Get(h.ClusterURL())
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
			}
			return nil
		})

	h.MustRun(t, fmt.Sprintf("octops cert %s --key %s --cert %s --kubeconfig %s",
		h.Domain, h.State.KeyPath, h.State.CertPath, h.State.KubeconfigPath))

	h.Consistently(t, "the Ingress to keep answering after the certificate reinstall",
		3*decisionSettle, func(ctx context.Context) error {
			res, err := h.HTTP().R().SetContext(ctx).Get(h.ClusterURL())
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
			}
			return nil
		})
}
