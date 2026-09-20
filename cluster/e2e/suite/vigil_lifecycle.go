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
	"slices"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const redeployBudget = 3 * time.Minute

type lifecycleCtx struct {
	h    *harness.H
	svc  *corev1.Service
	port int
}

func (l *lifecycleCtx) url(scheme string) string {
	return fmt.Sprintf("%s://localhost:%d", scheme, l.port)
}

func (l *lifecycleCtx) pods(t *testing.T) []string {
	t.Helper()

	pods, err := l.h.ServicePods(t.Context(), l.svc.Metadata.Name)
	require.Nil(t, err, "could not list the Service pods")

	var ret []string
	for _, pod := range pods {
		ret = append(ret, pod.Name)
	}

	return ret
}

func (l *lifecycleCtx) waitRedeployed(t *testing.T, what string, before []string) {
	t.Helper()

	l.h.Eventually(t, fmt.Sprintf("the Service pods to be replaced after %s", what),
		redeployBudget, func(ctx context.Context) error {
			pods, err := l.h.ServicePods(ctx, l.svc.Metadata.Name)
			if err != nil {
				return err
			}

			for _, pod := range pods {
				if slices.Contains(before, pod.Name) {
					return errors.Errorf("the pod %s is still present", pod.Name)
				}
				if pod.Status.Phase != "Running" {
					return errors.Errorf("the pod %s is %s", pod.Name, pod.Status.Phase)
				}
				for _, cs := range pod.Status.ContainerStatuses {
					if !cs.Ready {
						return errors.Errorf("the container %s of the pod %s is not ready",
							cs.Name, pod.Name)
					}
				}
			}

			return nil
		})

	zap.L().Info("The Service pods were replaced",
		zap.String("what", what), zap.Strings("before", before),
		zap.Strings("after", l.pods(t)))
}

func (l *lifecycleCtx) waitServing(t *testing.T, what string, c *resty.Client, url string) {
	t.Helper()

	l.h.Eventually(t, fmt.Sprintf("the upstream to be served %s", what),
		redeployBudget, func(ctx context.Context) error {
			res, err := c.R().SetContext(ctx).Get(url)
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
			}
			return nil
		})
}

func newLifecycleCtx(t *testing.T, h *harness.H) *lifecycleCtx {
	t.Helper()

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Port: 8080,
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

	h.MustWaitServiceUpstream(t, svc.Metadata.Name)
	h.MustWaitService(t, svc.Metadata.Name)

	ret := &lifecycleCtx{h: h, svc: svc, port: h.Port()}

	h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{svc.Metadata.Name: ret.port},
	})

	return ret
}

func testVigilModeSwitch(t *testing.T, h *harness.H) {
	l := newLifecycleCtx(t, h)

	l.waitServing(t, "in the HTTP mode", h.HTTP(), l.url("http"))

	setMode := func(t *testing.T, mode corev1.Service_Spec_Mode) {
		t.Helper()

		before := l.pods(t)

		l.svc.Spec.Mode = mode
		l.svc = h.UpdateService(t, l.svc)

		l.waitRedeployed(t, fmt.Sprintf("switching to the %s mode", mode), before)
	}

	t.Run("HTTPToTCP", func(t *testing.T) {
		setMode(t, corev1.Service_Spec_TCP)

		l.waitServing(t, "in the TCP mode", h.HTTP(), l.url("http"))

		res, err := h.HTTP().R().Get(l.url("http"))
		require.Nil(t, err)
		assert.NotEqual(t, "octelium", res.Header().Get("Server"),
			"the Service is still served by the HTTP mode")
	})

	t.Run("TCPToHTTP", func(t *testing.T) {
		setMode(t, corev1.Service_Spec_HTTP)

		l.waitServing(t, "in the HTTP mode again", h.HTTP(), l.url("http"))

		res, err := h.HTTP().R().Get(l.url("http"))
		require.Nil(t, err)
		assert.Equal(t, "octelium", res.Header().Get("Server"),
			"the Service is not served by the HTTP mode")
	})
}

func testVigilTLSSwitch(t *testing.T, h *harness.H) {
	l := newLifecycleCtx(t, h)

	fqdn := vutils.GetServicePrivateFQDN(l.svc, h.Domain)

	tlsClient := h.HTTP().SetTLSClientConfig(&tls.Config{
		ServerName: fqdn,
		MinVersion: tls.VersionTLS12,
	})

	l.waitServing(t, "over plaintext", h.HTTP(), l.url("http"))

	setTLS(t, l, true)

	t.Run("TLSEnabled", func(t *testing.T) {
		l.waitServing(t, "over TLS", tlsClient, l.url("https"))

		_, err := h.HTTPNoRetry().R().Get(l.url("http"))
		assert.NotNil(t, err,
			"a TLS Service must not serve plaintext requests")
	})

	setTLS(t, l, false)

	t.Run("TLSDisabled", func(t *testing.T) {
		l.waitServing(t, "over plaintext again", h.HTTP(), l.url("http"))

		_, err := h.HTTPNoRetry().SetTLSClientConfig(&tls.Config{
			ServerName: fqdn,
			MinVersion: tls.VersionTLS12,
		}).R().Get(l.url("https"))
		assert.NotNil(t, err,
			"a plaintext Service must not serve TLS requests")
	})
}

func setTLS(t *testing.T, l *lifecycleCtx, isTLS bool) {
	t.Helper()

	before := l.pods(t)

	l.svc.Spec.IsTLS = isTLS
	l.svc = l.h.UpdateService(t, l.svc)

	l.waitRedeployed(t, fmt.Sprintf("setting isTLS to %t", isTLS), before)
}
