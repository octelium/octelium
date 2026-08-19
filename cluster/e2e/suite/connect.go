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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

func testConnect(t *testing.T, h *harness.H) {
	t.Run("UnknownServiceFails", func(t *testing.T) {
		h.MustFailWithin(t, fmt.Sprintf("octelium connect -p %s:%d",
			utilrand.GetRandomStringCanonical(8), h.Port()), 2*time.Minute)
	})

	t.Run("PublishedService", func(t *testing.T) {
		port := h.Port()
		conn := h.Connect(t, harness.ConnectOpts{
			Publish: map[string]int{"demo-nginx": port},
		})

		h.WaitGetStatus(t, h.HTTP(), conn.URL("demo-nginx"), http.StatusOK)
	})
}

func testConnectQUIC(t *testing.T, h *harness.H) {
	h.Require(t, capQUICv0)

	port := h.Port()
	conn := h.Connect(t, harness.ConnectOpts{
		TunnelMode: "quicv0",
		Publish:    map[string]int{"nginx": port},
	})

	h.MustWaitServiceUpstream(t, "nginx")

	res := h.WaitGetStatus(t, h.HTTP(), conn.URL("nginx"), http.StatusOK)

	_, err := html.Parse(strings.NewReader(string(res.Body())))
	assert.Nil(t, err)
}

func connectionUpstream(c *corev1.Session_Status_Connection,
	svc *corev1.Service) *corev1.Session_Status_Connection_Upstream {
	if c == nil {
		return nil
	}

	for _, upstream := range c.Upstreams {
		if upstream.ServiceRef != nil && upstream.ServiceRef.Uid == svc.Metadata.Uid {
			return upstream
		}
	}

	return nil
}

func testConnectServiceLifecycle(t *testing.T, h *harness.H) {
	first := h.StartHTTPUpstream(t, nil)
	first.SetServeFn(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("first"))
	})

	second := h.StartHTTPUpstream(t, nil)
	second.SetServeFn(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("second"))
	})

	h.Connect(t, harness.ConnectOpts{ServeAll: true})
	status := h.Status(t)
	require.NotNil(t, status.Session)
	sessName := status.Session.Metadata.Name

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
						Url: fmt.Sprintf("http://localhost:%d", first.Port),
					},
					User: "root",
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	var listenerPort int32
	waitConnectionState(t, h, sessName,
		func(c *corev1.Session_Status_Connection) error {
			upstream := connectionUpstream(c, svc)
			if upstream == nil {
				return errors.Errorf("the new Service is missing from the Session upstreams")
			}
			if upstream.Port == 0 {
				return errors.Errorf("the new Service has no listener port")
			}
			if upstream.Backend == nil || upstream.Backend.Port != int32(first.Port) {
				return errors.Errorf("the new Service has not received its backend yet")
			}
			listenerPort = upstream.Port
			return nil
		})

	res := h.WaitGetStatus(t, h.ServiceClient(svc, ""), "/", http.StatusOK)
	assert.Equal(t, "first", res.String())

	svc.Spec.Config.Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: fmt.Sprintf("http://localhost:%d", second.Port),
	}
	svc = h.UpdateService(t, svc)

	waitConnectionState(t, h, sessName,
		func(c *corev1.Session_Status_Connection) error {
			upstream := connectionUpstream(c, svc)
			if upstream == nil {
				return errors.Errorf("the updated Service is missing from the Session upstreams")
			}
			if upstream.Port != listenerPort {
				return errors.Errorf("the listener port changed from %d to %d",
					listenerPort, upstream.Port)
			}
			if upstream.Backend == nil || upstream.Backend.Port != int32(second.Port) {
				return errors.Errorf("the updated Service still has the previous backend")
			}
			return nil
		})

	h.Eventually(t, "the updated Service to use the new client upstream",
		harness.DecisionBudget, func(ctx context.Context) error {
			res, err := h.ServiceClient(svc, "").R().SetContext(ctx).Get("/")
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return errors.Errorf("the updated Service returned status %d", res.StatusCode())
			}
			if res.String() != "second" {
				return errors.Errorf("the updated Service returned %q, want %q",
					res.String(), "second")
			}
			return nil
		})

	h.DeleteService(t, svc)

	waitConnectionState(t, h, sessName,
		func(c *corev1.Session_Status_Connection) error {
			if connectionUpstream(c, svc) != nil {
				return errors.Errorf("the deleted Service is still present in the Session upstreams")
			}
			return nil
		})

	h.Eventually(t, "the deleted Service route to disappear", harness.DecisionBudget,
		func(ctx context.Context) error {
			res, err := h.HTTPNoRetry().R().SetContext(ctx).Get(h.ServiceURL(svc))
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusNotFound {
				return errors.Errorf("the deleted Service returned status %d", res.StatusCode())
			}
			return nil
		})

	status = h.Status(t)
	require.NotNil(t, status.Session)
	require.NotNil(t, status.Session.Status)
	assert.True(t, status.Session.Status.IsConnected)
}

func testConnectResilience(t *testing.T, h *harness.H) {
	port := h.Port()
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{"demo-nginx": port},
	})

	h.WaitGetStatus(t, h.HTTP(), conn.URL("demo-nginx"), http.StatusOK)

	status := h.Status(t)
	require.NotNil(t, status.Session)
	require.NotNil(t, status.Session.Status)

	sessName := status.Session.Metadata.Name
	sess := h.GetSession(t, sessName)
	require.NotNil(t, sess.Status)
	totalConnections := sess.Status.TotalConnections

	t.Run("APIServer", func(t *testing.T) {
		replaced := h.RestartService(t, "default.octelium-api")

		reconnected := h.Within(t, "octelium connect to restore its API stream",
			harness.ConnectBudget, func(ctx context.Context) error {
				sess, err := h.CoreC().GetSession(ctx,
					&metav1.GetOptions{Name: sessName})
				if err != nil {
					return err
				}
				if sess.Status == nil || !sess.Status.IsConnected {
					return errors.Errorf("the Session is not connected")
				}
				if sess.Status.TotalConnections <= totalConnections {
					return errors.Errorf("the Session has not opened a new API stream")
				}
				totalConnections = sess.Status.TotalConnections
				return nil
			})

		h.WaitConnected(t)
		h.WaitGetStatus(t, h.HTTP(), conn.URL("demo-nginx"), http.StatusOK)

		zap.L().Info("octelium connect recovery after API Server replacement",
			zap.Duration("replacement", replaced),
			zap.Duration("reconnected", reconnected))
	})

	t.Run("GatewayAgent", func(t *testing.T) {
		replaced := h.RestartComponent(t, "gwagent")
		recovered := h.Within(t, "the published Service to recover after Gateway Agent replacement",
			harness.ConnectBudget, func(ctx context.Context) error {
				got, err := h.StatusOf(ctx, h.HTTPNoRetry().SetBaseURL(conn.URL("demo-nginx")), "/")
				if err != nil {
					return err
				}
				if got != http.StatusOK {
					return errors.Errorf("the published Service returned status %d", got)
				}
				return nil
			})

		zap.L().Info("Published Service recovery after Gateway Agent replacement",
			zap.Duration("replacement", replaced),
			zap.Duration("recovered", recovered))
	})
}
