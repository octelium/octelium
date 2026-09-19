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
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rejectedConnectBudget = 90 * time.Second

func connectionPublished(c *corev1.Session_Status_Connection,
	svc *corev1.Service) *corev1.Session_Status_Connection_PublishedService {
	if c == nil {
		return nil
	}

	for _, published := range c.PublishedServices {
		if published.ServiceRef != nil && published.ServiceRef.Uid == svc.Metadata.Uid {
			return published
		}
	}

	return nil
}

func publishedService(t *testing.T, h *harness.H,
	svc *corev1.Service) *corev1.Session_Status_Connection_PublishedService {
	t.Helper()

	sess := h.GetSession(t, h.Status(t).Session.Metadata.Name)
	require.NotNil(t, sess.Status.Connection)

	ret := connectionPublished(sess.Status.Connection, svc)
	require.NotNil(t, ret,
		"the Service %s is missing from the Session published Services",
		svc.Metadata.Name)

	return ret
}

func testConnectPublish(t *testing.T, h *harness.H) {
	ns := h.EnsureTestNamespace(t)

	svc := h.NewPublicService(t, "default")
	nsSvc := h.NewPublicService(t, ns.Metadata.Name)

	t.Run("Loopback", func(t *testing.T) {
		port := h.Port()
		conn := h.Connect(t, harness.ConnectOpts{
			PublishOrdered: []harness.PublishSpec{
				{Service: svc.Metadata.Name, Address: "127.0.0.1", Port: port},
			},
		})

		h.WaitGetStatus(t, h.HTTP(), conn.URL(svc.Metadata.Name), http.StatusOK)

		published := publishedService(t, h, svc)
		assert.Equal(t, "127.0.0.1", published.Address)
		assert.Equal(t, int32(port), published.Port)
	})

	t.Run("AllInterfaces", func(t *testing.T) {
		port := h.Port()
		conn := h.Connect(t, harness.ConnectOpts{
			PublishOrdered: []harness.PublishSpec{
				{Service: svc.Metadata.Name, Address: "0.0.0.0", Port: port},
			},
		})

		h.WaitGetStatus(t, h.HTTP(), conn.URL(svc.Metadata.Name), http.StatusOK)

		published := publishedService(t, h, svc)
		assert.Equal(t, "0.0.0.0", published.Address)

		h.WaitGetStatus(t, h.HTTP(), fmt.Sprintf("http://%s",
			net.JoinHostPort(h.ExternalIP, fmt.Sprintf("%d", port))), http.StatusOK)
	})

	t.Run("Namespaced", func(t *testing.T) {
		port := h.Port()
		nsPort := h.Port()

		conn := h.Connect(t, harness.ConnectOpts{
			Publish: map[string]int{
				svc.Metadata.Name:   port,
				nsSvc.Metadata.Name: nsPort,
			},
		})

		for _, cur := range []*corev1.Service{svc, nsSvc} {
			h.WaitGetStatus(t, h.HTTP(), conn.URL(cur.Metadata.Name), http.StatusOK)

			published := publishedService(t, h, cur)
			assert.Equal(t, "localhost", published.Address)
			assert.Equal(t, int32(conn.Port(cur.Metadata.Name)), published.Port)
		}
	})

	t.Run("Rejected", func(t *testing.T) {
		for _, arg := range []string{
			svc.Metadata.Name,
			fmt.Sprintf("%s:0", svc.Metadata.Name),
			fmt.Sprintf("%s:70000", svc.Metadata.Name),
			fmt.Sprintf("%s:notaport", svc.Metadata.Name),
			fmt.Sprintf("%s:300.400.500.600:%d", svc.Metadata.Name, h.Port()),
			fmt.Sprintf("%s:%d", harness.DNSServiceName, h.Port()),
			fmt.Sprintf("%s.%s:%d", utilrand.GetRandomStringCanonical(8),
				utilrand.GetRandomStringCanonical(8), h.Port()),
		} {
			h.MustFailWithin(t, fmt.Sprintf("octelium connect -p %s", arg),
				rejectedConnectBudget)
		}
	})
}

func newClientServedService(t *testing.T, h *harness.H, port int) *corev1.Service {
	t.Helper()

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", port),
					},
					User: "root",
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	return svc
}

func testConnectServe(t *testing.T, h *harness.H) {
	served := h.StartHTTPUpstream(t, nil)
	served.SetServeFn(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("served"))
	})

	ignored := h.StartHTTPUpstream(t, nil)
	ignored.SetServeFn(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ignored"))
	})

	servedSvc := newClientServedService(t, h, served.Port)
	ignoredSvc := newClientServedService(t, h, ignored.Port)

	port := h.Port()
	conn := h.Connect(t, harness.ConnectOpts{
		Serve:   []string{servedSvc.Metadata.Name},
		Publish: map[string]int{servedSvc.Metadata.Name: port},
	})

	sessName := h.Status(t).Session.Metadata.Name

	waitConnectionState(t, h, sessName,
		func(c *corev1.Session_Status_Connection) error {
			upstream := connectionUpstream(c, servedSvc)
			if upstream == nil {
				return errors.Errorf("the selected Service is not served yet")
			}
			if upstream.Backend == nil || upstream.Backend.Port != int32(served.Port) {
				return errors.Errorf("the selected Service has not received its backend yet")
			}
			return nil
		})

	sess := h.GetSession(t, sessName)
	require.NotNil(t, sess.Status.Connection)

	assert.Nil(t, connectionUpstream(sess.Status.Connection, ignoredSvc),
		"only the Services selected with --serve must be served")

	res := h.WaitGetStatus(t, h.HTTP(), conn.URL(servedSvc.Metadata.Name), http.StatusOK)
	assert.Equal(t, "served", res.String())

	h.Consistently(t, "the unselected Service to stay unserved", decisionSettle,
		func(ctx context.Context) error {
			cur, err := h.CoreC().GetSession(ctx, &metav1.GetOptions{Name: sessName})
			if err != nil {
				return err
			}
			if connectionUpstream(cur.Status.Connection, ignoredSvc) != nil {
				return errors.Errorf("the unselected Service has been served")
			}
			return nil
		})
}
