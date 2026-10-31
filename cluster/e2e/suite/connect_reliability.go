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

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func ClientReliabilityPhases() []Phase {
	return []Phase{
		{"ConnectReliabilityIngressDataPlaneRestart", testConnectReliabilityIngressDataPlaneRestart},
		{"ConnectReliabilityAPIBlackhole", testConnectReliabilityAPIBlackhole},
		{"ConnectReliabilityControlAndDataPlaneRestart", testConnectReliabilityControlAndDataPlaneRestart},
		{"ConnectReliabilityLocalDNSAcrossAPIRestarts", testConnectReliabilityLocalDNSAcrossAPIRestarts},
	}
}

func waitConnectReliabilityReconnected(t *testing.T, h *harness.H, conn *harness.Conn,
	sessName string, previous uint32, what string) {
	t.Helper()

	reconnected := h.Within(t, what, harness.ConnectBudget, func(ctx context.Context) error {
		if !conn.IsRunning() {
			return errors.New("octelium connect exited instead of reconnecting")
		}
		sess, err := h.CoreC().GetSession(ctx, &metav1.GetOptions{Name: sessName})
		if err != nil {
			return err
		}
		if !sess.GetStatus().GetIsConnected() {
			return errors.Errorf("the Session is not connected")
		}
		if sess.GetStatus().GetTotalConnections() <= previous {
			return errors.Errorf("the Session has not opened a new API stream")
		}
		return nil
	})

	zap.L().Info("octelium connect reconnected", zap.String("what", what), zap.Duration("reconnected", reconnected))
}

func startConnectReliabilityClient(t *testing.T, h *harness.H) (*harness.Conn, string, string) {
	t.Helper()

	svc := h.NewPublicService(t, "default")
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{svc.Metadata.Name: h.Port()},
		Args:    []string{"--no-dns", "--ip-mode v4", "--implementation gvisor"},
	})
	h.WaitGetStatus(t, h.HTTP(), conn.URL(svc.Metadata.Name), http.StatusOK)

	status := h.Status(t)
	require.NotNil(t, status.Session)

	return conn, svc.Metadata.Name, status.Session.Metadata.Name
}

func testConnectReliabilityIngressDataPlaneRestart(t *testing.T, h *harness.H) {
	conn, svcName, sessName := startConnectReliabilityClient(t, h)

	for range 2 {
		previous := h.GetSession(t, sessName).Status.TotalConnections
		h.RestartComponent(t, "ingress-dataplane")
		waitConnectReliabilityReconnected(t, h, conn, sessName, previous,
			"octelium connect to reconnect after the ingress data plane replacement")
		h.WaitGetStatus(t, h.HTTP(), conn.URL(svcName), http.StatusOK)
	}
}

func testConnectReliabilityAPIBlackhole(t *testing.T, h *harness.H) {
	requireBlackhole(t, h)

	conn, svcName, sessName := startConnectReliabilityClient(t, h)
	previous := h.GetSession(t, sessName).Status.TotalConnections

	h.BlackholeConnections(t, conn, apiServerPort)

	waitConnectReliabilityReconnected(t, h, conn, sessName, previous,
		"octelium connect to detect the silently dropped API connection and reconnect")
	h.WaitGetStatus(t, h.HTTP(), conn.URL(svcName), http.StatusOK)
}

func testConnectReliabilityControlAndDataPlaneRestart(t *testing.T, h *harness.H) {
	conn, svcName, sessName := startConnectReliabilityClient(t, h)

	previous := h.GetSession(t, sessName).Status.TotalConnections
	replaced := h.RestartWorkloads(t, []string{"gwagent", "ingress-dataplane"}, []string{"default.octelium-api"})
	waitConnectReliabilityReconnected(t, h, conn, sessName, previous,
		"octelium connect to recover from a simultaneous control and data plane replacement")
	h.WaitGetStatus(t, h.HTTP(), conn.URL(svcName), http.StatusOK)

	zap.L().Info("octelium connect recovery after a control and data plane replacement",
		zap.Duration("replacement", replaced))
}

func testConnectReliabilityLocalDNSAcrossAPIRestarts(t *testing.T, h *harness.H) {
	h.Require(t, capRootTUN)

	svc := h.GetService(t, h.NewPublicService(t, "default").Metadata.Name)
	want := serviceAddrs(svc, dns.TypeA)
	require.True(t, len(want) > 0, "the Service %s has no IPv4 address", svc.Metadata.Name)

	name, _, _ := strings.Cut(svc.Metadata.Name, ".")
	fqdn := fmt.Sprintf("%s.default.local", name)
	listen := fmt.Sprintf("127.0.0.1:%d", h.Port())

	conn := h.Connect(t, harness.ConnectOpts{
		Root: true,
		Args: []string{"--no-dns", "--ip-mode v4", "--localdns",
			fmt.Sprintf("--localdns-addr %s", listen)},
	})

	c := h.DNSClientAt(listen)
	waitLocalDNSAddrs(t, h, c, fqdn, dns.TypeA, want)

	sessName := h.Status(t).Session.Metadata.Name
	for range 2 {
		previous := h.GetSession(t, sessName).Status.TotalConnections
		h.RestartService(t, "default.octelium-api")
		waitConnectReliabilityReconnected(t, h, conn, sessName, previous,
			"octelium connect with a local DNS server to reconnect after an API Server restart")
		waitLocalDNSAddrs(t, h, c, fqdn, dns.TypeA, want)
	}
}
