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
	"net/http"
	"testing"

	"github.com/octelium/octelium/cluster/e2e/harness"
	"go.uber.org/zap"
)

func testClusterReady(t *testing.T, h *harness.H) {
	h.MustRun(t, "id")
	h.MustRun(t, "mkdir -p ~/.ssh")
	h.MustRun(t, "chmod 700 ~/.ssh")

	zap.L().Info("Harness environment", zap.Strings("env", envForLog()))

	for _, component := range []string{
		"nocturne",
		"octovigil",
		"ingress",
		"rscserver",
		"ingress-dataplane",
	} {
		if err := h.WaitDeployment(t.Context(), "octelium-"+component); err != nil {
			t.Fatalf("%+v", err)
		}
	}

	if err := h.WaitDaemonSet(t.Context(), "octelium-gwagent"); err != nil {
		t.Fatalf("%+v", err)
	}

	h.StartLogStream(t.Context(), "-l octelium.com/component=nocturne")
	h.StartLogStream(t.Context(), "-l octelium.com/component=octovigil")

	h.MustRun(t, "kubectl get pods -A")
	h.MustRun(t, "kubectl get deployment -A")
	h.MustRun(t, "kubectl get svc -A")
	h.MustRun(t, "kubectl get daemonset -A")

	h.MustWaitService(t, "demo-nginx", "portal", "default")
}

func testCLIVersions(t *testing.T, h *harness.H) {
	h.MustRun(t, "octelium version")
	h.MustRun(t, "octelium version -o json")
	h.MustRun(t, "octeliumctl version")
	h.MustRun(t, "octelium status")

	h.MustRun(t, "octeliumctl get rgn default")
	h.MustRun(t, "octeliumctl get gw -o yaml")
}

func testIngressPublic(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)

	h.GetStatus(t, h.HTTP(), h.ClusterURL(), http.StatusOK)
	h.GetStatus(t, h.HTTPPublic("demo-nginx"), "/", http.StatusUnauthorized)
	h.GetStatus(t, h.HTTPPublic("portal"), "/", http.StatusUnauthorized)
}

func testComponentHealth(t *testing.T, h *harness.H) {
	zap.L().Debug("Checking components",
		zap.Time("installedAt", h.State.InstalledAt))

	for _, component := range []string{
		"ingress",
		"ingress-dataplane",
		"nocturne",
		"rscserver",
		"octovigil",
		"gwagent",
	} {
		h.CheckComponentRestarts(t, component)
	}
}
