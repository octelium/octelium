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
	"fmt"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/stretchr/testify/require"
)

var applyServices = []string{
	"nginx",
	"google",
	"postgres-main",
	"essh",
	"pg.production",
	"redis",
	"ws-echo",
	"nats",
	"mariadb",
	"s3",
	"opensearch",
	"mcp-echo",
	"clickhouse",
	"llama",
	"mongo",
	"mysql8",
	"mysql9",
}

type applyCtx struct {
	h    *harness.H
	conn *harness.Conn
}

func (a *applyCtx) port(svc string) int { return a.conn.Port(svc) }

func (a *applyCtx) addr(svc string) string { return a.conn.Addr(svc) }

func (a *applyCtx) url(svc string) string { return a.conn.URL(svc) }

func testApply(t *testing.T, h *harness.H) {
	_, err := h.CoreC().ListService(t.Context(), &corev1.ListServiceOptions{})
	require.Nil(t, err)

	wsSrv := h.StartHTTPUpstream(t, &harness.TestSrvHTTP{IsWS: true})
	mcpSrv := h.StartMCPUpstream(t, nil)

	t.Run("Secrets", func(t *testing.T) {
		h.MustRun(t, "octeliumctl create secret password --value password")
		h.MustRun(t, fmt.Sprintf("octeliumctl create secret kubeconfig -f %s",
			h.State.KubeconfigPath))
	})

	dir, names := renderManifests(t, manifestVars{
		WSEchoPort: wsSrv.Port,
		MCPPort:    mcpSrv.Port,
	})

	t.Run("Apply", func(t *testing.T) {
		h.MustRun(t, fmt.Sprintf("octeliumctl apply %s", dir))
		h.MustRun(t, fmt.Sprintf("octeliumctl apply %s", filepath.Join(dir, names[0])))

		h.MustWaitService(t, "nginx-anonymous", "nginx")
	})

	t.Run("PublicAccess", func(t *testing.T) {
		h.Require(t, capHostPortIngress)

		h.GetStatus(t, h.HTTPPublic("nginx-anonymous"), "/", http.StatusOK)
		h.GetStatus(t, h.HTTPPublic("nginx"), "/", http.StatusUnauthorized)
	})

	publish := map[string]int{}
	for _, svc := range applyServices {
		publish[svc] = h.Port()
	}

	conn := h.Connect(t, harness.ConnectOpts{
		Publish:  publish,
		UseESSH:  true,
		ServeAll: true,
	})

	a := &applyCtx{h: h, conn: conn}

	for _, phase := range []struct {
		name string
		fn   func(t *testing.T, a *applyCtx)
	}{
		{"Nginx", applyNginx},
		{"Google", applyGoogle},
		{"PostgresMain", applyPostgresMain},
		{"PostgresContainer", applyPostgresContainer},
		{"ESSH", applyESSH},
		{"Redis", applyRedis},
		{"WebSocket", applyWebSocket},
		{"NATS", applyNATS},
		{"MCP", applyMCP},
		{"OpenSearch", applyOpenSearch},
		{"ClickHouse", applyClickHouse},
		{"MySQL", applyMySQL},
		{"S3", applyS3},
		{"MongoDB", applyMongo},
		{"LLM", applyLLM},
	} {
		t.Run(phase.name, func(t *testing.T) {
			phase.fn(t, a)
		})
	}
}

func sshUser(t *testing.T, h *harness.H) string {
	t.Helper()

	status := h.Status(t)
	require.NotNil(t, status.Session)

	return status.Session.Metadata.Name
}

func requireAMD64(t *testing.T, why string) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skipf("%s is only exercised on amd64 (running on %s)", why, runtime.GOARCH)
	}
}
