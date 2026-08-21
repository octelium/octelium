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
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mcpBearerTransport struct {
	token string
	next  http.RoundTripper
}

func (t *mcpBearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", t.token))
	return t.next.RoundTrip(req)
}

func applyMCPGateway(t *testing.T, a *applyCtx) {
	h := a.h

	h.Require(t, capHostPortIngress)
	h.MustWaitService(t, "mcp-echo")

	svc := h.GetService(t, "mcp-echo")

	usr := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
		InlinePolicies: harness.InlineAllowAny("allow-mcp-e2e"),
	})
	token := h.AccessToken(t, usr)

	httpC := &http.Client{
		Transport: &mcpBearerTransport{token: token, next: http.DefaultTransport},
	}

	newSession := func(t *testing.T) *mcp.ClientSession {
		t.Helper()

		client := mcp.NewClient(&mcp.Implementation{
			Name:    "octelium-e2e",
			Version: "1.0.0",
		}, nil)

		session, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
			Endpoint:             h.ServiceURL(svc),
			HTTPClient:           httpC,
			DisableStandaloneSSE: true,
		}, nil)
		require.Nil(t, err)

		t.Cleanup(func() { session.Close() })
		return session
	}

	callBody := func(name string) map[string]any {
		return map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      name,
				"arguments": map[string]any{"input": "hello"},
			},
		}
	}

	t.Run("Session", func(t *testing.T) {
		session := newSession(t)

		toolsResult, err := session.ListTools(t.Context(), nil)
		require.Nil(t, err)

		assert.True(t, slices.ContainsFunc(toolsResult.Tools, func(r *mcp.Tool) bool {
			return r.Name == "echo"
		}))

		input := utilrand.GetRandomString(32)

		result, err := session.CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "echo",
			Arguments: map[string]any{"input": input},
		})
		require.Nil(t, err)

		textContent, ok := result.Content[0].(*mcp.TextContent)
		require.True(t, ok)
		assert.Equal(t, input, textContent.Text)
	})

	t.Run("Unauthenticated", func(t *testing.T) {
		res, err := h.HTTP().R().
			SetHeader("Content-Type", "application/json").
			SetBody(callBody("echo")).
			Post(h.ServiceURL(svc))
		require.Nil(t, err)
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode())
	})

	t.Run("StandaloneSSE", func(t *testing.T) {
		res, err := h.ServiceClient(svc, token).R().Get("/")
		require.Nil(t, err)

		assert.Equal(t, http.StatusMethodNotAllowed, res.StatusCode())
		assert.Contains(t, string(res.Body()), "-40003")
	})

	t.Run("Origin", func(t *testing.T) {
		res, err := h.ServiceClient(svc, token).R().
			SetHeader("Content-Type", "application/json").
			SetHeader("Origin", "https://evil.example.com").
			SetBody(callBody("echo")).
			Post("/")
		require.Nil(t, err)

		assert.Equal(t, http.StatusForbidden, res.StatusCode())
		assert.Contains(t, string(res.Body()), "-40004")
	})

	t.Run("Authorization", func(t *testing.T) {
		svc := h.GetService(t, "mcp-echo")
		original := svc.Spec.Authorization

		t.Cleanup(func() {
			svc := h.GetService(t, "mcp-echo")
			svc.Spec.Authorization = original
			h.UpdateService(t, svc)
		})

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Name: "deny-mcp-tool",
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							harness.MatchRule("deny-echo", 0,
								corev1.Policy_Spec_Rule_DENY,
								`ctx.request.mcp.method == "tools/call" && ctx.request.mcp.name == "echo"`),
							harness.MatchRule("allow-rest", 10,
								corev1.Policy_Spec_Rule_ALLOW, `true`),
						},
					},
				},
			},
		}
		h.UpdateService(t, svc)

		c := h.ServiceClient(svc, token)

		h.Eventually(t, "the denied MCP tool to be rejected", propagationBudget,
			func(ctx context.Context) error {
				res, err := c.R().SetContext(ctx).
					SetHeader("Content-Type", "application/json").
					SetBody(callBody("echo")).
					Post("/")
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusForbidden {
					return errors.Errorf("got status %d, want %d",
						res.StatusCode(), http.StatusForbidden)
				}
				return nil
			})

		res, err := c.R().
			SetHeader("Content-Type", "application/json").
			SetBody(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "tools/list",
			}).
			Post("/")
		require.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), res.String())
	})

	t.Run("CORS", func(t *testing.T) {
		svc := h.GetService(t, "mcp-echo")

		t.Cleanup(func() {
			svc := h.GetService(t, "mcp-echo")
			svc.Spec.Config.GetMcp().Cors = nil
			h.UpdateService(t, svc)
		})

		origin := fmt.Sprintf("https://console.%s", h.Domain)

		svc.Spec.Config.GetMcp().Cors = &corev1.Service_Spec_Config_HTTP_CORS{
			AllowClusterServices: true,
		}
		h.UpdateService(t, svc)

		h.Eventually(t, "the MCP CORS preflight to be answered", propagationBudget,
			func(ctx context.Context) error {
				res, err := h.HTTP().R().SetContext(ctx).
					SetHeader("Origin", origin).
					SetHeader("Access-Control-Request-Method", http.MethodPost).
					SetHeader("Access-Control-Request-Headers",
						"content-type,mcp-session-id,mcp-protocol-version").
					Options(h.ServiceURL(svc))
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusNoContent {
					return errors.Errorf("got status %d, want %d",
						res.StatusCode(), http.StatusNoContent)
				}
				if got := res.Header().Get("Access-Control-Allow-Origin"); got != origin {
					return errors.Errorf("got ACAO %q, want %q", got, origin)
				}
				if got := res.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
					return errors.Errorf("got ACAC %q", got)
				}
				return nil
			})

		res, err := h.ServiceClient(svc, token).R().
			SetHeader("Content-Type", "application/json").
			SetHeader("Origin", origin).
			SetBody(callBody("echo")).
			Post("/")
		require.Nil(t, err)

		assert.Equal(t, http.StatusOK, res.StatusCode(), res.String())
		assert.Equal(t, origin, res.Header().Get("Access-Control-Allow-Origin"))
	})
}
