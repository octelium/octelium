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

	"github.com/go-resty/resty/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const mcpAccept = "application/json, text/event-stream"

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

	callArgs := func(name string, args map[string]any) map[string]any {
		return map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      name,
				"arguments": args,
			},
		}
	}

	callBody := func(name string) map[string]any {
		return callArgs(name, map[string]any{"input": "hello"})
	}

	listBody := func() map[string]any {
		return map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/list",
		}
	}

	post := func(c *resty.Client, body map[string]any) *resty.Request {
		return c.R().
			SetHeader("Content-Type", "application/json").
			SetHeader("Accept", mcpAccept).
			SetBody(body)
	}

	waitStatus := func(t *testing.T, c *resty.Client,
		what string, body map[string]any, want int) {
		t.Helper()

		h.Eventually(t, what, propagationBudget, func(ctx context.Context) error {
			res, err := post(c, body).SetContext(ctx).Post("/")
			if err != nil {
				return err
			}
			if res.StatusCode() != want {
				return errors.Errorf("got status %d, want %d: %s",
					res.StatusCode(), want, res.String())
			}
			return nil
		})
	}

	setPolicy := func(t *testing.T, name string, rules []*corev1.Policy_Spec_Rule) {
		t.Helper()

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
					Name: name,
					Spec: &corev1.Policy_Spec{
						Rules: rules,
					},
				},
			},
		}
		h.UpdateService(t, svc)
	}

	removePolicy := func(t *testing.T) {
		t.Helper()

		svc := h.GetService(t, "mcp-echo")
		svc.Spec.Authorization = nil
		h.UpdateService(t, svc)
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
		res, err := post(h.HTTP(), callBody("echo")).Post(h.ServiceURL(svc))
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
		c := h.ServiceClient(svc, token)

		res, err := post(c, callBody("echo")).
			SetHeader("Origin", "https://evil.example.com").
			Post("/")
		require.Nil(t, err)

		assert.Equal(t, http.StatusForbidden, res.StatusCode())
		assert.Contains(t, string(res.Body()), "-40004")

		res, err = post(c, callBody("echo")).
			SetHeader("Origin", fmt.Sprintf("https://console.%s", h.Domain)).
			Post("/")
		require.Nil(t, err)

		assert.Equal(t, http.StatusForbidden, res.StatusCode(), res.String())
		assert.Empty(t, res.Header().Get("Access-Control-Allow-Origin"))

		res, err = post(c, callBody("echo")).
			SetHeader("Origin", h.ServiceURL(svc)).
			Post("/")
		require.Nil(t, err)

		assert.Equal(t, http.StatusOK, res.StatusCode(), res.String())
	})

	t.Run("Authorization", func(t *testing.T) {
		setPolicy(t, "deny-mcp-tool", []*corev1.Policy_Spec_Rule{
			harness.MatchRule("deny-echo", 0,
				corev1.Policy_Spec_Rule_DENY,
				`ctx.request.mcp.method == "tools/call" && ctx.request.mcp.name == "echo"`),
			harness.MatchRule("allow-rest", 1,
				corev1.Policy_Spec_Rule_ALLOW, `true`),
		})

		c := h.ServiceClient(svc, token)

		waitStatus(t, c, "the denied MCP tool to be rejected",
			callBody("echo"), http.StatusForbidden)

		res, err := post(c, listBody()).Post("/")
		require.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), res.String())
	})

	t.Run("ToolName", func(t *testing.T) {
		setPolicy(t, "mcp-tool-allowlist", []*corev1.Policy_Spec_Rule{
			harness.MatchRule("deny-unlisted-tools", 0,
				corev1.Policy_Spec_Rule_DENY,
				`ctx.request.mcp.method == "tools/call" && !(ctx.request.mcp.name in ["echo"])`),
			harness.MatchRule("allow-rest", 1,
				corev1.Policy_Spec_Rule_ALLOW, `true`),
		})

		c := h.ServiceClient(svc, token)

		waitStatus(t, c, "the MCP tool that is not in the allow list to be rejected",
			callArgs("transfer", map[string]any{"amount": 10}), http.StatusForbidden)

		res, err := post(c, callBody("echo")).Post("/")
		require.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), res.String())

		res, err = post(c, listBody()).Post("/")
		require.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), res.String())

		removePolicy(t)

		waitStatus(t, c, "the MCP tool to be allowed once the Policy is removed",
			callArgs("transfer", map[string]any{"amount": 10}), http.StatusOK)
	})

	t.Run("ToolArguments", func(t *testing.T) {
		setPolicy(t, "mcp-tool-arguments", []*corev1.Policy_Spec_Rule{
			harness.MatchRule("deny-large-transfers", 0,
				corev1.Policy_Spec_Rule_DENY,
				`ctx.request.mcp.method == "tools/call" && ctx.request.mcp.name == "transfer" && double(ctx.request.mcp.http.bodyMap.params.arguments.amount) > 100.0`),
			harness.MatchRule("allow-rest", 1,
				corev1.Policy_Spec_Rule_ALLOW, `true`),
		})

		c := h.ServiceClient(svc, token)

		waitStatus(t, c, "the MCP tool call above the argument limit to be rejected",
			callArgs("transfer", map[string]any{"amount": 500}), http.StatusForbidden)

		result, err := newSession(t).CallTool(t.Context(), &mcp.CallToolParams{
			Name:      "transfer",
			Arguments: map[string]any{"amount": 10},
		})
		require.Nil(t, err)

		textContent, ok := result.Content[0].(*mcp.TextContent)
		require.True(t, ok)
		assert.Equal(t, "transferred 10", textContent.Text)

		res, err := post(c, callBody("echo")).Post("/")
		require.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), res.String())

		removePolicy(t)

		waitStatus(t, c, "the same MCP tool call to be allowed once the Policy is removed",
			callArgs("transfer", map[string]any{"amount": 500}), http.StatusOK)
	})

	t.Run("CORS", func(t *testing.T) {
		svc := h.GetService(t, "mcp-echo")
		original := svc.Spec.Config.Type

		t.Cleanup(func() {
			svc := h.GetService(t, "mcp-echo")
			svc.Spec.Config.Type = original
			h.UpdateService(t, svc)
		})

		origin := fmt.Sprintf("https://console.%s", h.Domain)

		mcpCfg := svc.Spec.Config.GetMcp()
		if mcpCfg == nil {
			mcpCfg = &corev1.Service_Spec_Config_MCP{}
		}
		mcpCfg.Cors = &corev1.Service_Spec_Config_HTTP_CORS{
			AllowClusterServices: true,
		}
		svc.Spec.Config.Type = &corev1.Service_Spec_Config_Mcp{Mcp: mcpCfg}
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

		res, err := post(h.ServiceClient(svc, token), callBody("echo")).
			SetHeader("Origin", origin).
			Post("/")
		require.Nil(t, err)

		assert.Equal(t, http.StatusOK, res.StatusCode(), res.String())
		assert.Equal(t, origin, res.Header().Get("Access-Control-Allow-Origin"))
	})
}
