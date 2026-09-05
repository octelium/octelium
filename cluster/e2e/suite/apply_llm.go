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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func applyLLMGateway(t *testing.T, a *applyCtx, upstream *harness.LLMSrv) {
	h := a.h

	h.Require(t, capHostPortIngress)
	h.MustWaitService(t, "llm-echo")

	svc := h.GetService(t, "llm-echo")

	usr := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
		InlinePolicies: harness.InlineAllowAny("allow-llm-e2e"),
	})
	token := h.AccessToken(t, usr)

	h.WaitStatus(t, h.ServiceClient(svc, token), "/v1/models", http.StatusOK)

	newClient := func() *openai.Client {
		ret := openai.NewClient(
			option.WithBaseURL(fmt.Sprintf("%s/v1", h.ServiceURL(svc))),
			option.WithAPIKey(token),
			option.WithMaxRetries(5),
		)
		return &ret
	}

	t.Run("Completion", func(t *testing.T) {
		res, err := newClient().Chat.Completions.New(t.Context(),
			openai.ChatCompletionNewParams{
				Messages: []openai.ChatCompletionMessageParamUnion{
					openai.UserMessage("What is zero trust?"),
				},
				Model: "e2e-model",
			})
		require.Nil(t, err)

		assert.Equal(t, "octelium", res.Choices[0].Message.Content)
		assert.Equal(t, "/v1/chat/completions", upstream.LastPath())
		assert.Equal(t, "e2e-model", upstream.LastModel())
	})

	t.Run("CredentialsNotForwarded", func(t *testing.T) {
		assert.Empty(t, upstream.LastAuthorization())
	})

	t.Run("Streaming", func(t *testing.T) {
		stream := newClient().Chat.Completions.NewStreaming(t.Context(),
			openai.ChatCompletionNewParams{
				Messages: []openai.ChatCompletionMessageParamUnion{
					openai.UserMessage("What are the largest cities?"),
				},
				Model: "e2e-model",
			})

		acc := openai.ChatCompletionAccumulator{}

		count := 0
		for stream.Next() {
			chunk := stream.Current()
			acc.AddChunk(chunk)
			if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
				count++
			}
		}

		assert.Nil(t, stream.Err())
		assert.True(t, count > 10, "got %d streamed chunks", count)

		zap.L().Debug("LLM gateway streaming", zap.Int("count", count))
	})

	t.Run("UnknownRoute", func(t *testing.T) {
		cnt := upstream.ReqCount()

		res := h.GetStatus(t, h.ServiceClient(svc, token),
			"/v1/octelium-unknown", http.StatusNotFound)

		assert.Contains(t, string(res.Body()), "octelium_not_found")
		assert.Equal(t, cnt, upstream.ReqCount())
	})

	t.Run("Unauthenticated", func(t *testing.T) {
		cnt := upstream.ReqCount()

		h.GetStatus(t, h.ServiceClient(svc, ""), "/v1/models", http.StatusUnauthorized)

		assert.Equal(t, cnt, upstream.ReqCount())
	})

	t.Run("ModelRewrite", func(t *testing.T) {
		svc := h.GetService(t, "llm-echo")

		t.Cleanup(func() {
			svc := h.GetService(t, "llm-echo")
			svc.Spec.Config.GetLlm().Model = nil
			h.UpdateService(t, svc)
		})

		svc.Spec.Config.GetLlm().Model = &corev1.Service_Spec_Config_LLM_Model{
			Type: &corev1.Service_Spec_Config_LLM_Model_Value{
				Value: "octelium-rewritten",
			},
		}
		h.UpdateService(t, svc)

		h.Eventually(t, "the upstream to observe the rewritten model",
			propagationBudget, func(ctx context.Context) error {
				_, err := newClient().Chat.Completions.New(ctx,
					openai.ChatCompletionNewParams{
						Messages: []openai.ChatCompletionMessageParamUnion{
							openai.UserMessage("hello"),
						},
						Model: "e2e-model",
					})
				if err != nil {
					return err
				}
				if got := upstream.LastModel(); got != "octelium-rewritten" {
					return errors.Errorf("the upstream model is %q", got)
				}
				return nil
			})
	})

	t.Run("Authorization", func(t *testing.T) {
		svc := h.GetService(t, "llm-echo")
		original := svc.Spec.Authorization

		t.Cleanup(func() {
			svc := h.GetService(t, "llm-echo")
			svc.Spec.Authorization = original
			h.UpdateService(t, svc)
		})

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Name: "deny-llm-model",
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							harness.MatchRule("deny-model", 0,
								corev1.Policy_Spec_Rule_DENY,
								`ctx.request.llm.model == "e2e-denied"`),
							harness.MatchRule("allow-rest", 1,
								corev1.Policy_Spec_Rule_ALLOW, `true`),
						},
					},
				},
			},
		}
		h.UpdateService(t, svc)

		c := h.ServiceClient(svc, token)

		h.Eventually(t, "the denied model to be rejected", propagationBudget,
			func(ctx context.Context) error {
				res, err := c.R().SetContext(ctx).
					SetHeader("Content-Type", "application/json").
					SetBody(map[string]any{
						"model": "e2e-denied",
						"messages": []any{
							map[string]any{"role": "user", "content": "hello"},
						},
					}).
					Post("/v1/chat/completions")
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
				"model": "e2e-model",
				"messages": []any{
					map[string]any{"role": "user", "content": "hello"},
				},
			}).
			Post("/v1/chat/completions")
		require.Nil(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode(), res.String())
	})

	t.Run("CORS", func(t *testing.T) {
		svc := h.GetService(t, "llm-echo")

		t.Cleanup(func() {
			svc := h.GetService(t, "llm-echo")
			svc.Spec.Config.GetLlm().Cors = nil
			h.UpdateService(t, svc)
		})

		origin := fmt.Sprintf("https://console.%s", h.Domain)

		svc.Spec.Config.GetLlm().Cors = &corev1.Service_Spec_Config_HTTP_CORS{
			AllowClusterServices: true,
		}
		h.UpdateService(t, svc)

		h.Eventually(t, "the CORS preflight to be answered", propagationBudget,
			func(ctx context.Context) error {
				res, err := h.HTTP().R().SetContext(ctx).
					SetHeader("Origin", origin).
					SetHeader("Access-Control-Request-Method", http.MethodPost).
					SetHeader("Access-Control-Request-Headers", "content-type,authorization").
					Options(fmt.Sprintf("%s/v1/chat/completions", h.ServiceURL(svc)))
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
				return nil
			})
	})

	t.Run("Operations", func(t *testing.T) {
		applyLLMOperations(t, h, svc, token, upstream)
	})

	t.Run("Limits", func(t *testing.T) {
		applyLLMLimits(t, h, svc, token, upstream)
	})

	t.Run("Configuration", func(t *testing.T) {
		applyLLMConfiguration(t, h, svc, token, upstream)
	})

	t.Run("InferencePlugins", func(t *testing.T) {
		applyLLMInferencePlugins(t, h, svc, token, upstream)
	})

	t.Run("SemanticPlugins", func(t *testing.T) {
		applyLLMSemanticPlugins(t, h, svc, token, upstream)
	})

	t.Run("HTTPPlugins", func(t *testing.T) {
		applyLLMHTTPPlugins(t, h, svc, token, upstream)
	})
}

func setLLMConfig(t *testing.T, h *harness.H, name string,
	cfg *corev1.Service_Spec_Config_LLM) *corev1.Service {
	t.Helper()

	svc := h.GetService(t, name)
	svc.Spec.Config.Type = &corev1.Service_Spec_Config_Llm{Llm: cfg}
	return h.UpdateService(t, svc)
}

func llmRequest(ctx context.Context, h *harness.H, svc *corev1.Service,
	token, method, path string, body any) (int, []byte, http.Header, error) {
	req := h.ServiceClient(svc, token).SetRetryCount(0).R().SetContext(ctx)
	if body != nil {
		req.SetHeader("Content-Type", "application/json").SetBody(body)
	}

	res, err := req.Execute(method, path)
	if err != nil {
		return 0, nil, nil, err
	}
	return res.StatusCode(), res.Body(), res.Header().Clone(), nil
}

func waitLLMForwarded(t *testing.T, h *harness.H, svc *corev1.Service,
	token, method, path string, body any, upstream *harness.LLMSrv,
	check func(map[string]any) error) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("%s %s to reach the LLM upstream", method, path),
		propagationBudget, func(ctx context.Context) error {
			before := upstream.ReqCountPath(path)
			status, response, _, err := llmRequest(ctx, h, svc, token, method, path, body)
			if err != nil {
				return err
			}
			if status < http.StatusOK || status >= http.StatusMultipleChoices {
				return errors.Errorf("got status %d: %s", status, response)
			}
			if upstream.ReqCountPath(path) == before {
				return errors.New("the upstream request count did not advance")
			}
			if check != nil {
				return check(upstream.BodyForPath(path))
			}
			return nil
		})
}

func waitLLMStatus(t *testing.T, h *harness.H, svc *corev1.Service,
	token, method, path string, body any, status int, upstream *harness.LLMSrv) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("%s %s to return %d", method, path, status),
		propagationBudget, func(ctx context.Context) error {
			before := upstream.ReqCount()
			got, response, _, err := llmRequest(ctx, h, svc, token, method, path, body)
			if err != nil {
				return err
			}
			if got != status {
				return errors.Errorf("got status %d, want %d: %s", got, status, response)
			}
			if upstream != nil && upstream.ReqCount() != before {
				return errors.New("the rejected request reached the upstream")
			}
			return nil
		})
}

func applyLLMOperations(t *testing.T, h *harness.H, svc *corev1.Service,
	token string, upstream *harness.LLMSrv) {
	type operation struct {
		method string
		path   string
		body   any
	}

	chat := map[string]any{
		"model":    "e2e-model",
		"messages": []any{map[string]any{"role": "user", "content": "hello"}},
	}
	gemini := map[string]any{
		"contents": []any{map[string]any{
			"role": "user", "parts": []any{map[string]any{"text": "hello"}},
		}},
	}
	bedrock := map[string]any{
		"messages": []any{map[string]any{
			"role": "user", "content": []any{map[string]any{"text": "hello"}},
		}},
		"inferenceConfig": map[string]any{"maxTokens": 64},
	}

	tests := []struct {
		name       string
		protocol   corev1.Service_Spec_Config_LLM_Protocol
		operations []operation
	}{
		{
			name:     "OpenAI",
			protocol: corev1.Service_Spec_Config_LLM_OPENAI,
			operations: []operation{
				{http.MethodPost, "/v1/chat/completions", chat},
				{http.MethodPost, "/v1/responses", map[string]any{
					"model": "e2e-model", "input": "hello",
				}},
				{http.MethodPost, "/v1/completions", map[string]any{
					"model": "e2e-model", "prompt": "hello",
				}},
				{http.MethodPost, "/v1/embeddings", map[string]any{
					"model": "e2e-embedding", "input": "hello",
				}},
				{http.MethodPost, "/v1/moderations", map[string]any{
					"model": "e2e-moderation", "input": "hello",
				}},
				{http.MethodGet, "/v1/models", nil},
				{http.MethodGet, "/v1/models/e2e-model", nil},
			},
		},
		{
			name:     "Anthropic",
			protocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
			operations: []operation{
				{http.MethodPost, "/v1/messages", map[string]any{
					"model": "e2e-model", "max_tokens": 64, "messages": chat["messages"],
				}},
				{http.MethodPost, "/v1/messages/count_tokens", map[string]any{
					"model": "e2e-model", "messages": chat["messages"],
				}},
				{http.MethodGet, "/v1/models", nil},
				{http.MethodGet, "/v1/models/e2e-model", nil},
			},
		},
		{
			name:     "Gemini",
			protocol: corev1.Service_Spec_Config_LLM_GEMINI,
			operations: []operation{
				{http.MethodPost, "/v1beta/models/e2e-model:generateContent", gemini},
				{http.MethodPost, "/v1beta/models/e2e-model:streamGenerateContent", gemini},
				{http.MethodPost, "/v1beta/models/e2e-model:countTokens", gemini},
				{http.MethodPost, "/v1beta/models/e2e-embedding:embedContent", map[string]any{
					"content": map[string]any{"parts": []any{map[string]any{"text": "hello"}}},
				}},
				{http.MethodPost, "/v1beta/models/e2e-embedding:batchEmbedContents", map[string]any{
					"requests": []any{map[string]any{
						"content": map[string]any{"parts": []any{map[string]any{"text": "hello"}}},
					}},
				}},
				{http.MethodGet, "/v1beta/models", nil},
				{http.MethodGet, "/v1beta/models/e2e-model", nil},
			},
		},
		{
			name:     "Bedrock",
			protocol: corev1.Service_Spec_Config_LLM_BEDROCK,
			operations: []operation{
				{http.MethodPost, "/model/e2e-model/converse", bedrock},
				{http.MethodPost, "/model/e2e-model/converse-stream", bedrock},
				{http.MethodPost, "/model/e2e-model/invoke", map[string]any{
					"anthropic_version": "bedrock-2023-05-31", "max_tokens": 64,
					"messages": chat["messages"],
				}},
				{http.MethodPost, "/model/e2e-model/invoke-with-response-stream", map[string]any{
					"anthropic_version": "bedrock-2023-05-31", "max_tokens": 64,
					"messages": chat["messages"],
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc = setLLMConfig(t, h, svc.Metadata.Name,
				&corev1.Service_Spec_Config_LLM{Protocol: tt.protocol})
			for _, operation := range tt.operations {
				waitLLMForwarded(t, h, svc, token, operation.method,
					operation.path, operation.body, upstream, nil)
			}
		})
	}
}

func applyLLMLimits(t *testing.T, h *harness.H, svc *corev1.Service,
	token string, upstream *harness.LLMSrv) {
	svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
		Protocol: corev1.Service_Spec_Config_LLM_OPENAI,
		Limits: &corev1.Service_Spec_Config_LLM_Limits{
			MaxRequestBytes:         1024,
			MaxEstimatedInputTokens: 64,
			MaxOutputTokens:         32,
			MaxTools:                1,
			MaxToolSchemaBytes:      128,
		},
	})

	tests := []struct {
		name   string
		body   any
		status int
	}{
		{
			name: "RequestBytes",
			body: map[string]any{
				"model": "e2e-model",
				"messages": []any{map[string]any{
					"role": "user", "content": strings.Repeat("x", 2048),
				}},
			},
			status: http.StatusRequestEntityTooLarge,
		},
		{
			name: "EstimatedInputTokens",
			body: map[string]any{
				"model": "e2e-model",
				"messages": []any{map[string]any{
					"role": "user", "content": strings.Repeat("input ", 80),
				}},
			},
			status: http.StatusRequestEntityTooLarge,
		},
		{
			name: "OutputTokens",
			body: map[string]any{
				"model": "e2e-model", "max_tokens": 33,
				"messages": []any{map[string]any{"role": "user", "content": "hello"}},
			},
			status: http.StatusBadRequest,
		},
		{
			name: "Tools",
			body: map[string]any{
				"model":    "e2e-model",
				"messages": []any{map[string]any{"role": "user", "content": "hello"}},
				"tools": []any{
					map[string]any{"type": "function", "function": map[string]any{"name": "one"}},
					map[string]any{"type": "function", "function": map[string]any{"name": "two"}},
				},
			},
			status: http.StatusBadRequest,
		},
		{
			name: "ToolSchemaBytes",
			body: map[string]any{
				"model":    "e2e-model",
				"messages": []any{map[string]any{"role": "user", "content": "hello"}},
				"tools": []any{map[string]any{
					"type": "function", "function": map[string]any{
						"name": "large",
						"parameters": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"value": map[string]any{
									"type": "string", "description": strings.Repeat("schema", 64),
								},
							},
						},
					},
				}},
			},
			status: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waitLLMStatus(t, h, svc, token, http.MethodPost,
				"/v1/chat/completions", tt.body, tt.status, upstream)
		})
	}

	t.Run("WithinLimits", func(t *testing.T) {
		waitLLMForwarded(t, h, svc, token, http.MethodPost,
			"/v1/chat/completions", map[string]any{
				"model": "e2e-model", "max_tokens": 16,
				"messages": []any{map[string]any{"role": "user", "content": "hello"}},
			}, upstream, nil)
	})

	t.Run("StreamEventBytes", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Protocol: corev1.Service_Spec_Config_LLM_OPENAI,
			Model: &corev1.Service_Spec_Config_LLM_Model{
				Type: &corev1.Service_Spec_Config_LLM_Model_Value{
					Value: "stream-limit-model",
				},
			},
			Limits: &corev1.Service_Spec_Config_LLM_Limits{
				MaxStreamEventBytes: 32,
			},
		})

		h.Eventually(t, "large stream events to be forwarded transparently",
			propagationBudget, func(ctx context.Context) error {
				before := upstream.ReqCountPath("/v1/chat/completions")
				status, response, _, err := llmRequest(ctx, h, svc, token,
					http.MethodPost, "/v1/chat/completions", map[string]any{
						"model": "requested-model", "stream": true,
						"messages": []any{map[string]any{
							"role": "user", "content": "stream limits",
						}},
					})
				if err != nil {
					return err
				}
				if status != http.StatusOK || !strings.Contains(string(response), "tok-15") ||
					!strings.Contains(string(response), "[DONE]") {
					return errors.Errorf("got status %d and stream %s", status, response)
				}
				if upstream.ReqCountPath("/v1/chat/completions") == before ||
					upstream.BodyForPath("/v1/chat/completions")["model"] != "stream-limit-model" {
					return errors.New("the stream event limit configuration did not reach the upstream")
				}
				return nil
			})
	})
}

func applyLLMConfiguration(t *testing.T, h *harness.H, svc *corev1.Service,
	token string, upstream *harness.LLMSrv) {
	chat := func(model string) map[string]any {
		return map[string]any{
			"model":    model,
			"messages": []any{map[string]any{"role": "user", "content": "hello"}},
		}
	}

	t.Run("ModelAndReasoning", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Protocol: corev1.Service_Spec_Config_LLM_OPENAI,
			Model: &corev1.Service_Spec_Config_LLM_Model{
				Type: &corev1.Service_Spec_Config_LLM_Model_Eval{
					Eval: `ctx.request.llm.model + "-cel"`,
				},
			},
			Reasoning: &corev1.Service_Spec_Config_LLM_Reasoning{
				Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{
					Level: corev1.Service_Spec_Config_LLM_Reasoning_HIGH,
				},
			},
		})

		waitLLMForwarded(t, h, svc, token, http.MethodPost,
			"/v1/chat/completions", chat("requested"), upstream,
			func(body map[string]any) error {
				if got := body["model"]; got != "requested-cel" {
					return errors.Errorf("got model %q, want %q", got, "requested-cel")
				}
				if got := body["reasoning_effort"]; got != "high" {
					return errors.Errorf("got reasoning effort %q, want %q", got, "high")
				}
				return nil
			})
	})

	t.Run("PolicyBackedModelAndReasoning", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Protocol: corev1.Service_Spec_Config_LLM_OPENAI,
			Model: &corev1.Service_Spec_Config_LLM_Model{
				Type: &corev1.Service_Spec_Config_LLM_Model_Opa{
					Opa: `
package octelium.eval

result := sprintf("%s-opa", [input.ctx.request.llm.model])
`,
				},
			},
			Reasoning: &corev1.Service_Spec_Config_LLM_Reasoning{
				Type: &corev1.Service_Spec_Config_LLM_Reasoning_Eval{
					Eval: `ctx.request.llm.model == "requested" ? "MEDIUM" : ""`,
				},
			},
		})

		waitLLMForwarded(t, h, svc, token, http.MethodPost,
			"/v1/chat/completions", chat("requested"), upstream,
			func(body map[string]any) error {
				if body["model"] != "requested-opa" || body["reasoning_effort"] != "medium" {
					return errors.Errorf("unexpected policy-backed configuration: %#v", body)
				}
				return nil
			})
	})

	t.Run("ProtocolReasoning", func(t *testing.T) {
		tests := []struct {
			name     string
			protocol corev1.Service_Spec_Config_LLM_Protocol
			path     string
			body     any
			check    func(map[string]any) error
		}{
			{
				name:     "Anthropic",
				protocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
				path:     "/v1/messages",
				body: map[string]any{
					"model": "requested", "max_tokens": 4096,
					"messages": chat("requested")["messages"],
				},
				check: func(body map[string]any) error {
					thinking, _ := body["thinking"].(map[string]any)
					if thinking["budget_tokens"] != float64(2048) {
						return errors.Errorf("got Anthropic thinking %#v", thinking)
					}
					return nil
				},
			},
			{
				name:     "Gemini",
				protocol: corev1.Service_Spec_Config_LLM_GEMINI,
				path:     "/v1beta/models/requested:generateContent",
				body: map[string]any{
					"contents": []any{map[string]any{
						"role": "user", "parts": []any{map[string]any{"text": "hello"}},
					}},
				},
				check: func(body map[string]any) error {
					generation, _ := body["generationConfig"].(map[string]any)
					thinking, _ := generation["thinkingConfig"].(map[string]any)
					if thinking["thinkingBudget"] != float64(2048) {
						return errors.Errorf("got Gemini thinking %#v", thinking)
					}
					return nil
				},
			},
			{
				name:     "Bedrock",
				protocol: corev1.Service_Spec_Config_LLM_BEDROCK,
				path:     "/model/requested/converse",
				body: map[string]any{
					"messages": []any{map[string]any{
						"role": "user", "content": []any{map[string]any{"text": "hello"}},
					}},
				},
				check: func(body map[string]any) error {
					fields, _ := body["additionalModelRequestFields"].(map[string]any)
					reasoning, _ := fields["reasoning_config"].(map[string]any)
					if reasoning["budget_tokens"] != float64(2048) {
						return errors.Errorf("got Bedrock reasoning %#v", reasoning)
					}
					return nil
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc = setLLMConfig(t, h, svc.Metadata.Name,
					&corev1.Service_Spec_Config_LLM{
						Protocol: tt.protocol,
						Reasoning: &corev1.Service_Spec_Config_LLM_Reasoning{
							Type: &corev1.Service_Spec_Config_LLM_Reasoning_MaxTokens{
								MaxTokens: 2048,
							},
						},
					})
				waitLLMForwarded(t, h, svc, token, http.MethodPost,
					tt.path, tt.body, upstream, tt.check)
			})
		}
	})

	t.Run("HeadersAndUpstreamAuth", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Protocol: corev1.Service_Spec_Config_LLM_OPENAI,
			Auth: &corev1.Service_Spec_Config_HTTP_Auth{
				Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_{
					Bearer: &corev1.Service_Spec_Config_HTTP_Auth_Bearer{
						Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{
							FromSecret: "password",
						},
					},
				},
			},
			Header: &corev1.Service_Spec_Config_HTTP_Header{
				AddRequestHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
					{
						Key: "X-E2E-LLM-Request",
						Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
							Value: "upstream",
						},
					},
				},
				AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
					{
						Key: "X-E2E-LLM-Response",
						Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{
							Value: "downstream",
						},
					},
				},
			},
			Visibility: &corev1.Service_Spec_Config_LLM_Visibility{
				EnableRequestBody:      true,
				EnableRequestBodyMap:   true,
				EnableResponseBody:     true,
				EnableResponseBodyMap:  true,
				IncludeRequestHeaders:  []string{"X-E2E-LLM-Request"},
				IncludeResponseHeaders: []string{"X-E2E-LLM-Response"},
				ExcludeRequestHeaders:  []string{"Authorization"},
				ExcludeResponseHeaders: []string{"Set-Cookie"},
			},
		})

		h.Eventually(t, "the LLM upstream authentication and headers to propagate",
			propagationBudget, func(ctx context.Context) error {
				res, err := h.ServiceClient(svc, token).R().SetContext(ctx).
					SetHeader("Content-Type", "application/json").
					SetHeader("X-Api-Key", "downstream-secret").
					SetBody(chat("e2e-model")).Post("/v1/chat/completions")
				if err != nil {
					return err
				}
				if !res.IsSuccess() {
					return errors.Errorf("got status %d: %s", res.StatusCode(), res.Body())
				}
				if got := upstream.LastAuthorization(); got != "Bearer password" {
					return errors.Errorf("the upstream authorization is %q", got)
				}
				if got := upstream.LastHeader("X-Api-Key"); got != "" {
					return errors.Errorf("the downstream API key was forwarded as %q", got)
				}
				if got := upstream.LastHeader("X-E2E-LLM-Request"); got != "upstream" {
					return errors.Errorf("the request header is %q", got)
				}
				if got := res.Header().Get("X-E2E-LLM-Response"); got != "downstream" {
					return errors.Errorf("the response header is %q", got)
				}
				return nil
			})
	})

	t.Run("UpstreamPath", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Protocol: corev1.Service_Spec_Config_LLM_OPENAI,
			Path: &corev1.Service_Spec_Config_HTTP_Path{
				AddPrefix: "/provider",
			},
		})

		h.Eventually(t, "the LLM upstream path configuration to be applied",
			propagationBudget, func(ctx context.Context) error {
				before := upstream.ReqCountPath("/provider/v1/chat/completions")
				status, response, _, err := llmRequest(ctx, h, svc, token,
					http.MethodPost, "/v1/chat/completions", chat("e2e-model"))
				if err != nil {
					return err
				}
				if status != http.StatusOK {
					return errors.Errorf("got status %d: %s", status, response)
				}
				if upstream.ReqCountPath("/provider/v1/chat/completions") == before {
					return errors.New("the configured upstream path was not used")
				}
				return nil
			})
	})
}

func llmMatchAny() *corev1.Condition {
	return &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}
}

func llmPromptContent(value string) *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content {
	return &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content{
		Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content_Value{Value: value},
	}
}

func applyLLMInferencePlugins(t *testing.T, h *harness.H, svc *corev1.Service,
	token string, upstream *harness.LLMSrv) {
	t.Run("MutationOrder", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Protocol: corev1.Service_Spec_Config_LLM_OPENAI,
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				{
					Name: "reasoning", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Reasoning{
						Reasoning: &corev1.Service_Spec_Config_LLM_Reasoning{
							Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{
								Level: corev1.Service_Spec_Config_LLM_Reasoning_LOW,
							},
						},
					},
				},
				{
					Name: "message", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_{
						Prompt: &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
							Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_{
								Message: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message{
									Role:     corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_USER,
									Position: corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_APPEND,
									Content:  llmPromptContent("answer briefly"),
								},
							},
						},
					},
				},
				{
					Name: "tools", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Tools_{
						Tools: &corev1.Service_Spec_Config_LLM_Plugin_Tools{
							Filters: []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter{
								{
									Match: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Name{
										Name: "read_*",
									},
									Decision: corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_ALLOW,
								},
								{
									Match: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Type{
										Type: "*",
									},
									Decision: corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REMOVE,
								},
							},
							Tools: []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool{
								{
									Type: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_Value{
										Value: `{"type":"function","function":{"name":"octelium_audit"}}`,
									},
									Position: corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_PREPEND,
								},
							},
							Choice: corev1.Service_Spec_Config_LLM_Plugin_Tools_AUTO,
						},
					},
				},
				{
					Name: "pii", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_{
						Guardrail: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail{
							Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
								{
									Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Type_{
										Type: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_EMAIL,
									},
									Action: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REDACT,
								},
							},
						},
					},
				},
				{
					Name: "system", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_{
						Prompt: &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
							Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_{
								System: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System{
									Mode:    corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_PREPEND,
									Content: llmPromptContent("governed by Octelium"),
								},
							},
						},
					},
				},
				{
					Name: "model", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Model{
						Model: &corev1.Service_Spec_Config_LLM_Model{
							Type: &corev1.Service_Spec_Config_LLM_Model_Value{Value: "plugin-model"},
						},
					},
				},
			},
		})

		body := map[string]any{
			"model": "requested-model",
			"messages": []any{
				map[string]any{"role": "system", "content": "downstream system"},
				map[string]any{"role": "user", "content": "mail person@example.com"},
			},
			"tools": []any{
				map[string]any{"type": "function", "function": map[string]any{"name": "read_file"}},
				map[string]any{"type": "function", "function": map[string]any{"name": "delete_file"}},
				map[string]any{"type": "web_search_preview"},
			},
			"tool_choice": "required",
		}

		waitLLMForwarded(t, h, svc, token, http.MethodPost,
			"/v1/chat/completions", body, upstream, func(body map[string]any) error {
				if body["model"] != "plugin-model" || body["reasoning_effort"] != "low" {
					return errors.Errorf("unexpected model or reasoning: %#v", body)
				}
				if body["tool_choice"] != "auto" {
					return errors.Errorf("got tool choice %q", body["tool_choice"])
				}

				encoded, _ := json.Marshal(body["messages"])
				messages := string(encoded)
				for _, want := range []string{
					"governed by Octelium", "downstream system",
					"[REDACTED:EMAIL]", "answer briefly",
				} {
					if !strings.Contains(messages, want) {
						return errors.Errorf("the messages do not contain %q: %s", want, messages)
					}
				}
				if strings.Contains(messages, "person@example.com") {
					return errors.Errorf("the messages still contain the email: %s", messages)
				}

				tools, _ := body["tools"].([]any)
				if len(tools) != 2 {
					return errors.Errorf("got %d tools, want 2", len(tools))
				}
				encoded, _ = json.Marshal(tools)
				if !strings.Contains(string(encoded), "octelium_audit") ||
					!strings.Contains(string(encoded), "read_file") ||
					strings.Contains(string(encoded), "delete_file") ||
					strings.Contains(string(encoded), "web_search_preview") {
					return errors.Errorf("unexpected tools: %s", encoded)
				}
				return nil
			})
	})

	t.Run("PromptReject", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				{
					Name: "own-system", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_{
						Prompt: &corev1.Service_Spec_Config_LLM_Plugin_Prompt{
							Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_{
								System: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_System{
									Mode:    corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_REJECT,
									Content: llmPromptContent("service instructions"),
								},
							},
						},
					},
				},
			},
		})

		waitLLMStatus(t, h, svc, token, http.MethodPost, "/v1/chat/completions",
			map[string]any{
				"model": "e2e-model",
				"messages": []any{
					map[string]any{"role": "system", "content": "downstream"},
					map[string]any{"role": "user", "content": "hello"},
				},
			}, http.StatusForbidden, upstream)
	})

	t.Run("ResponseGuardrail", func(t *testing.T) {
		upstream.SetCompletionContent("e2e response leak")
		t.Cleanup(func() { upstream.SetCompletionContent("") })

		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				{
					Name: "response-guard", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_{
						Guardrail: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail{
							Leg: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_RESPONSE,
							Patterns: []*corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern{
								{
									Match: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Regex{
										Regex: "response leak",
									},
									Action: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_DENY,
								},
							},
							DenyMessage: "response withheld",
						},
					},
				},
			},
		})

		h.Eventually(t, "the response guardrail to withhold the upstream response",
			propagationBudget, func(ctx context.Context) error {
				before := upstream.ReqCountPath("/v1/chat/completions")
				status, body, _, err := llmRequest(ctx, h, svc, token, http.MethodPost,
					"/v1/chat/completions", map[string]any{
						"model":    "e2e-model",
						"messages": []any{map[string]any{"role": "user", "content": "hello"}},
					})
				if err != nil {
					return err
				}
				if status != http.StatusForbidden || !strings.Contains(string(body), "response withheld") {
					return errors.Errorf("got status %d and body %s", status, body)
				}
				if upstream.ReqCountPath("/v1/chat/completions") == before {
					return errors.New("the guarded response did not originate at the upstream")
				}
				return nil
			})
	})

	t.Run("TokenRateLimit", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				{
					Name: "token-quota", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_{
						TokenRateLimit: &corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit{
							Scope: corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_TOTAL,
							Key: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_PerUser{
									PerUser: true,
								},
							},
							Limit: 15,
							Window: &metav1.Duration{
								Type: &metav1.Duration_Minutes{Minutes: 1},
							},
							DenyMessage: "token quota exhausted",
							Headers: []*corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_KeyValue{
								{Key: "Retry-After", Value: "60"},
							},
						},
					},
				},
			},
		})

		waitLLMStatus(t, h, svc, token, http.MethodPost, "/v1/chat/completions",
			map[string]any{
				"model": "e2e-model", "max_tokens": 64,
				"messages": []any{map[string]any{"role": "user", "content": "probe"}},
			}, http.StatusTooManyRequests, upstream)

		body := map[string]any{
			"model":    "e2e-model",
			"messages": []any{map[string]any{"role": "user", "content": "quota"}},
		}
		waitLLMForwarded(t, h, svc, token, http.MethodPost,
			"/v1/chat/completions", body, upstream, nil)

		h.Eventually(t, "the reconciled token usage to exhaust the quota",
			propagationBudget, func(ctx context.Context) error {
				status, response, header, err := llmRequest(ctx, h, svc, token,
					http.MethodPost, "/v1/chat/completions", body)
				if err != nil {
					return err
				}
				if status != http.StatusTooManyRequests {
					return errors.Errorf("got status %d: %s", status, response)
				}
				if !strings.Contains(string(response), "token quota exhausted") ||
					header.Get("Retry-After") != "60" {
					return errors.Errorf("unexpected token quota response: %s", response)
				}
				return nil
			})

		other := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow-token-quota-e2e"),
		})
		waitLLMForwarded(t, h, svc, h.AccessToken(t, other), http.MethodPost,
			"/v1/chat/completions", body, upstream, nil)
	})
}

func llmEmbedding() *corev1.Service_Spec_Config_LLM_Embedding {
	return &corev1.Service_Spec_Config_LLM_Embedding{
		Source: &corev1.Service_Spec_Config_LLM_Embedding_Source{
			Type: &corev1.Service_Spec_Config_LLM_Embedding_Source_CurrentUpstream{
				CurrentUpstream: true,
			},
		},
		Model:      "e2e-embedding",
		Dimensions: 4,
	}
}

func applyLLMSemanticPlugins(t *testing.T, h *harness.H, svc *corev1.Service,
	token string, upstream *harness.LLMSrv) {
	t.Run("Router", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Protocol:  corev1.Service_Spec_Config_LLM_OPENAI,
			Embedding: llmEmbedding(),
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				{
					Name: "semantic-router", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter_{
						SemanticRouter: &corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter{
							Routes: []*corev1.Service_Spec_Config_LLM_Plugin_SemanticRouter_Route{
								{
									Name: "billing", Description: "billing and invoices",
									Examples: []string{"explain this invoice"}, Model: "billing-model",
								},
								{
									Name: "engineering", Description: "programming and deadlocks",
									Examples: []string{"debug this program deadlock"}, Model: "code-model",
								},
							},
							MinSimilarity: 0.8,
							FallbackModel: "fallback-model",
						},
					},
				},
			},
		})

		for _, tt := range []struct {
			prompt string
			model  string
		}{
			{"please explain this billing invoice", "billing-model"},
			{"why does this program deadlock", "code-model"},
			{"what is tomorrow's weather", "fallback-model"},
		} {
			waitLLMForwarded(t, h, svc, token, http.MethodPost,
				"/v1/chat/completions", map[string]any{
					"model":    "auto",
					"messages": []any{map[string]any{"role": "user", "content": tt.prompt}},
				}, upstream, func(body map[string]any) error {
					if body["model"] != tt.model {
						return errors.Errorf("got routed model %q, want %q", body["model"], tt.model)
					}
					return nil
				})
		}
	})

	t.Run("Cache", func(t *testing.T) {
		cachePlugin := func(name string,
			scope *corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope,
		) *corev1.Service_Spec_Config_LLM_Plugin {
			return &corev1.Service_Spec_Config_LLM_Plugin{
				Name: name, Condition: llmMatchAny(),
				Type: &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_{
					SemanticCache: &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache{
						Scope: scope, MinSimilarity: 0.95,
						Ttl:     &metav1.Duration{Type: &metav1.Duration_Minutes{Minutes: 5}},
						MaxSize: 64 * 1024, UseXCacheHeader: true,
					},
				},
			}
		}

		other := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow-semantic-cache-e2e"),
		})
		otherToken := h.AccessToken(t, other)

		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Protocol:  corev1.Service_Spec_Config_LLM_OPENAI,
			Embedding: llmEmbedding(),
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				cachePlugin("per-user-cache", nil),
			},
		})

		body := func(content string) map[string]any {
			return map[string]any{
				"model":    "cache-model",
				"messages": []any{map[string]any{"role": "user", "content": content}},
			}
		}

		miss := func(t *testing.T, accessToken, content string) {
			t.Helper()
			h.Eventually(t, "the semantic cache request to miss and reach the upstream",
				propagationBudget, func(ctx context.Context) error {
					before := upstream.ReqCountPath("/v1/chat/completions")
					status, response, header, err := llmRequest(ctx, h, svc, accessToken,
						http.MethodPost, "/v1/chat/completions", body(content))
					if err != nil {
						return err
					}
					if status != http.StatusOK || header.Get("X-Cache") != "MISS" {
						return errors.Errorf("got status %d, X-Cache %q: %s",
							status, header.Get("X-Cache"), response)
					}
					if upstream.ReqCountPath("/v1/chat/completions") == before {
						return errors.New("the cache miss did not reach the upstream")
					}
					return nil
				})
		}

		hit := func(t *testing.T, accessToken, content string) {
			t.Helper()
			h.Eventually(t, "the semantic cache request to be served without the upstream",
				propagationBudget, func(ctx context.Context) error {
					before := upstream.ReqCountPath("/v1/chat/completions")
					status, response, header, err := llmRequest(ctx, h, svc, accessToken,
						http.MethodPost, "/v1/chat/completions", body(content))
					if err != nil {
						return err
					}
					if status != http.StatusOK || header.Get("X-Cache") != "HIT" {
						return errors.Errorf("got status %d, X-Cache %q: %s",
							status, header.Get("X-Cache"), response)
					}
					if upstream.ReqCountPath("/v1/chat/completions") != before {
						return errors.New("the cache hit reached the upstream")
					}
					return nil
				})
		}

		miss(t, token, "What is Octelium zero trust cache e2e?")
		hit(t, token, "What is Octelium zero trust cache e2e?")
		hit(t, token, "Tell me about the Octelium zero trust cache e2e")
		miss(t, otherToken, "What is Octelium zero trust cache e2e?")

		shared := &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope{
			Type: &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope_Shared{
				Shared: true,
			},
		}
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Protocol:  corev1.Service_Spec_Config_LLM_OPENAI,
			Embedding: llmEmbedding(),
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				cachePlugin("shared-cache", shared),
				{
					Name: "shared-cache-model", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Model{
						Model: &corev1.Service_Spec_Config_LLM_Model{
							Type: &corev1.Service_Spec_Config_LLM_Model_Value{
								Value: "shared-cache-model",
							},
						},
					},
				},
			},
		})

		h.Eventually(t, "the shared semantic cache configuration to seed",
			propagationBudget, func(ctx context.Context) error {
				before := upstream.ReqCountPath("/v1/chat/completions")
				status, response, header, err := llmRequest(ctx, h, svc, token,
					http.MethodPost, "/v1/chat/completions",
					body("shared Octelium zero trust cache e2e"))
				if err != nil {
					return err
				}
				if status != http.StatusOK || header.Get("X-Cache") != "MISS" {
					return errors.Errorf("got status %d, X-Cache %q: %s",
						status, header.Get("X-Cache"), response)
				}
				if upstream.ReqCountPath("/v1/chat/completions") == before ||
					upstream.BodyForPath("/v1/chat/completions")["model"] != "shared-cache-model" {
					return errors.New("the shared cache configuration did not reach the upstream")
				}
				return nil
			})
		hit(t, token, "shared Octelium zero trust cache e2e")

		before := upstream.ReqCountPath("/v1/chat/completions")
		status, response, header, err := llmRequest(t.Context(), h, svc, otherToken,
			http.MethodPost, "/v1/chat/completions",
			body("shared Octelium zero trust cache e2e"))
		require.Nil(t, err)
		require.Equal(t, http.StatusOK, status, string(response))
		assert.Equal(t, "HIT", header.Get("X-Cache"))
		assert.Equal(t, before, upstream.ReqCountPath("/v1/chat/completions"))
	})
}

func applyLLMHTTPPlugins(t *testing.T, h *harness.H, svc *corev1.Service,
	token string, upstream *harness.LLMSrv) {
	chat := func(marker string) map[string]any {
		return map[string]any{
			"model": "e2e-model", "e2e_marker": marker,
			"messages": []any{map[string]any{"role": "user", "content": "hello"}},
		}
	}

	t.Run("ExtProcFailClosed", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				{
					Name: "ext-proc", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_ExtProc{
						ExtProc: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc{
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_Address{
								Address: "127.0.0.1:1",
							},
							ProcessingMode: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode{
								RequestHeaderMode: corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_SEND,
							},
							MessageTimeout: &metav1.Duration{
								Type: &metav1.Duration_Seconds{Seconds: 1},
							},
						},
					},
				},
			},
		})

		waitLLMStatus(t, h, svc, token, http.MethodPost, "/v1/chat/completions",
			chat("ext-proc"), http.StatusBadGateway, upstream)
	})

	t.Run("Direct", func(t *testing.T) {
		const direct = `{"id":"chatcmpl-direct","object":"chat.completion",` +
			`"choices":[{"index":0,"finish_reason":"stop",` +
			`"message":{"role":"assistant","content":"direct-e2e"}}]}`

		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				{
					Name: "direct", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Direct{
						Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{
							StatusCode: http.StatusOK,
							Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{
									Inline: direct,
								},
							},
						},
					},
				},
			},
		})

		h.Eventually(t, "the direct LLM response to bypass the upstream",
			propagationBudget, func(ctx context.Context) error {
				before := upstream.ReqCount()
				status, body, _, err := llmRequest(ctx, h, svc, token, http.MethodPost,
					"/v1/chat/completions", chat("direct"))
				if err != nil {
					return err
				}
				if status != http.StatusOK || !strings.Contains(string(body), "direct-e2e") {
					return errors.Errorf("got status %d and body %s", status, body)
				}
				if upstream.ReqCount() != before {
					return errors.New("the direct response reached the upstream")
				}
				return nil
			})
	})

	t.Run("JSONSchema", func(t *testing.T) {
		const schema = `{"type":"object","required":["model","messages","e2e_marker"],` +
			`"properties":{"e2e_marker":{"const":"valid"}}}`

		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				{
					Name: "schema", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_JsonSchema{
						JsonSchema: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema{
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline{
								Inline: schema,
							},
							StatusCode: http.StatusUnprocessableEntity,
						},
					},
				},
			},
		})

		waitLLMStatus(t, h, svc, token, http.MethodPost, "/v1/chat/completions",
			chat("invalid"), http.StatusUnprocessableEntity, upstream)
		waitLLMForwarded(t, h, svc, token, http.MethodPost, "/v1/chat/completions",
			chat("valid"), upstream, nil)
	})

	t.Run("LuaAndPath", func(t *testing.T) {
		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				{
					Name: "lua", Phase: corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH,
					Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Lua{
						Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
								Inline: `
function onRequest(ctx)
  local body = json.decode(octelium.req.getRequestBody())
  body["model"] = "lua-model"
  octelium.req.setRequestBody(json.encode(body))
  octelium.req.setRequestHeader("X-E2E-Lua", "yes")
end
`,
							},
						},
					},
				},
				{
					Name: "path", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_Path{
						Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{
							AddPrefix: "/e2e",
						},
					},
				},
			},
		})

		h.Eventually(t, "the Lua and path Plugins to mutate the upstream request",
			propagationBudget, func(ctx context.Context) error {
				before := upstream.ReqCount()
				status, response, _, err := llmRequest(ctx, h, svc, token,
					http.MethodPost, "/v1/chat/completions", chat("lua"))
				if err != nil {
					return err
				}
				if status != http.StatusOK {
					return errors.Errorf("got status %d: %s", status, response)
				}
				if upstream.ReqCount() == before || upstream.LastPath() != "/e2e/v1/chat/completions" {
					return errors.Errorf("got upstream path %q", upstream.LastPath())
				}
				body := upstream.LastBody()
				if body["model"] != "lua-model" || upstream.LastHeader("X-E2E-Lua") != "yes" {
					return errors.Errorf("the Lua mutation was not applied: %#v", body)
				}
				return nil
			})
	})

	t.Run("RateLimit", func(t *testing.T) {
		const limit = 2

		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{
			Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
				{
					Name: "request-rate-limit", Condition: llmMatchAny(),
					Type: &corev1.Service_Spec_Config_LLM_Plugin_RateLimit{
						RateLimit: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit{
							Limit: limit,
							Window: &metav1.Duration{
								Type: &metav1.Duration_Seconds{Seconds: 60},
							},
							Key: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_PerUser{
									PerUser: true,
								},
							},
						},
					},
				},
			},
		})

		h.Eventually(t, "the LLM request rate limit to refuse requests",
			propagationBudget, func(ctx context.Context) error {
				for range limit + 2 {
					status, _, _, err := llmRequest(ctx, h, svc, token,
						http.MethodPost, "/v1/chat/completions", chat("rate-limit"))
					if err != nil {
						return err
					}
					if status == http.StatusTooManyRequests {
						return nil
					}
				}
				return errors.New("the LLM request rate limit never refused a request")
			})
	})

	t.Run("DynamicConfig", func(t *testing.T) {
		const body = `{"id":"chatcmpl-beta","object":"chat.completion",` +
			`"choices":[{"message":{"role":"assistant","content":"beta-e2e"}}]}`

		svc = setLLMConfig(t, h, svc.Metadata.Name, &corev1.Service_Spec_Config_LLM{})
		svc = h.GetService(t, svc.Metadata.Name)
		svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
			Configs: []*corev1.Service_Spec_Config{
				{
					Name: "beta",
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: fmt.Sprintf("http://localhost:%d", upstream.Port),
						},
						User: "root",
					},
					Type: &corev1.Service_Spec_Config_Llm{
						Llm: &corev1.Service_Spec_Config_LLM{
							Plugins: []*corev1.Service_Spec_Config_LLM_Plugin{
								{
									Name: "beta", Condition: llmMatchAny(),
									Type: &corev1.Service_Spec_Config_LLM_Plugin_Direct{
										Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{
											StatusCode: http.StatusOK,
											Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
												Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{
													Inline: body,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
				{
					Condition: llmMatchAny(),
					Type:      &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "beta"},
				},
			},
		}
		svc = h.UpdateService(t, svc)

		h.Eventually(t, "the named LLM configuration to be selected",
			propagationBudget, func(ctx context.Context) error {
				before := upstream.ReqCount()
				res, err := h.ServiceClient(svc, token).R().SetContext(ctx).
					SetHeader("Content-Type", "application/json").
					SetBody(chat("dynamic")).Post("/v1/chat/completions")
				if err != nil {
					return err
				}
				if !res.IsSuccess() || !strings.Contains(string(res.Body()), "beta-e2e") {
					return errors.Errorf("got status %d and body %s", res.StatusCode(), res.Body())
				}
				if upstream.ReqCount() != before {
					return errors.New("the named direct configuration reached the upstream")
				}
				return nil
			})

		svc = h.GetService(t, svc.Metadata.Name)
		svc.Spec.DynamicConfig = nil
		h.UpdateService(t, svc)
	})
}
