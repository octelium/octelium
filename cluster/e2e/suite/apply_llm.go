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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
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
}
