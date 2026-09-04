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
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

func applyNginx(t *testing.T, a *applyCtx) {
	a.h.MustWaitServiceUpstream(t, "nginx")

	res := a.h.WaitGetStatus(t, a.h.HTTP(), a.url("nginx"), http.StatusOK)

	_, err := html.Parse(strings.NewReader(string(res.Body())))
	assert.Nil(t, err)
}

func applyGoogle(t *testing.T, a *applyCtx) {
	a.h.MustWaitService(t, "google")

	res := a.h.WaitGetStatus(t, a.h.HTTP(), a.url("google"), http.StatusOK)

	_, err := html.Parse(strings.NewReader(string(res.Body())))
	assert.Nil(t, err)
}

func applyWebSocket(t *testing.T, a *applyCtx) {
	a.h.MustWaitService(t, "ws-echo")

	dialer := websocket.Dialer{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	wsC, _, err := dialer.DialContext(t.Context(),
		fmt.Sprintf("ws://%s/", a.addr("ws-echo")), http.Header{})
	require.Nil(t, err)
	defer wsC.Close()

	for range 5 {
		msg := utilrand.GetRandomBytesMust(32)

		err = wsC.WriteMessage(websocket.BinaryMessage, msg)
		assert.Nil(t, err)

		_, read, err := wsC.ReadMessage()
		assert.Nil(t, err)
		assert.True(t, utils.SecureBytesEqual(msg, read))

		time.Sleep(1 * time.Second)
	}
}

func applyMCP(t *testing.T, a *applyCtx) {
	a.h.MustWaitService(t, "mcp-echo")

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "echo-client",
		Version: "1.0.0",
	}, nil)

	session, err := client.Connect(t.Context(),
		&mcp.StreamableClientTransport{Endpoint: a.url("mcp-echo")}, nil)
	require.Nil(t, err)
	defer session.Close()

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
}

func applyLLM(t *testing.T, a *applyCtx) {
	h := a.h
	h.Require(t, capHostPortIngress)

	h.StartLogStream(t.Context(),
		"-l octelium.com/svc=llm-aimock.default,octelium.com/component=svc-k8s-upstream")

	h.MustWaitServiceUpstream(t, "llm-aimock")
	h.MustWaitService(t, "llm-aimock")

	svc := h.GetService(t, "llm-aimock")
	usr := h.CreateWorkloadUser(t, &corev1.User_Spec_Authorization{
		InlinePolicies: harness.InlineAllowAny("allow-aimock-e2e"),
	})
	token := h.AccessToken(t, usr)

	setProtocol := func(t *testing.T, protocol corev1.Service_Spec_Config_LLM_Protocol) {
		t.Helper()
		svc = h.GetService(t, "llm-aimock")
		svc.Spec.Config.GetLlm().Protocol = protocol
		svc = h.UpdateService(t, svc)
	}

	waitPost := func(t *testing.T, path string, body any) ([]byte, http.Header) {
		t.Helper()

		var ret []byte
		var header http.Header
		h.Eventually(t, fmt.Sprintf("the AI mock to serve POST %s", path),
			harness.DecisionBudget, func(ctx context.Context) error {
				res, err := h.ServiceClient(svc, token).R().SetContext(ctx).
					SetHeader("Content-Type", "application/json").
					SetBody(body).Post(path)
				if err != nil {
					return err
				}
				if !res.IsSuccess() {
					return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
				}
				ret = append(ret[:0], res.Body()...)
				header = res.Header().Clone()
				return nil
			})
		return ret, header
	}

	c := openai.NewClient(
		option.WithBaseURL(h.ServiceURL(svc)+"/v1"),
		option.WithAPIKey(token),
		option.WithMaxRetries(10),
	)

	t.Run("OpenAI", func(t *testing.T) {
		setProtocol(t, corev1.Service_Spec_Config_LLM_OPENAI)
		started := time.Now()

		res, err := c.Chat.Completions.New(t.Context(), openai.ChatCompletionNewParams{
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.UserMessage("hello"),
			},
			Model: "e2e-model",
		})
		require.Nil(t, err)
		assert.Contains(t, res.Choices[0].Message.Content, "Hello")

		zap.L().Debug("Chat completion output",
			zap.Duration("duration", time.Since(started)))

		stream := c.Chat.Completions.NewStreaming(t.Context(), openai.ChatCompletionNewParams{
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.UserMessage("hello"),
			},
			Model: "e2e-model",
		})

		acc := openai.ChatCompletionAccumulator{}
		for stream.Next() {
			acc.AddChunk(stream.Current())
		}

		require.Nil(t, stream.Err())
		require.NotEmpty(t, acc.Choices)
		assert.Contains(t, acc.Choices[0].Message.Content, "Hello")
	})

	t.Run("Anthropic", func(t *testing.T) {
		setProtocol(t, corev1.Service_Spec_Config_LLM_ANTHROPIC)

		body := map[string]any{
			"model": "e2e-model", "max_tokens": 64,
			"messages": []any{map[string]any{"role": "user", "content": "hello"}},
		}
		res, _ := waitPost(t, "/v1/messages", body)
		assert.Contains(t, string(res), "Hello")

		body["stream"] = true
		res, header := waitPost(t, "/v1/messages", body)
		assert.Contains(t, header.Get("Content-Type"), "text/event-stream")
		assert.Contains(t, string(res), "message_stop")
	})

	t.Run("Gemini", func(t *testing.T) {
		setProtocol(t, corev1.Service_Spec_Config_LLM_GEMINI)

		body := map[string]any{
			"contents": []any{map[string]any{
				"role": "user", "parts": []any{map[string]any{"text": "hello"}},
			}},
		}
		res, _ := waitPost(t, "/v1beta/models/e2e-model:generateContent", body)
		assert.Contains(t, string(res), "Hello")

		res, header := waitPost(t,
			"/v1beta/models/e2e-model:streamGenerateContent?alt=sse", body)
		assert.Contains(t, header.Get("Content-Type"), "text/event-stream")
		assert.Contains(t, string(res), "candidates")
	})

	t.Run("Bedrock", func(t *testing.T) {
		setProtocol(t, corev1.Service_Spec_Config_LLM_BEDROCK)

		body := map[string]any{
			"messages": []any{map[string]any{
				"role": "user", "content": []any{map[string]any{"text": "hello"}},
			}},
			"inferenceConfig": map[string]any{"maxTokens": 64},
		}
		res, _ := waitPost(t, "/model/e2e-model/converse", body)
		assert.Contains(t, string(res), "Hello")

		res, header := waitPost(t, "/model/e2e-model/converse-stream", body)
		assert.Contains(t, header.Get("Content-Type"), "application/vnd.amazon.eventstream")
		assert.NotEmpty(t, res)
	})

	h.MustRun(t, "octeliumctl del svc llm-aimock")
}

func drainBody(t *testing.T, r io.Reader) string {
	t.Helper()

	b, err := io.ReadAll(r)
	require.Nil(t, err)
	return string(b)
}
