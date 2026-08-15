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
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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
	requireAMD64(t, "the llama.cpp Service")

	h := a.h

	h.StartLogStream(t.Context(),
		"-l octelium.com/svc=llama.default,octelium.com/component=svc-k8s-upstream")

	h.MustWaitServiceUpstream(t, "llama")
	h.MustWaitService(t, "llama")

	time.Sleep(5 * time.Second)

	c := openai.NewClient(
		option.WithBaseURL(a.url("llama")+"/v1"),
		option.WithMaxRetries(20),
	)

	t.Run("Completion", func(t *testing.T) {
		started := time.Now()

		_, err := c.Chat.Completions.New(t.Context(), openai.ChatCompletionNewParams{
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.UserMessage("What is zero trust?"),
			},
			Model: "e2e",
		})
		assert.Nil(t, err)

		zap.L().Debug("Chat completion output",
			zap.Duration("duration", time.Since(started)))
	})

	t.Run("Streaming", func(t *testing.T) {
		started := time.Now()

		stream := c.Chat.Completions.NewStreaming(t.Context(), openai.ChatCompletionNewParams{
			Messages: []openai.ChatCompletionMessageParamUnion{
				openai.UserMessage("What are the largest cities in the world?"),
			},
			Model: "e2e",
		})

		acc := openai.ChatCompletionAccumulator{}

		count := 0
		totalLen := 0
		for stream.Next() {
			chunk := stream.Current()
			acc.AddChunk(chunk)

			if len(chunk.Choices) > 0 {
				count++
				totalLen += len(chunk.Choices[0].Delta.Content)
			}
		}

		zap.L().Debug("Total openAI chat completion streaming chunks",
			zap.Int("count", count), zap.Int("totalLen", totalLen),
			zap.Duration("duration", time.Since(started)))

		assert.Nil(t, stream.Err())
		assert.True(t, count > 10)

		if len(acc.Choices) > 0 {
			zap.L().Debug("Complete answer", zap.String("val", acc.Choices[0].Message.Content))
		}
	})

	h.MustRun(t, "octeliumctl del svc llama")
}

func drainBody(t *testing.T, r io.Reader) string {
	t.Helper()

	b, err := io.ReadAll(r)
	require.Nil(t, err)
	return string(b)
}
