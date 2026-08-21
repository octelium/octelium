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

package httputils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
)

func parseLLM(t *testing.T, protocol corev1.Service_Spec_Config_LLM_Protocol,
	method, path, body string) *LLMRequest {

	req := httptest.NewRequest(method, "http://my-llm.example.com"+path,
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	return ParseLLMRequest(req, protocol, []byte(body))
}

func TestMatchLLMRoute(t *testing.T) {

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodGet, "/v1/models")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_LIST, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodGet, "/v1/models/gpt-4o")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_GET, operation)
	}

	{
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodGet, "/v1/chat/completions")
		assert.False(t, ok)
	}

	{
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/models/gpt-4o")
		assert.False(t, ok)
	}

	{
		for _, path := range []string{
			"/v1", "/v1/", "/v1/files", "/v1/chat", "/v1/chat/completions/x",
			"/v1/models/", "/v1/models/a/b", "/",
		} {
			_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
				http.MethodPost, path)
			assert.False(t, ok, path)
		}
	}

	{
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/messages")
		assert.False(t, ok)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_ANTHROPIC,
			http.MethodPost, "/v1/messages")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MESSAGES, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_ANTHROPIC,
			http.MethodPost, "/v1/messages/count_tokens")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_COUNT_TOKENS, operation)
	}

	{
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_ANTHROPIC,
			http.MethodPost, "/v1/chat/completions")
		assert.False(t, ok)
	}
}

func TestParseLLMRequestOpenAI(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello there"}]}`)

		assert.True(t, llmReq.IsKnownRoute)
		assert.True(t, llmReq.IsBodyValid)
		assert.Equal(t, corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS, llmReq.Operation)
		assert.Equal(t, "gpt-4o", llmReq.Model)
		assert.False(t, llmReq.Stream)
		assert.Equal(t, uint32(1), llmReq.InputItemCount)
		assert.False(t, llmReq.HasTools)
		assert.Equal(t, corev1.RequestContext_Request_LLM_COMPLETE, llmReq.EstimateQuality)
		assert.True(t, llmReq.EstimatedInputTokens > 0)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","stream":true,"max_completion_tokens":512,
			"messages":[{"role":"system","content":"a"},{"role":"user","content":"b"}]}`)

		assert.True(t, llmReq.Stream)
		assert.Equal(t, uint64(512), llmReq.MaxOutputTokens)
		assert.Equal(t, uint32(2), llmReq.InputItemCount)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/responses",
			`{"model":"gpt-5","max_output_tokens":1024,"input":"Hello"}`)

		assert.Equal(t, corev1.RequestContext_Request_LLM_RESPONSES, llmReq.Operation)
		assert.Equal(t, uint64(1024), llmReq.MaxOutputTokens)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],
			"tools":[
				{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}},
				{"type":"function","function":{"name":"add","parameters":{"type":"object"}}}]}`)

		assert.True(t, llmReq.HasTools)
		assert.Equal(t, uint32(2), llmReq.ToolCount)
		assert.Equal(t, []string{"add", "get_weather"}, llmReq.ToolNames)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],
			"some_brand_new_provider_option":{"a":1}}`)

		assert.True(t, llmReq.IsBodyValid)
		assert.Equal(t, "gpt-4o", llmReq.Model)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions", `[]`)
		assert.True(t, llmReq.IsKnownRoute)
		assert.True(t, llmReq.HasBody)
		assert.False(t, llmReq.IsBodyValid)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions", `not json`)
		assert.False(t, llmReq.IsBodyValid)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodGet, "/v1/models", "")
		assert.True(t, llmReq.IsKnownRoute)
		assert.False(t, llmReq.HasBody)
		assert.Equal(t, corev1.RequestContext_Request_LLM_UNAVAILABLE, llmReq.EstimateQuality)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/files", `{"model":"gpt-4o"}`)
		assert.False(t, llmReq.IsKnownRoute)
		assert.Empty(t, llmReq.Model)
	}
}

func TestParseLLMRequestAnthropic(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_ANTHROPIC,
			http.MethodPost, "/v1/messages",
			`{"model":"claude-sonnet-4","max_tokens":2048,"system":"Be brief",
			"messages":[{"role":"user","content":"Hello"}],
			"tools":[{"name":"bash","input_schema":{"type":"object"}}]}`)

		assert.True(t, llmReq.IsKnownRoute)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MESSAGES, llmReq.Operation)
		assert.Equal(t, corev1.Service_Spec_Config_LLM_ANTHROPIC, llmReq.Protocol)
		assert.Equal(t, "claude-sonnet-4", llmReq.Model)
		assert.Equal(t, uint64(2048), llmReq.MaxOutputTokens)
		assert.Equal(t, uint32(1), llmReq.ToolCount)
		assert.Equal(t, []string{"bash"}, llmReq.ToolNames)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_ANTHROPIC,
			http.MethodPost, "/v1/messages",
			`{"model":"claude-sonnet-4","max_tokens":16,"messages":[{"role":"user",
			"content":[{"type":"image","source":{"type":"base64","media_type":"image/png",
			"data":"`+strings.Repeat("A", 64000)+`"}}]}]}`)

		assert.True(t, llmReq.HasImageInput)
		assert.Equal(t, corev1.RequestContext_Request_LLM_PARTIAL, llmReq.EstimateQuality)

		assert.True(t, llmReq.EstimatedInputTokens < llmTokensPerImage+64)
		assert.True(t, llmReq.EstimatedInputTokens >= llmTokensPerImage)
	}
}

func TestLLMEstimate(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[{"role":"user","content":"`+
				strings.Repeat("a", 400)+`"}]}`)

		assert.True(t, llmReq.EstimatedInputTokens >= 100)
		assert.True(t, llmReq.EstimatedInputTokens < 130)
	}

	{
		ascii := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"m","messages":[{"role":"user","content":"`+
				strings.Repeat("a", 300)+`"}]}`)

		nonASCII := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"m","messages":[{"role":"user","content":"`+
				strings.Repeat("あ", 100)+`"}]}`)

		assert.True(t, nonASCII.EstimatedInputTokens > ascii.EstimatedInputTokens)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/embeddings",
			`{"model":"text-embedding-3-small","input":["a","b","c"]}`)

		assert.Equal(t, corev1.RequestContext_Request_LLM_EMBEDDINGS, llmReq.Operation)
		assert.Equal(t, uint32(3), llmReq.InputItemCount)
	}
}

func TestParseLLMResponse(t *testing.T) {

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-123","model":"gpt-4o-2024-11-20","object":"chat.completion",
			"choices":[{"finish_reason":"stop","message":{"content":"hi"}}],
			"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20,
			"prompt_tokens_details":{"cached_tokens":4}}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, "chatcmpl-123", msg.ResponseID)
		assert.Equal(t, "gpt-4o-2024-11-20", msg.Model)
		assert.Equal(t, "stop", msg.FinishReason)
		assert.True(t, msg.Usage.IsSet)
		assert.Equal(t, uint64(12), msg.Usage.InputTokens)
		assert.Equal(t, uint64(8), msg.Usage.OutputTokens)
		assert.Equal(t, uint64(20), msg.Usage.TotalTokens)
		assert.Equal(t, uint64(4), msg.Usage.CacheReadInputTokens)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-123","model":"gpt-4o","object":"chat.completion.chunk",
			"choices":[{"delta":{"content":"Hel"},"finish_reason":null}]}`))

		assert.NotNil(t, msg)
		assert.True(t, msg.HasContentDelta)
		assert.False(t, msg.Usage.IsSet)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"type":"response.completed","response":{"id":"resp_1","model":"gpt-5",
			"status":"completed","usage":{"input_tokens":30,"output_tokens":100,
			"total_tokens":130,"output_tokens_details":{"reasoning_tokens":64}}}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, "resp_1", msg.ResponseID)
		assert.Equal(t, "gpt-5", msg.Model)
		assert.Equal(t, "completed", msg.FinishReason)
		assert.Equal(t, uint64(30), msg.Usage.InputTokens)
		assert.Equal(t, uint64(100), msg.Usage.OutputTokens)
		assert.Equal(t, uint64(64), msg.Usage.ReasoningTokens)
	}

	{
		msg := ParseLLMResponse([]byte(`{"type":"response.output_text.delta","delta":"x"}`))
		assert.NotNil(t, msg)
		assert.True(t, msg.HasContentDelta)
	}

	{
		start := ParseLLMResponse([]byte(
			`{"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4",
			"usage":{"input_tokens":25,"cache_read_input_tokens":10}}}`))

		assert.NotNil(t, start)
		assert.Equal(t, "msg_1", start.ResponseID)
		assert.Equal(t, "claude-sonnet-4", start.Model)
		assert.Equal(t, uint64(25), start.Usage.InputTokens)
		assert.Equal(t, uint64(10), start.Usage.CacheReadInputTokens)

		delta := ParseLLMResponse([]byte(
			`{"type":"message_delta","delta":{"stop_reason":"end_turn"},
			"usage":{"output_tokens":42}}`))

		assert.NotNil(t, delta)
		assert.Equal(t, "end_turn", delta.FinishReason)
		assert.Equal(t, uint64(42), delta.Usage.OutputTokens)
	}

	{
		msg := ParseLLMResponse([]byte(`{"type":"content_block_delta","index":0,
		"delta":{"type":"text_delta","text":"Hello"}}`))
		assert.NotNil(t, msg)
		assert.True(t, msg.HasContentDelta)
	}

	{
		assert.Nil(t, ParseLLMResponse([]byte("[DONE]")))
		assert.Nil(t, ParseLLMResponse([]byte("")))
		assert.Nil(t, ParseLLMResponse([]byte("not json")))
	}

	{
		assert.True(t, IsLLMStreamDone([]byte("[DONE]")))
		assert.True(t, IsLLMStreamDone([]byte(" [DONE] ")))
		assert.False(t, IsLLMStreamDone([]byte(`{"a":1}`)))
	}
}

func TestLLMUsageMerge(t *testing.T) {

	{
		usage := LLMUsage{}

		usage.Merge(ParseLLMResponse([]byte(
			`{"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4",
			"usage":{"input_tokens":100,"cache_read_input_tokens":40,
			"cache_creation_input_tokens":25,"output_tokens":1}}}`)).Usage)

		usage.Merge(ParseLLMResponse([]byte(
			`{"type":"content_block_delta","index":0,
			"delta":{"type":"text_delta","text":"Hi"}}`)).Usage)

		usage.Merge(ParseLLMResponse([]byte(
			`{"type":"message_delta","delta":{"stop_reason":"end_turn"},
			"usage":{"output_tokens":50}}`)).Usage)

		assert.True(t, usage.IsSet)
		assert.Equal(t, uint64(100), usage.InputTokens)
		assert.Equal(t, uint64(50), usage.OutputTokens)
		assert.Equal(t, uint64(215), usage.TotalTokens)
		assert.Equal(t, uint64(40), usage.CacheReadInputTokens)
		assert.Equal(t, uint64(25), usage.CacheCreationInputTokens)
	}

	{
		usage := LLMUsage{}

		usage.Merge(ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"delta":{"content":"a"}}]}`)).Usage)

		assert.False(t, usage.IsSet)

		usage.Merge(ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"finish_reason":"stop"}],
			"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}`)).Usage)

		assert.True(t, usage.IsSet)
		assert.Equal(t, uint64(12), usage.InputTokens)
		assert.Equal(t, uint64(8), usage.OutputTokens)
		assert.Equal(t, uint64(20), usage.TotalTokens)
	}
}

func TestParseLLMRequestModelsGet(t *testing.T) {

	{
		req := httptest.NewRequest(http.MethodGet,
			"http://my-llm.example.com/v1/models/gpt-4o", nil)

		llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_OPENAI, nil)

		assert.True(t, llmReq.IsKnownRoute)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_GET, llmReq.Operation)
		assert.Equal(t, "gpt-4o", llmReq.Model)
	}

	{
		req := httptest.NewRequest(http.MethodGet,
			"http://my-llm.example.com/v1/models/claude-sonnet-4-20250514", nil)

		llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_ANTHROPIC, nil)

		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_GET, llmReq.Operation)
		assert.Equal(t, "claude-sonnet-4-20250514", llmReq.Model)
	}

	{
		req := httptest.NewRequest(http.MethodGet,
			"http://my-llm.example.com/v1/models", nil)

		llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_OPENAI, nil)

		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_LIST, llmReq.Operation)
		assert.Empty(t, llmReq.Model)
	}
}

func TestParseLLMRequestBounds(t *testing.T) {

	{
		model := strings.Repeat("a", maxLLMStringLen+1)
		body := fmt.Sprintf(`{"model":%q,"messages":[]}`, model)

		req := httptest.NewRequest(http.MethodPost,
			"http://my-llm.example.com/v1/chat/completions", strings.NewReader(body))

		llmReq := ParseLLMRequest(req,
			corev1.Service_Spec_Config_LLM_OPENAI, []byte(body))

		assert.True(t, llmReq.IsBodyValid)
		assert.Empty(t, llmReq.Model)
	}

	{
		name := strings.Repeat("b", maxLLMStringLen+1)
		body := fmt.Sprintf(
			`{"model":"gpt-4o","messages":[],"tools":[{"name":%q},{"name":"ok"}]}`, name)

		req := httptest.NewRequest(http.MethodPost,
			"http://my-llm.example.com/v1/chat/completions", strings.NewReader(body))

		llmReq := ParseLLMRequest(req,
			corev1.Service_Spec_Config_LLM_OPENAI, []byte(body))

		assert.Equal(t, uint32(2), llmReq.ToolCount)
		assert.Equal(t, []string{"ok"}, llmReq.ToolNames)
	}

	{
		req := httptest.NewRequest(http.MethodGet,
			"http://my-llm.example.com"+llmModelsPrefix+strings.Repeat("c", maxLLMStringLen+1),
			nil)

		llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_OPENAI, nil)

		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_GET, llmReq.Operation)
		assert.Empty(t, llmReq.Model)
	}
}

func TestParseLLMResponseTerminalStatus(t *testing.T) {

	{
		msg := ParseLLMResponse([]byte(
			`{"type":"response.in_progress","response":{"id":"resp_1","status":"in_progress"}}`))

		assert.NotNil(t, msg)
		assert.Empty(t, msg.FinishReason)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"type":"response.created","response":{"id":"resp_1","status":"queued"}}`))

		assert.NotNil(t, msg)
		assert.Empty(t, msg.FinishReason)
	}

	for _, status := range []string{"completed", "failed", "cancelled", "incomplete"} {
		msg := ParseLLMResponse([]byte(
			`{"type":"response.done","response":{"id":"resp_1","status":"` + status + `"}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, status, msg.FinishReason)
	}
}

func TestParseLLMRequestMaxOutputTokens(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[],"max_output_tokens":10,"max_tokens":100000}`)

		assert.Equal(t, uint64(100000), llmReq.MaxOutputTokens)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_OPENAI,
			http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[],"max_completion_tokens":256}`)

		assert.Equal(t, uint64(256), llmReq.MaxOutputTokens)
	}
}

func TestLLMUsagePresence(t *testing.T) {

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"finish_reason":"stop"}],` +
				`"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}`))

		assert.NotNil(t, msg)
		assert.True(t, msg.Usage.IsSet)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","choices":[{"finish_reason":"stop"}]}`))

		assert.NotNil(t, msg)
		assert.False(t, msg.Usage.IsSet)
	}
}

func TestParseLLMResponseUsageNoProviderTotal(t *testing.T) {

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-1","model":"llama-3","object":"chat.completion",
			"choices":[{"finish_reason":"stop","message":{"content":"hi"}}],
			"usage":{"prompt_tokens":100,"completion_tokens":50,
			"prompt_tokens_details":{"cached_tokens":40}}}`))

		assert.NotNil(t, msg)
		assert.True(t, msg.Usage.IsSet)
		assert.Equal(t, uint64(100), msg.Usage.InputTokens)
		assert.Equal(t, uint64(50), msg.Usage.OutputTokens)
		assert.Equal(t, uint64(40), msg.Usage.CacheReadInputTokens)
		assert.Equal(t, uint64(150), msg.Usage.TotalTokens)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"msg_1","model":"claude-sonnet-4","type":"message",
			"usage":{"input_tokens":100,"output_tokens":50,
			"cache_read_input_tokens":40,"cache_creation_input_tokens":25}}`))

		assert.NotNil(t, msg)
		assert.True(t, msg.Usage.IsSet)
		assert.Equal(t, uint64(215), msg.Usage.TotalTokens)
	}

	{
		msg := ParseLLMResponse([]byte(
			`{"id":"chatcmpl-2","model":"llama-3","object":"chat.completion",
			"choices":[{"finish_reason":"stop","message":{"content":"hi"}}],
			"usage":{"prompt_tokens":100,"completion_tokens":50,
			"completion_tokens_details":{"reasoning_tokens":30}}}`))

		assert.NotNil(t, msg)
		assert.Equal(t, uint64(150), msg.Usage.TotalTokens)
	}
}
