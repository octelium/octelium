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
	"encoding/binary"
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

func TestMatchLLMRouteGemini(t *testing.T) {
	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:generateContent")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_GENERATE_CONTENT, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:streamGenerateContent")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_GENERATE_CONTENT, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:countTokens")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_COUNT_TOKENS, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/text-embedding-004:embedContent")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_EMBED_CONTENT, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodGet, "/v1beta/models")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_LIST, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodGet, "/v1beta/models/gemini-2.5-pro")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MODELS_GET, operation)
	}

	for _, path := range []string{
		"/v1/chat/completions",
		"/v1beta/models/gemini-2.5-pro:unknownVerb",
		"/v1beta/models/:generateContent",
		"/v1beta/models/nested/model:generateContent",
	} {
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, path)
		assert.False(t, ok, path)
	}

	{
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodGet, "/v1beta/models/gemini-2.5-pro:generateContent")
		assert.False(t, ok)
	}
}

func TestMatchLLMRouteBedrock(t *testing.T) {
	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_BEDROCK,
			http.MethodPost, "/model/anthropic.claude-sonnet-4-5-v1:0/converse")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_CONVERSE, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_BEDROCK,
			http.MethodPost, "/model/anthropic.claude-sonnet-4-5-v1:0/converse-stream")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_CONVERSE, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_BEDROCK,
			http.MethodPost, "/model/anthropic.claude-sonnet-4-5-v1:0/invoke")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_INVOKE_MODEL, operation)
	}

	{
		operation, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_BEDROCK,
			http.MethodPost,
			"/model/arn:aws:bedrock:us-east-1:1/inference-profile/us.anthropic.x/converse")
		assert.True(t, ok)
		assert.Equal(t, corev1.RequestContext_Request_LLM_CONVERSE, operation)
	}

	for _, path := range []string{
		"/v1/chat/completions",
		"/model/anthropic.claude/unknown",
		"/model/converse",
	} {
		_, ok := MatchLLMRoute(corev1.Service_Spec_Config_LLM_BEDROCK,
			http.MethodPost, path)
		assert.False(t, ok, path)
	}
}

func TestParseLLMRequestGemini(t *testing.T) {
	body := `{"contents":[{"role":"user","parts":[{"text":"Hello there"}]}],` +
		`"systemInstruction":{"parts":[{"text":"You are helpful"}]},` +
		`"generationConfig":{"maxOutputTokens":512},` +
		`"tools":[{"functionDeclarations":[` +
		`{"name":"get_weather","parameters":{"type":"object"}},` +
		`{"name":"send_email","parameters":{"type":"object"}}]}]}`

	req := httptest.NewRequest(http.MethodPost,
		"http://localhost/v1beta/models/gemini-2.5-pro:streamGenerateContent",
		strings.NewReader(body))

	llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_GEMINI, []byte(body))

	assert.True(t, llmReq.IsKnownRoute)
	assert.True(t, llmReq.IsBodyValid)
	assert.True(t, llmReq.Stream)
	assert.Equal(t, corev1.RequestContext_Request_LLM_GENERATE_CONTENT, llmReq.Operation)
	assert.Equal(t, "gemini-2.5-pro", llmReq.Model)
	assert.Equal(t, uint64(512), llmReq.MaxOutputTokens)
	assert.True(t, llmReq.HasTools)
	assert.Equal(t, uint32(2), llmReq.ToolCount)
	assert.Equal(t, []string{"get_weather", "send_email"}, llmReq.ToolNames)
	assert.True(t, llmReq.EstimatedInputTokens > 0)
	assert.Equal(t, corev1.RequestContext_Request_LLM_COMPLETE, llmReq.EstimateQuality)
}

func TestParseLLMRequestBedrock(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"text":"Hello there"}]}],` +
		`"system":[{"text":"You are helpful"}],` +
		`"inferenceConfig":{"maxTokens":900},` +
		`"toolConfig":{"tools":[{"toolSpec":{"name":"get_weather",` +
		`"inputSchema":{"json":{"type":"object"}}}}]}}`

	req := httptest.NewRequest(http.MethodPost,
		"http://localhost/model/anthropic.claude-sonnet-4-5-v1:0/converse-stream",
		strings.NewReader(body))

	llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_BEDROCK, []byte(body))

	assert.True(t, llmReq.IsKnownRoute)
	assert.True(t, llmReq.IsBodyValid)
	assert.True(t, llmReq.Stream)
	assert.Equal(t, corev1.RequestContext_Request_LLM_CONVERSE, llmReq.Operation)
	assert.Equal(t, "anthropic.claude-sonnet-4-5-v1:0", llmReq.Model)
	assert.Equal(t, uint64(900), llmReq.MaxOutputTokens)
	assert.True(t, llmReq.HasTools)
	assert.Equal(t, uint32(1), llmReq.ToolCount)
	assert.Equal(t, []string{"get_weather"}, llmReq.ToolNames)
	assert.True(t, llmReq.EstimatedInputTokens > 0)
}

func TestParseLLMRequestInvokeModel(t *testing.T) {
	body := `{"anthropic_version":"bedrock-2023-05-31","messages":[]}`

	req := httptest.NewRequest(http.MethodPost,
		"http://localhost/model/anthropic.claude-sonnet-4-5-v1:0/invoke",
		strings.NewReader(body))

	llmReq := ParseLLMRequest(req, corev1.Service_Spec_Config_LLM_BEDROCK, []byte(body))

	assert.True(t, llmReq.IsKnownRoute)
	assert.False(t, llmReq.IsBodyValid)
	assert.Equal(t, corev1.RequestContext_Request_LLM_INVOKE_MODEL, llmReq.Operation)
	assert.Equal(t, "anthropic.claude-sonnet-4-5-v1:0", llmReq.Model)
}

func TestParseLLMResponseGemini(t *testing.T) {
	body := `{"candidates":[{"content":{"role":"model","parts":[{"text":"Hi"}]},` +
		`"finishReason":"STOP"}],"modelVersion":"gemini-2.5-pro","responseId":"abc",` +
		`"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":22,` +
		`"thoughtsTokenCount":7,"totalTokenCount":40}}`

	res := ParseLLMResponse([]byte(body))
	assert.NotNil(t, res)
	assert.Equal(t, "gemini-2.5-pro", res.Model)
	assert.Equal(t, "abc", res.ResponseID)
	assert.Equal(t, "STOP", res.FinishReason)
	assert.True(t, res.HasContentDelta)
	assert.True(t, res.Usage.IsSet)
	assert.Equal(t, uint64(11), res.Usage.InputTokens)
	assert.Equal(t, uint64(29), res.Usage.OutputTokens)
	assert.Equal(t, uint64(7), res.Usage.ReasoningTokens)
	assert.Equal(t, uint64(40), res.Usage.TotalTokens)
}

func TestParseLLMResponseBedrock(t *testing.T) {
	{
		body := `{"output":{"message":{"role":"assistant","content":[{"text":"Hi"}]}},` +
			`"stopReason":"end_turn",` +
			`"usage":{"inputTokens":11,"outputTokens":22,"totalTokens":33}}`

		res := ParseLLMResponse([]byte(body))
		assert.NotNil(t, res)
		assert.Equal(t, "end_turn", res.FinishReason)
		assert.True(t, res.Usage.IsSet)
		assert.Equal(t, uint64(11), res.Usage.InputTokens)
		assert.Equal(t, uint64(22), res.Usage.OutputTokens)
		assert.Equal(t, uint64(33), res.Usage.TotalTokens)
	}

	{
		res := ParseLLMResponse([]byte(`{"delta":{"text":"Hello"}}`))
		assert.NotNil(t, res)
		assert.True(t, res.HasContentDelta)
	}

	{
		res := ParseLLMResponse([]byte(
			`{"usage":{"inputTokens":5,"outputTokens":6,"totalTokens":11}}`))
		assert.NotNil(t, res)
		assert.Equal(t, uint64(11), res.Usage.TotalTokens)
	}
}

func newLLMEventStreamMessage(t *testing.T, headers, payload []byte) []byte {
	total := 12 + len(headers) + len(payload) + 4
	ret := make([]byte, 0, total)

	ret = binary.BigEndian.AppendUint32(ret, uint32(total))
	ret = binary.BigEndian.AppendUint32(ret, uint32(len(headers)))
	ret = binary.BigEndian.AppendUint32(ret, 0)
	ret = append(ret, headers...)
	ret = append(ret, payload...)
	ret = binary.BigEndian.AppendUint32(ret, 0)

	assert.Equal(t, total, len(ret))

	return ret
}

func TestNextLLMEventStreamMessage(t *testing.T) {
	payload := []byte(`{"usage":{"inputTokens":5,"outputTokens":6,"totalTokens":11}}`)
	headers := []byte("\x0b:event-type")

	msg := newLLMEventStreamMessage(t, headers, payload)

	{
		out, n := NextLLMEventStreamMessage(msg)
		assert.Equal(t, len(msg), n)
		assert.Equal(t, string(payload), string(out))
	}

	{
		_, n := NextLLMEventStreamMessage(msg[:len(msg)-1])
		assert.Equal(t, 0, n)
	}

	{
		_, n := NextLLMEventStreamMessage(msg[:4])
		assert.Equal(t, 0, n)
	}

	{
		invalid := make([]byte, len(msg))
		copy(invalid, msg)
		binary.BigEndian.PutUint32(invalid[0:4], 3)
		_, n := NextLLMEventStreamMessage(invalid)
		assert.Equal(t, -1, n)
	}

	{
		invalid := make([]byte, len(msg))
		copy(invalid, msg)
		binary.BigEndian.PutUint32(invalid[4:8], uint32(len(msg)))
		_, n := NextLLMEventStreamMessage(invalid)
		assert.Equal(t, -1, n)
	}

	{
		two := append(append([]byte{}, msg...), msg...)
		out, n := NextLLMEventStreamMessage(two)
		assert.Equal(t, len(msg), n)
		assert.Equal(t, string(payload), string(out))

		out, n = NextLLMEventStreamMessage(two[n:])
		assert.Equal(t, len(msg), n)
		assert.Equal(t, string(payload), string(out))
	}
}

func TestSetLLMModelPath(t *testing.T) {

	{
		path, rawPath := SetLLMModelPath(corev1.Service_Spec_Config_LLM_GEMINI,
			"/v1beta/models/gemini-2.5-pro:generateContent", "gemini-2.5-flash")
		assert.Equal(t, "/v1beta/models/gemini-2.5-flash:generateContent", path)
		assert.Equal(t, path, rawPath)
	}

	{
		path, _ := SetLLMModelPath(corev1.Service_Spec_Config_LLM_GEMINI,
			"/v1beta/models/gemini-2.5-pro", "gemini-2.5-flash")
		assert.Equal(t, "", path)
	}

	{
		path, rawPath := SetLLMModelPath(corev1.Service_Spec_Config_LLM_BEDROCK,
			"/model/anthropic.claude-v1:0/converse-stream",
			"arn:aws:bedrock:us-east-1:1234:inference-profile/us.anthropic.claude")
		assert.Equal(t,
			"/model/arn:aws:bedrock:us-east-1:1234:inference-profile/"+
				"us.anthropic.claude/converse-stream", path)
		assert.Equal(t,
			"/model/arn:aws:bedrock:us-east-1:1234:inference-profile%2F"+
				"us.anthropic.claude/converse-stream", rawPath)
	}

	{
		path, _ := SetLLMModelPath(corev1.Service_Spec_Config_LLM_BEDROCK,
			"/model/anthropic.claude-v1:0", "anthropic.claude-v2:0")
		assert.Equal(t, "", path)
	}

	{
		path, _ := SetLLMModelPath(corev1.Service_Spec_Config_LLM_OPENAI,
			"/v1/chat/completions", "gpt-4o")
		assert.Equal(t, "", path)
	}
}

func TestNextLLMJSONArrayMessage(t *testing.T) {
	body := []byte(`[{"candidates":[{"content":{"parts":[{"text":"a]}"}]}}]},` +
		"\r\n" + `{"usageMetadata":{"totalTokenCount":11}}]`)

	var msgs []string
	for len(body) > 0 {
		payload, n := NextLLMJSONArrayMessage(body)
		assert.True(t, n > 0)
		body = body[n:]
		if len(payload) > 0 {
			msgs = append(msgs, string(payload))
		}
	}

	assert.Equal(t, 2, len(msgs))
	assert.Equal(t, `{"candidates":[{"content":{"parts":[{"text":"a]}"}]}}]}`, msgs[0])
	assert.Equal(t, `{"usageMetadata":{"totalTokenCount":11}}`, msgs[1])

	{
		_, n := NextLLMJSONArrayMessage([]byte(`[{"a":1`))
		assert.Equal(t, 0, n)
	}

	{
		_, n := NextLLMJSONArrayMessage([]byte(`data: {"a":1}`))
		assert.Equal(t, -1, n)
	}

	{
		_, n := NextLLMJSONArrayMessage([]byte("  \r\n"))
		assert.Equal(t, 4, n)
	}
}

func TestParseLLMRequestGeminiEmbed(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/text-embedding-004:embedContent",
			`{"content":{"parts":[{"text":"`+strings.Repeat("a", 400)+`"}]}}`)

		assert.True(t, llmReq.IsKnownRoute)
		assert.Equal(t, corev1.RequestContext_Request_LLM_EMBED_CONTENT,
			llmReq.Operation)
		assert.Equal(t, "text-embedding-004", llmReq.Model)
		assert.True(t, llmReq.EstimatedInputTokens >= 100)
		assert.Equal(t, corev1.RequestContext_Request_LLM_COMPLETE,
			llmReq.EstimateQuality)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/text-embedding-004:batchEmbedContents",
			`{"requests":[{"model":"models/text-embedding-004","content":{"parts":`+
				`[{"text":"`+strings.Repeat("a", 400)+`"}]}}]}`)

		assert.Equal(t, uint32(1), llmReq.InputItemCount)
		assert.True(t, llmReq.EstimatedInputTokens >= 100)
	}
}

func TestParseLLMRequestGeminiOpaque(t *testing.T) {

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:generateContent",
			`{"contents":[{"role":"user","parts":[{"text":"Hello"}]}],`+
				`"cachedContent":"cachedContents/abcd"}`)

		assert.Equal(t, corev1.RequestContext_Request_LLM_PARTIAL,
			llmReq.EstimateQuality)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:generateContent",
			`{"contents":[{"role":"user","parts":[{"inline_data":`+
				`{"mime_type":"image/png","data":"`+strings.Repeat("A", 4000)+`"}}]}]}`)

		assert.True(t, llmReq.HasImageInput)
		assert.Equal(t, corev1.RequestContext_Request_LLM_PARTIAL,
			llmReq.EstimateQuality)
		assert.True(t, llmReq.EstimatedInputTokens >= llmTokensPerImage)
	}

	{
		llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_GEMINI,
			http.MethodPost, "/v1beta/models/gemini-2.5-pro:generateContent",
			`{"contents":[{"role":"user","parts":[{"fileData":`+
				`{"mimeType":"application/pdf","fileUri":"https://example.com/a.pdf"}}]}]}`)

		assert.False(t, llmReq.HasImageInput)
		assert.Equal(t, corev1.RequestContext_Request_LLM_PARTIAL,
			llmReq.EstimateQuality)
	}
}

func TestParseLLMRequestBedrockDocument(t *testing.T) {
	llmReq := parseLLM(t, corev1.Service_Spec_Config_LLM_BEDROCK,
		http.MethodPost, "/model/anthropic.claude-v1:0/converse",
		`{"messages":[{"role":"user","content":[{"document":{"format":"pdf",`+
			`"name":"a","source":{"bytes":"`+strings.Repeat("A", 4000)+`"}}}]}]}`)

	assert.False(t, llmReq.HasImageInput)
	assert.Equal(t, corev1.RequestContext_Request_LLM_PARTIAL, llmReq.EstimateQuality)
}
