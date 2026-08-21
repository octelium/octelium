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

package accesslog

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
)

const llmReqBody = `{"model":"gpt-4o","messages":[{"role":"user","content":"my s3cr3t prompt"}]}`

const llmRespBody = `{"id":"chatcmpl-1","model":"gpt-4o-2024-11-20",` +
	`"choices":[{"finish_reason":"stop","message":{"content":"hi"}}],` +
	`"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}`

func newLLMReqCtx(t *testing.T,
	cfg *corev1.Service_Spec_Config_LLM) *middlewares.RequestContext {

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "my-llm.default",
			Uid:  "d3d0d2a2-0000-0000-0000-000000000002",
		},
		Spec: &corev1.Service_Spec{
			Mode:     corev1.Service_Spec_LLM,
			IsPublic: true,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "default"},
		},
	}

	req := httptest.NewRequest(http.MethodPost,
		"http://my-llm.example.com/v1/chat/completions", strings.NewReader(llmReqBody))

	llmReq := httputils.ParseLLMRequest(req, cfg.GetProtocol(), []byte(llmReqBody))

	return &middlewares.RequestContext{
		CreatedAt: time.Now(),
		Service:   svc,
		ServiceConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Llm{Llm: cfg},
		},
		Body: []byte(llmReqBody),
		LLM:  llmReq,
		DownstreamInfo: &corev1.RequestContext{
			Service: svc,
			Request: &corev1.RequestContext_Request{
				Type: &corev1.RequestContext_Request_Llm{
					Llm: middlewares.GetLLMRequestContext(llmReq, nil),
				},
			},
		},
		DownstreamRequest: &coctovigilv1.DownstreamRequest{
			Source: &coctovigilv1.DownstreamRequest_Source{
				Address: "127.0.0.1",
				Port:    12345,
			},
		},
	}
}

func serveLLMLog(t *testing.T, cfg *corev1.Service_Spec_Config_LLM,
	respBody string, isSSE bool) *corev1.AccessLog_Entry_Info_LLM {

	reqCtx := newLLMReqCtx(t, cfg)

	req := httptest.NewRequest(http.MethodPost,
		"http://my-llm.example.com/v1/chat/completions", strings.NewReader(llmReqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "openai-python/1.0")

	rw := httptest.NewRecorder()
	crw := newResponseWriter(rw, streamKindLLM)
	crw.maxSSEEvent = defaultMaxLLMStreamEventBytes
	crw.maxBody = maxLLMResponseBodyBytes

	obs := &llmObserver{}
	crw.onSSEEvent = obs.onSSEEvent

	if isSSE {
		crw.Header().Set("Content-Type", "text/event-stream")
	} else {
		crw.Header().Set("Content-Type", "application/json")
	}

	_, err := crw.Write([]byte(respBody))
	assert.Nil(t, err)

	md := &middleware{}

	phase := logPhaseComplete
	if isSSE {
		phase = logPhaseStreamClose
	} else {
		obs.onFinalBody(crw.body.Bytes())
	}

	logE := md.getLLMAccessLog(req, crw, reqCtx, obs, phase, "", 0)
	assert.NotNil(t, logE)

	return logE.Entry.Info.GetLlm()
}

func TestLLMAccessLogComplete(t *testing.T) {
	llmC := serveLLMLog(t, &corev1.Service_Spec_Config_LLM{}, llmRespBody, false)

	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_COMPLETE, llmC.Type)
	assert.Equal(t, corev1.Service_Spec_Config_LLM_OPENAI, llmC.Protocol)
	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_CHAT_COMPLETIONS, llmC.Operation)
	assert.Equal(t, "gpt-4o", llmC.RequestedModel)
	assert.Equal(t, "gpt-4o-2024-11-20", llmC.Model)
	assert.Equal(t, "chatcmpl-1", llmC.ResponseID)
	assert.Equal(t, "stop", llmC.FinishReason)
	assert.False(t, llmC.Stream)
	assert.True(t, llmC.EstimatedInputTokens > 0)

	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_Usage_PROVIDER, llmC.Usage.Source)
	assert.Equal(t, uint64(12), llmC.Usage.InputTokens)
	assert.Equal(t, uint64(8), llmC.Usage.OutputTokens)
	assert.Equal(t, uint64(20), llmC.Usage.TotalTokens)
}

func TestLLMAccessLogStream(t *testing.T) {

	{
		stream := "data: " +
			`{"id":"chatcmpl-2","model":"gpt-4o","choices":[{"delta":{"content":"He"}}]}` +
			"\n\n" +
			"data: " +
			`{"id":"chatcmpl-2","choices":[{"delta":{"content":"llo"},"finish_reason":null}]}` +
			"\n\n" +
			"data: " +
			`{"id":"chatcmpl-2","choices":[{"delta":{},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}` +
			"\n\n" +
			"data: [DONE]\n\n"

		llmC := serveLLMLog(t, &corev1.Service_Spec_Config_LLM{}, stream, true)

		assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_STREAM_END, llmC.Type)
		assert.Equal(t, "chatcmpl-2", llmC.ResponseID)
		assert.Equal(t, "stop", llmC.FinishReason)
		assert.Equal(t, uint64(4), llmC.EventCount)

		assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_Usage_PROVIDER, llmC.Usage.Source)
		assert.Equal(t, uint64(5), llmC.Usage.InputTokens)
		assert.Equal(t, uint64(3), llmC.Usage.OutputTokens)

		assert.NotNil(t, llmC.TimeToFirstToken)
	}

	{
		stream := "data: " +
			`{"id":"chatcmpl-3","model":"gpt-4o","choices":[{"delta":{"content":"He"}}],` +
			`"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}` +
			"\n\n"

		llmC := serveLLMLog(t, &corev1.Service_Spec_Config_LLM{}, stream, true)

		assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_Usage_PARTIAL, llmC.Usage.Source)
		assert.Empty(t, llmC.FinishReason)
	}
}

func TestLLMAccessLogUsageFallback(t *testing.T) {
	llmC := serveLLMLog(t, &corev1.Service_Spec_Config_LLM{},
		`{"id":"chatcmpl-4","model":"local-model","choices":[{"finish_reason":"stop"}]}`,
		false)

	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_Usage_ESTIMATED, llmC.Usage.Source)
	assert.Equal(t, llmC.EstimatedInputTokens, llmC.Usage.InputTokens)
	assert.Equal(t, uint64(0), llmC.Usage.OutputTokens)
}

func TestLLMVisibility(t *testing.T) {

	{
		reqCtx := newLLMReqCtx(t, &corev1.Service_Spec_Config_LLM{})

		req := httptest.NewRequest(http.MethodPost,
			"http://my-llm.example.com/v1/chat/completions", strings.NewReader(llmReqBody))

		rw := httptest.NewRecorder()
		crw := newResponseWriter(rw, streamKindLLM)
		crw.Header().Set("Content-Type", "application/json")
		_, err := crw.Write([]byte(llmRespBody))
		assert.Nil(t, err)

		md := &middleware{}
		logE := md.getLLMAccessLog(req, crw, reqCtx, &llmObserver{}, logPhaseComplete, "", 0)

		httpC := logE.Entry.Info.GetLlm().GetHttp()
		assert.Empty(t, httpC.Request.Body)
		assert.Nil(t, httpC.Request.BodyMap)
		assert.Empty(t, httpC.Response.Body)
		assert.Nil(t, httpC.Response.BodyMap)
	}

	{
		reqCtx := newLLMReqCtx(t, &corev1.Service_Spec_Config_LLM{
			Visibility: &corev1.Service_Spec_Config_LLM_Visibility{
				EnableRequestBody:     true,
				EnableRequestBodyMap:  true,
				EnableResponseBody:    true,
				EnableResponseBodyMap: true,
			},
		})

		req := httptest.NewRequest(http.MethodPost,
			"http://my-llm.example.com/v1/chat/completions", strings.NewReader(llmReqBody))

		rw := httptest.NewRecorder()
		crw := newResponseWriter(rw, streamKindLLM)
		crw.Header().Set("Content-Type", "application/json")
		_, err := crw.Write([]byte(llmRespBody))
		assert.Nil(t, err)

		md := &middleware{}
		logE := md.getLLMAccessLog(req, crw, reqCtx, &llmObserver{}, logPhaseComplete, "", 0)

		httpC := logE.Entry.Info.GetLlm().GetHttp()
		assert.Equal(t, llmReqBody, string(httpC.Request.Body))
		assert.NotNil(t, httpC.Request.BodyMap)
		assert.Equal(t, llmRespBody, string(httpC.Response.Body))
		assert.NotNil(t, httpC.Response.BodyMap)
	}
}

func TestLLMAccessLogLargeBody(t *testing.T) {
	body := `{"id":"chatcmpl-5","model":"gpt-4o","choices":[{"finish_reason":"stop",` +
		`"message":{"content":"` + strings.Repeat("x", 64*1024) + `"}}],` +
		`"usage":{"prompt_tokens":11,"completion_tokens":9000,"total_tokens":9011}}`

	llmC := serveLLMLog(t, &corev1.Service_Spec_Config_LLM{}, body, false)

	assert.Equal(t, "chatcmpl-5", llmC.ResponseID)
	assert.Equal(t, "gpt-4o", llmC.Model)
	assert.Equal(t, "stop", llmC.FinishReason)

	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_Usage_PROVIDER, llmC.Usage.Source)
	assert.Equal(t, uint64(11), llmC.Usage.InputTokens)
	assert.Equal(t, uint64(9000), llmC.Usage.OutputTokens)

	assert.Empty(t, llmC.GetHttp().Response.Body)
}

func TestLLMAccessLogAnthropicStream(t *testing.T) {
	stream := "data: " +
		`{"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-4",` +
		`"usage":{"input_tokens":100,"cache_read_input_tokens":40,` +
		`"cache_creation_input_tokens":25,"output_tokens":1}}}` +
		"\n\n" +
		"data: " +
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}` +
		"\n\n" +
		"data: " +
		`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":50}}` +
		"\n\n"

	llmC := serveLLMLog(t, &corev1.Service_Spec_Config_LLM{
		Protocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
	}, stream, true)

	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_STREAM_END, llmC.Type)
	assert.Equal(t, "msg_1", llmC.ResponseID)
	assert.Equal(t, "claude-sonnet-4", llmC.Model)
	assert.Equal(t, "end_turn", llmC.FinishReason)

	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_Usage_PROVIDER, llmC.Usage.Source)
	assert.Equal(t, uint64(100), llmC.Usage.InputTokens)
	assert.Equal(t, uint64(50), llmC.Usage.OutputTokens)
	assert.Equal(t, uint64(215), llmC.Usage.TotalTokens)
	assert.Equal(t, uint64(40), llmC.Usage.CacheReadInputTokens)
	assert.Equal(t, uint64(25), llmC.Usage.CacheCreationInputTokens)
}

func TestLLMAccessLogUsageUnset(t *testing.T) {

	{
		reqCtx := newLLMReqCtx(t, &corev1.Service_Spec_Config_LLM{})

		req := httptest.NewRequest(http.MethodGet,
			"http://my-llm.example.com/v1/models", nil)

		reqCtx.LLM = httputils.ParseLLMRequest(req,
			corev1.Service_Spec_Config_LLM_OPENAI, nil)

		rw := httptest.NewRecorder()
		crw := newResponseWriter(rw, streamKindLLM)
		crw.maxBody = maxLLMResponseBodyBytes
		crw.Header().Set("Content-Type", "application/json")
		_, err := crw.Write([]byte(`{"object":"list","data":[]}`))
		assert.Nil(t, err)

		md := &middleware{}
		logE := md.getLLMAccessLog(req, crw, reqCtx, &llmObserver{},
			logPhaseComplete, "", 0)

		llmC := logE.Entry.Info.GetLlm()
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_Usage_SOURCE_UNSET, llmC.Usage.Source)
		assert.Equal(t, uint64(0), llmC.Usage.TotalTokens)
	}

	{
		reqCtx := newLLMReqCtx(t, &corev1.Service_Spec_Config_LLM{})

		req := httptest.NewRequest(http.MethodPost,
			"http://my-llm.example.com/v1/chat/completions", strings.NewReader(llmReqBody))

		rw := httptest.NewRecorder()
		crw := newResponseWriter(rw, streamKindLLM)
		crw.maxBody = maxLLMResponseBodyBytes
		crw.Header().Set("Content-Type", "application/json")
		crw.WriteHeader(http.StatusTooManyRequests)
		_, err := crw.Write([]byte(`{"error":{"message":"rate limited"}}`))
		assert.Nil(t, err)

		md := &middleware{}
		logE := md.getLLMAccessLog(req, crw, reqCtx, &llmObserver{},
			logPhaseComplete, "", 0)

		llmC := logE.Entry.Info.GetLlm()
		assert.Equal(t,
			corev1.AccessLog_Entry_Info_LLM_Usage_SOURCE_UNSET, llmC.Usage.Source)
	}
}

func TestLLMAccessLogOversizedStreamEvent(t *testing.T) {
	reqCtx := newLLMReqCtx(t, &corev1.Service_Spec_Config_LLM{})

	req := httptest.NewRequest(http.MethodPost,
		"http://my-llm.example.com/v1/chat/completions", strings.NewReader(llmReqBody))

	rw := httptest.NewRecorder()
	crw := newResponseWriter(rw, streamKindLLM)
	crw.maxSSEEvent = 512
	crw.Header().Set("Content-Type", "text/event-stream")

	obs := &llmObserver{}
	crw.onSSEEvent = obs.onSSEEvent

	_, err := crw.Write([]byte("data: " +
		`{"id":"chatcmpl-9","usage":{"prompt_tokens":99999,"completion_tokens":1},` +
		`"pad":"` + strings.Repeat("x", 2048)))
	assert.Nil(t, err)

	_, err = crw.Write([]byte(strings.Repeat("x", 2048) + `"}` + "\n\n"))
	assert.Nil(t, err)

	_, err = crw.Write([]byte("data: " +
		`{"id":"chatcmpl-9","choices":[{"delta":{},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}` + "\n\n"))
	assert.Nil(t, err)

	md := &middleware{}
	logE := md.getLLMAccessLog(req, crw, reqCtx, obs, logPhaseStreamClose, "", 1)

	llmC := logE.Entry.Info.GetLlm()

	assert.Equal(t, uint64(5), llmC.Usage.InputTokens)
	assert.Equal(t, uint64(3), llmC.Usage.OutputTokens)
	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_Usage_PARTIAL, llmC.Usage.Source)
	assert.Equal(t, uint64(1), llmC.EventCount)
	assert.Equal(t, "stop", llmC.FinishReason)
}

func TestLLMAccessLogOversizedStreamEventSingleWrite(t *testing.T) {
	reqCtx := newLLMReqCtx(t, &corev1.Service_Spec_Config_LLM{})

	req := httptest.NewRequest(http.MethodPost,
		"http://my-llm.example.com/v1/chat/completions", strings.NewReader(llmReqBody))

	rw := httptest.NewRecorder()
	crw := newResponseWriter(rw, streamKindLLM)
	crw.maxSSEEvent = 512
	crw.Header().Set("Content-Type", "text/event-stream")

	obs := &llmObserver{}
	crw.onSSEEvent = obs.onSSEEvent

	_, err := crw.Write([]byte("data: " +
		`{"id":"chatcmpl-9","usage":{"prompt_tokens":99999,"completion_tokens":1},` +
		`"pad":"` + strings.Repeat("x", 4096) + `"}` + "\n\n"))
	assert.Nil(t, err)

	_, err = crw.Write([]byte("data: " +
		`{"id":"chatcmpl-9","choices":[{"delta":{},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}` + "\n\n"))
	assert.Nil(t, err)

	md := &middleware{}
	logE := md.getLLMAccessLog(req, crw, reqCtx, obs, logPhaseStreamClose, "", 1)

	llmC := logE.Entry.Info.GetLlm()

	assert.Equal(t, uint64(5), llmC.Usage.InputTokens)
	assert.Equal(t, uint64(3), llmC.Usage.OutputTokens)
	assert.Equal(t, corev1.AccessLog_Entry_Info_LLM_Usage_PARTIAL, llmC.Usage.Source)
	assert.Equal(t, uint64(1), llmC.EventCount)
	assert.Equal(t, "stop", llmC.FinishReason)
}
