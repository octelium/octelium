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

package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type transOpts struct {
	protocol         corev1.Service_Spec_Config_LLM_Protocol
	upstreamProtocol corev1.Service_Spec_Config_LLM_Protocol

	path string
	body string

	reasoning *corev1.Service_Spec_Config_LLM_Reasoning
	limits    *corev1.Service_Spec_Config_LLM_Limits

	defaultMaxOutputTokens uint64

	header map[string]string

	isStream bool

	cacheC *fakeCache

	upstream http.HandlerFunc
}

type transResult struct {
	isNext bool
	code   int

	upstream       map[string]any
	upstreamPath   string
	upstreamHeader http.Header
	upstreamBody   string

	body   string
	header http.Header

	reqCtx *middlewares.RequestContext
}

func (r *transResult) json(t *testing.T) map[string]any {
	ret := make(map[string]any)
	assert.Nil(t, json.Unmarshal([]byte(r.body), &ret))
	return ret
}

func (r *transResult) events(t *testing.T) []map[string]any {
	var ret []map[string]any

	for _, event := range strings.Split(r.body, "\n\n") {
		data := httputils.GetSSEEventData([]byte(event))
		if len(data) == 0 || httputils.IsLLMStreamDone(data) {
			continue
		}
		cur := make(map[string]any)
		assert.Nil(t, json.Unmarshal(data, &cur), string(data))
		ret = append(ret, cur)
	}

	return ret
}

const transTestModel = "corp-model"

func transDefaultPath(protocol corev1.Service_Spec_Config_LLM_Protocol,
	isStream bool) string {

	path, _, query := httputils.GetLLMRoutePath(protocol,
		getTransRoute(protocol, corev1.Service_Spec_Config_LLM_GENERATE),
		transTestModel, isStream)

	if query != "" {
		return path + "?" + query
	}

	return path
}

type fakeCache struct {
	rcachev1.MainServiceClient

	entries map[string][]byte
}

func newFakeCache() *fakeCache {
	return &fakeCache{entries: make(map[string][]byte)}
}

func (c *fakeCache) SetCache(ctx context.Context, req *rcachev1.SetCacheRequest,
	opts ...grpc.CallOption) (*rcachev1.SetCacheResponse, error) {
	c.entries[string(req.Key)] = req.Data
	return &rcachev1.SetCacheResponse{}, nil
}

func (c *fakeCache) GetCache(ctx context.Context, req *rcachev1.GetCacheRequest,
	opts ...grpc.CallOption) (*rcachev1.GetCacheResponse, error) {
	data, ok := c.entries[string(req.Key)]
	if !ok {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return &rcachev1.GetCacheResponse{Data: data}, nil
}

func serveTranslation(t *testing.T, o *transOpts) *transResult {
	ctx := context.Background()
	ret := &transResult{}

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ret.isNext = true
		ret.upstreamPath = r.URL.Path
		ret.upstreamHeader = r.Header.Clone()

		out, err := io.ReadAll(r.Body)
		assert.Nil(t, err)
		ret.upstreamBody = string(out)
		if len(out) > 0 {
			assert.Equal(t, int64(len(out)), r.ContentLength)
			assert.Nil(t, json.Unmarshal(out, &ret.upstream))
		}

		if o.upstream != nil {
			o.upstream(w, r)
		}
	})

	var mdlwr http.Handler = next

	if o.cacheC == nil {
		o.cacheC = newFakeCache()
	}

	mdlwr, err = NewTranslation(ctx, mdlwr,
		&fakeOcteliumC{cacheC: o.cacheC}, newService().Metadata.Uid)
	assert.Nil(t, err)

	mdlwr, err = NewReasoning(ctx, mdlwr, celEngine)
	assert.Nil(t, err)

	path := o.path
	if path == "" {
		path = transDefaultPath(o.protocol, o.isStream)
	}

	req := httptest.NewRequest(http.MethodPost, "http://my-llm.example.com"+path,
		strings.NewReader(o.body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range o.header {
		req.Header.Set(k, v)
	}

	cfg := &corev1.Service_Spec_Config_LLM{
		Protocol:  o.protocol,
		Reasoning: o.reasoning,
		Limits:    o.limits,
		Translation: &corev1.Service_Spec_Config_LLM_Translation{
			UpstreamProtocol:       o.upstreamProtocol,
			DefaultMaxOutputTokens: o.defaultMaxOutputTokens,
		},
	}

	svcCfg := &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Llm{Llm: cfg},
	}

	bodyMap := make(map[string]any)
	json.Unmarshal([]byte(o.body), &bodyMap)

	llmReq := httputils.ParseLLMRequest(req, o.protocol, []byte(o.body))

	httpC := &corev1.RequestContext_Request_HTTP{
		Method: http.MethodPost,
		Path:   req.URL.Path,
		Body:   []byte(o.body),
		Size:   int64(len(o.body)),
	}
	downstreamReq := &coctovigilv1.DownstreamRequest{
		Request: &corev1.RequestContext_Request{
			Type: &corev1.RequestContext_Request_Llm{
				Llm: middlewares.GetLLMRequestContext(llmReq, httpC),
			},
		},
	}

	reqCtx := &middlewares.RequestContext{
		CreatedAt:         time.Now(),
		Service:           newService(),
		ServiceConfig:     svcCfg,
		Body:              []byte(o.body),
		BodyJSONMap:       bodyMap,
		LLM:               llmReq,
		DownstreamRequest: downstreamReq,
		DownstreamInfo: &corev1.RequestContext{
			Request: downstreamReq.Request,
			Session: &corev1.Session{
				Metadata: &metav1.Metadata{Uid: "f1c1d2a2-0000-0000-0000-000000000009"},
			},
		},
	}
	reqCtx.SetBodyDigest()
	reqCtx.SetReqCtxMap()
	ret.reqCtx = reqCtx

	req = req.WithContext(context.WithValue(ctx,
		middlewares.CtxRequestContext, reqCtx))

	rw := httptest.NewRecorder()
	mdlwr.ServeHTTP(rw, req)

	reqCtx.RunOnResponse()

	ret.code = rw.Result().StatusCode
	ret.body = rw.Body.String()
	ret.header = rw.Result().Header

	return ret
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(body))
}

func writeSSE(w http.ResponseWriter, events ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	for _, event := range events {
		w.Write([]byte(event))
	}
}

func newOpenAIToAnthropic(body string) *transOpts {
	return &transOpts{
		protocol:         corev1.Service_Spec_Config_LLM_OPENAI,
		upstreamProtocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
		body:             body,
	}
}

func newAnthropicToOpenAI(body string) *transOpts {
	return &transOpts{
		protocol:         corev1.Service_Spec_Config_LLM_ANTHROPIC,
		upstreamProtocol: corev1.Service_Spec_Config_LLM_OPENAI,
		body:             body,
	}
}

func TestTranslationDisabled(t *testing.T) {
	o := &transOpts{
		protocol: corev1.Service_Spec_Config_LLM_OPENAI,
		body:     `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`,
	}

	res := serveTranslation(t, o)

	assert.True(t, res.isNext)
	assert.Equal(t, openAIChatPath, res.upstreamPath)
	assert.Equal(t, o.body, res.upstreamBody)
	assert.Nil(t, res.reqCtx.LLMTranslation)
}

func TestTranslationSameProtocol(t *testing.T) {
	o := &transOpts{
		protocol:         corev1.Service_Spec_Config_LLM_ANTHROPIC,
		upstreamProtocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
		body: `{"model":"claude-sonnet-4-5","max_tokens":64,` +
			`"messages":[{"role":"user","content":"Hello"}]}`,
	}

	res := serveTranslation(t, o)

	assert.True(t, res.isNext)
	assert.Equal(t, anthropicMessagesPath, res.upstreamPath)
	assert.Equal(t, o.body, res.upstreamBody)
	assert.Nil(t, res.reqCtx.LLMTranslation)
}

func TestTranslationOpenAIToAnthropicRequest(t *testing.T) {
	{
		o := newOpenAIToAnthropic(`{"model":"claude-sonnet-4-5","messages":[` +
			`{"role":"system","content":"You are Acme's assistant."},` +
			`{"role":"developer","content":"Never expose secrets."},` +
			`{"role":"user","content":"Hello"}],` +
			`"max_completion_tokens":256,"stop":"END","temperature":0.5}`)

		res := serveTranslation(t, o)

		assert.True(t, res.isNext)
		assert.Equal(t, anthropicMessagesPath, res.upstreamPath)
		assert.Equal(t, anthropicDefaultVersion,
			res.upstreamHeader.Get(anthropicVersionHeader))

		assert.Equal(t, "claude-sonnet-4-5", res.upstream["model"])
		assert.Equal(t, float64(256), res.upstream["max_tokens"])
		assert.Equal(t, []any{"END"}, res.upstream["stop_sequences"])
		assert.Equal(t, 0.5, res.upstream["temperature"])

		system := res.upstream["system"].([]any)
		assert.Equal(t, 2, len(system))
		assert.Equal(t, "You are Acme's assistant.",
			system[0].(map[string]any)["text"])
		assert.Equal(t, "Never expose secrets.",
			system[1].(map[string]any)["text"])

		msgs := res.upstream["messages"].([]any)
		assert.Equal(t, 1, len(msgs))
		first := msgs[0].(map[string]any)
		assert.Equal(t, roleUser, first["role"])
		blocks := first["content"].([]any)
		assert.Equal(t, "text", blocks[0].(map[string]any)["type"])
		assert.Equal(t, "Hello", blocks[0].(map[string]any)["text"])

		assert.Equal(t, corev1.Service_Spec_Config_LLM_ANTHROPIC,
			res.reqCtx.LLMTranslation.UpstreamProtocol)
		assert.Equal(t, corev1.RequestContext_Request_LLM_MESSAGES,
			res.reqCtx.LLMTranslation.UpstreamRoute)
	}

	{
		o := newOpenAIToAnthropic(
			`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hello"}]}`)

		res := serveTranslation(t, o)

		assert.Equal(t, float64(defaultTransMaxOutputTokens), res.upstream["max_tokens"])
	}

	{
		o := newOpenAIToAnthropic(
			`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hello"}]}`)
		o.defaultMaxOutputTokens = 1024

		res := serveTranslation(t, o)

		assert.Equal(t, float64(1024), res.upstream["max_tokens"])
	}

	{
		o := newOpenAIToAnthropic(
			`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hello"}]}`)
		o.defaultMaxOutputTokens = 1024
		o.limits = &corev1.Service_Spec_Config_LLM_Limits{MaxOutputTokens: 512}

		res := serveTranslation(t, o)

		assert.Equal(t, float64(512), res.upstream["max_tokens"])
	}
}

func TestTranslationOpenAIToAnthropicTools(t *testing.T) {
	body := `{"model":"claude-sonnet-4-5","messages":[` +
		`{"role":"user","content":"Weather in Cairo?"},` +
		`{"role":"assistant","content":null,"tool_calls":[` +
		`{"id":"call_123","type":"function","function":` +
		`{"name":"get_weather","arguments":"{\"city\":\"Cairo\"}"}}]},` +
		`{"role":"tool","tool_call_id":"call_123","content":"{\"temperature\":31}"}],` +
		`"tools":[{"type":"function","function":{"name":"get_weather",` +
		`"description":"Get weather","parameters":{"type":"object",` +
		`"properties":{"city":{"type":"string"}},"required":["city"]}}}],` +
		`"tool_choice":"required","parallel_tool_calls":false}`

	res := serveTranslation(t, newOpenAIToAnthropic(body))

	assert.True(t, res.isNext)

	tools := res.upstream["tools"].([]any)
	assert.Equal(t, 1, len(tools))
	tool := tools[0].(map[string]any)
	assert.Equal(t, "get_weather", tool["name"])
	assert.Equal(t, "Get weather", tool["description"])
	schema := tool["input_schema"].(map[string]any)
	assert.Equal(t, "object", schema["type"])

	choice := res.upstream["tool_choice"].(map[string]any)
	assert.Equal(t, "any", choice["type"])
	assert.Equal(t, true, choice["disable_parallel_tool_use"])

	msgs := res.upstream["messages"].([]any)
	assert.Equal(t, 3, len(msgs))

	assistant := msgs[1].(map[string]any)
	assert.Equal(t, roleAssistant, assistant["role"])
	block := assistant["content"].([]any)[0].(map[string]any)
	assert.Equal(t, "tool_use", block["type"])
	assert.Equal(t, "call_123", block["id"])
	assert.Equal(t, "get_weather", block["name"])
	assert.Equal(t, "Cairo", block["input"].(map[string]any)["city"])

	result := msgs[2].(map[string]any)
	assert.Equal(t, roleUser, result["role"])
	resultBlock := result["content"].([]any)[0].(map[string]any)
	assert.Equal(t, "tool_result", resultBlock["type"])
	assert.Equal(t, "call_123", resultBlock["tool_use_id"])
	assert.Equal(t, `{"temperature":31}`, resultBlock["content"])
}

func TestTranslationOpenAIToAnthropicParallelToolResults(t *testing.T) {
	body := `{"model":"claude-sonnet-4-5","messages":[` +
		`{"role":"user","content":"Hi"},` +
		`{"role":"assistant","tool_calls":[` +
		`{"id":"call_a","type":"function","function":{"name":"a","arguments":"{}"}},` +
		`{"id":"call_b","type":"function","function":{"name":"b","arguments":"{}"}}]},` +
		`{"role":"tool","tool_call_id":"call_a","content":"A"},` +
		`{"role":"tool","tool_call_id":"call_b","content":"B"}]}`

	res := serveTranslation(t, newOpenAIToAnthropic(body))

	msgs := res.upstream["messages"].([]any)
	assert.Equal(t, 3, len(msgs))

	results := msgs[2].(map[string]any)["content"].([]any)
	assert.Equal(t, 2, len(results))
	assert.Equal(t, "call_a", results[0].(map[string]any)["tool_use_id"])
	assert.Equal(t, "call_b", results[1].(map[string]any)["tool_use_id"])
}

func TestTranslationOpenAIToAnthropicImage(t *testing.T) {
	{
		body := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":[` +
			`{"type":"text","text":"What is this?"},` +
			`{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]}`

		res := serveTranslation(t, newOpenAIToAnthropic(body))

		blocks := res.upstream["messages"].([]any)[0].(map[string]any)["content"].([]any)
		assert.Equal(t, 2, len(blocks))
		image := blocks[1].(map[string]any)
		assert.Equal(t, "image", image["type"])
		source := image["source"].(map[string]any)
		assert.Equal(t, "base64", source["type"])
		assert.Equal(t, "image/png", source["media_type"])
		assert.Equal(t, "AAAA", source["data"])
	}

	{
		body := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":[` +
			`{"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}`

		res := serveTranslation(t, newOpenAIToAnthropic(body))

		blocks := res.upstream["messages"].([]any)[0].(map[string]any)["content"].([]any)
		source := blocks[0].(map[string]any)["source"].(map[string]any)
		assert.Equal(t, "url", source["type"])
		assert.Equal(t, "https://example.com/a.png", source["url"])
	}
}

func TestTranslationOpenAIToAnthropicResponse(t *testing.T) {
	o := newOpenAIToAnthropic(
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hello"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"id":"msg_abc","type":"message","role":"assistant",`+
			`"model":"claude-sonnet-4-5-20250929","content":[{"type":"text","text":"Hi"}],`+
			`"stop_reason":"end_turn","stop_sequence":null,`+
			`"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":3}}`)
	}

	res := serveTranslation(t, o)

	assert.Equal(t, http.StatusOK, res.code)

	out := res.json(t)
	assert.Equal(t, openAIObjectCompletion, out["object"])
	assert.Equal(t, "claude-sonnet-4-5-20250929", out["model"])
	assert.True(t, strings.HasPrefix(out["id"].(string), "chatcmpl_"))

	choice := out["choices"].([]any)[0].(map[string]any)
	assert.Equal(t, "stop", choice["finish_reason"])
	assert.Equal(t, "Hi", choice["message"].(map[string]any)["content"])

	usage := out["usage"].(map[string]any)
	assert.Equal(t, float64(13), usage["prompt_tokens"])
	assert.Equal(t, float64(5), usage["completion_tokens"])
	assert.Equal(t, float64(18), usage["total_tokens"])
	assert.Equal(t, float64(3),
		usage["prompt_tokens_details"].(map[string]any)["cached_tokens"])

	upstream := res.reqCtx.LLMUpstreamResponse
	assert.Equal(t, "msg_abc", upstream.ResponseID)
	assert.Equal(t, "end_turn", upstream.FinishReason)
	assert.Equal(t, uint64(10), upstream.Usage.InputTokens)
	assert.Equal(t, uint64(5), upstream.Usage.OutputTokens)
}

func TestTranslationOpenAIToAnthropicResponseToolCall(t *testing.T) {
	o := newOpenAIToAnthropic(
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hello"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"id":"msg_abc","type":"message","role":"assistant",`+
			`"model":"claude-sonnet-4-5","content":[`+
			`{"type":"text","text":"Let me check."},`+
			`{"type":"tool_use","id":"toolu_1","name":"get_weather",`+
			`"input":{"city":"Cairo"}}],`+
			`"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":5}}`)
	}

	res := serveTranslation(t, o)

	choice := res.json(t)["choices"].([]any)[0].(map[string]any)
	assert.Equal(t, "tool_calls", choice["finish_reason"])

	msg := choice["message"].(map[string]any)
	assert.Equal(t, "Let me check.", msg["content"])

	calls := msg["tool_calls"].([]any)
	assert.Equal(t, 1, len(calls))
	call := calls[0].(map[string]any)
	assert.Equal(t, "toolu_1", call["id"])
	assert.Equal(t, functionToolKind, call["type"])
	assert.Equal(t, "get_weather", call["function"].(map[string]any)["name"])
	assert.Equal(t, `{"city":"Cairo"}`, call["function"].(map[string]any)["arguments"])
}

func TestTranslationOpenAIToAnthropicStream(t *testing.T) {
	o := newOpenAIToAnthropic(`{"model":"claude-sonnet-4-5","stream":true,` +
		`"stream_options":{"include_usage":true},` +
		`"messages":[{"role":"user","content":"Hello"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		writeSSE(w,
			`event: message_start`+"\n"+
				`data: {"type":"message_start","message":{"id":"msg_abc",`+
				`"type":"message","role":"assistant","model":"claude-sonnet-4-5",`+
				`"content":[],"usage":{"input_tokens":10,"output_tokens":0}}}`+"\n\n",
			`event: content_block_start`+"\n"+
				`data: {"type":"content_block_start","index":0,`+
				`"content_block":{"type":"text","text":""}}`+"\n\n",
			`event: content_block_delta`+"\n"+
				`data: {"type":"content_block_delta","index":0,`+
				`"delta":{"type":"text_delta","text":"He"}}`+"\n\n",
			`event: content_block_delta`+"\n"+
				`data: {"type":"content_block_delta","index":0,`+
				`"delta":{"type":"text_delta","text":"llo"}}`+"\n\n",
			`event: content_block_stop`+"\n"+
				`data: {"type":"content_block_stop","index":0}`+"\n\n",
			`event: message_delta`+"\n"+
				`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},`+
				`"usage":{"output_tokens":7}}`+"\n\n",
			`event: message_stop`+"\n"+`data: {"type":"message_stop"}`+"\n\n",
		)
	}

	res := serveTranslation(t, o)

	assert.Equal(t, "text/event-stream", res.header.Get("Content-Type"))
	assert.True(t, strings.HasSuffix(res.body, "data: [DONE]\n\n"))

	evs := res.events(t)
	assert.Equal(t, 5, len(evs))

	for _, ev := range evs {
		assert.Equal(t, openAIObjectChunk, ev["object"])
		assert.Equal(t, "claude-sonnet-4-5", ev["model"])
	}

	assert.Equal(t, roleAssistant,
		evs[0]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["role"])
	assert.Equal(t, "He",
		evs[1]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["content"])
	assert.Equal(t, "llo",
		evs[2]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)["content"])
	assert.Equal(t, "stop",
		evs[3]["choices"].([]any)[0].(map[string]any)["finish_reason"])

	usage := evs[4]["usage"].(map[string]any)
	assert.Equal(t, float64(10), usage["prompt_tokens"])
	assert.Equal(t, float64(7), usage["completion_tokens"])

	upstream := res.reqCtx.LLMUpstreamResponse
	assert.Equal(t, "msg_abc", upstream.ResponseID)
	assert.Equal(t, "end_turn", upstream.FinishReason)
}

func TestTranslationOpenAIToAnthropicStreamToolCall(t *testing.T) {
	o := newOpenAIToAnthropic(`{"model":"claude-sonnet-4-5","stream":true,` +
		`"messages":[{"role":"user","content":"Hello"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		writeSSE(w,
			`data: {"type":"message_start","message":{"id":"msg_abc",`+
				`"model":"claude-sonnet-4-5","usage":{"input_tokens":10}}}`+"\n\n",
			`data: {"type":"content_block_start","index":0,"content_block":`+
				`{"type":"tool_use","id":"toolu_1","name":"get_weather"}}`+"\n\n",
			`data: {"type":"content_block_delta","index":0,"delta":`+
				`{"type":"input_json_delta","partial_json":"{\"city\":"}}`+"\n\n",
			`data: {"type":"content_block_delta","index":0,"delta":`+
				`{"type":"input_json_delta","partial_json":"\"Cairo\"}"}}`+"\n\n",
			`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},`+
				`"usage":{"output_tokens":7}}`+"\n\n",
			`data: {"type":"message_stop"}`+"\n\n",
		)
	}

	res := serveTranslation(t, o)

	evs := res.events(t)
	assert.Equal(t, 5, len(evs))

	start := evs[1]["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
	call := start["tool_calls"].([]any)[0].(map[string]any)
	assert.Equal(t, float64(0), call["index"])
	assert.Equal(t, "toolu_1", call["id"])
	assert.Equal(t, "get_weather", call["function"].(map[string]any)["name"])

	assert.Equal(t, `{"city":`, streamToolArguments(t, evs[2]))
	assert.Equal(t, `"Cairo"}`, streamToolArguments(t, evs[3]))

	assert.Equal(t, "tool_calls",
		evs[4]["choices"].([]any)[0].(map[string]any)["finish_reason"])
}

func streamToolArguments(t *testing.T, ev map[string]any) string {
	delta := ev["choices"].([]any)[0].(map[string]any)["delta"].(map[string]any)
	fn := delta["tool_calls"].([]any)[0].(map[string]any)["function"].(map[string]any)

	ret, ok := fn["arguments"].(string)
	assert.True(t, ok)

	return ret
}

func TestTranslationAnthropicToOpenAIRequest(t *testing.T) {
	body := `{"model":"gpt-4o","max_tokens":256,"system":"Never expose secrets.",` +
		`"stop_sequences":["END"],"top_p":0.9,"metadata":{"user_id":"u-1"},` +
		`"messages":[{"role":"user","content":[{"type":"text","text":"Hello"}]}]}`

	res := serveTranslation(t, newAnthropicToOpenAI(body))

	assert.True(t, res.isNext)
	assert.Equal(t, openAIChatPath, res.upstreamPath)
	assert.Equal(t, "", res.upstreamHeader.Get(anthropicVersionHeader))

	assert.Equal(t, "gpt-4o", res.upstream["model"])
	assert.Equal(t, float64(256), res.upstream["max_completion_tokens"])
	assert.Equal(t, []any{"END"}, res.upstream["stop"])
	assert.Equal(t, 0.9, res.upstream["top_p"])
	assert.Equal(t, "u-1", res.upstream["user"])

	msgs := res.upstream["messages"].([]any)
	assert.Equal(t, 2, len(msgs))
	assert.Equal(t, roleSystem, msgs[0].(map[string]any)["role"])
	assert.Equal(t, "Never expose secrets.", msgs[0].(map[string]any)["content"])
	assert.Equal(t, roleUser, msgs[1].(map[string]any)["role"])
	assert.Equal(t, "Hello", msgs[1].(map[string]any)["content"])
}

func TestTranslationAnthropicToOpenAITools(t *testing.T) {
	body := `{"model":"gpt-4o","max_tokens":256,"messages":[` +
		`{"role":"user","content":"Weather in Cairo?"},` +
		`{"role":"assistant","content":[{"type":"text","text":"I'll check."},` +
		`{"type":"tool_use","id":"toolu_1","name":"get_weather",` +
		`"input":{"city":"Cairo"}}]},` +
		`{"role":"user","content":[` +
		`{"type":"tool_result","tool_use_id":"toolu_1","content":"31 C"},` +
		`{"type":"text","text":"What about tomorrow?"}]}],` +
		`"tools":[{"name":"get_weather","description":"Get weather",` +
		`"input_schema":{"type":"object","properties":{"city":{"type":"string"}}}}],` +
		`"tool_choice":{"type":"tool","name":"get_weather",` +
		`"disable_parallel_tool_use":true}}`

	res := serveTranslation(t, newAnthropicToOpenAI(body))

	tools := res.upstream["tools"].([]any)
	tool := tools[0].(map[string]any)
	assert.Equal(t, functionToolKind, tool["type"])
	fn := tool["function"].(map[string]any)
	assert.Equal(t, "get_weather", fn["name"])
	assert.Equal(t, "object", fn["parameters"].(map[string]any)["type"])

	choice := res.upstream["tool_choice"].(map[string]any)
	assert.Equal(t, functionToolKind, choice["type"])
	assert.Equal(t, "get_weather", choice["function"].(map[string]any)["name"])
	assert.Equal(t, false, res.upstream["parallel_tool_calls"])

	msgs := res.upstream["messages"].([]any)
	assert.Equal(t, 4, len(msgs))

	assistant := msgs[1].(map[string]any)
	assert.Equal(t, roleAssistant, assistant["role"])
	assert.Equal(t, "I'll check.", assistant["content"])
	call := assistant["tool_calls"].([]any)[0].(map[string]any)
	assert.Equal(t, "toolu_1", call["id"])
	assert.Equal(t, `{"city":"Cairo"}`,
		call["function"].(map[string]any)["arguments"])

	result := msgs[2].(map[string]any)
	assert.Equal(t, "tool", result["role"])
	assert.Equal(t, "toolu_1", result["tool_call_id"])
	assert.Equal(t, "31 C", result["content"])

	assert.Equal(t, roleUser, msgs[3].(map[string]any)["role"])
	assert.Equal(t, "What about tomorrow?", msgs[3].(map[string]any)["content"])
}

func TestTranslationAnthropicToOpenAIResponse(t *testing.T) {
	o := newAnthropicToOpenAI(
		`{"model":"gpt-4o","max_tokens":64,"messages":[{"role":"user","content":"Hi"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"id":"chatcmpl_abc","object":"chat.completion","created":1,`+
			`"model":"gpt-4o-2024-11-20","choices":[{"index":0,"message":`+
			`{"role":"assistant","content":"Hello"},"finish_reason":"stop"}],`+
			`"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`)
	}

	res := serveTranslation(t, o)

	out := res.json(t)
	assert.Equal(t, "message", out["type"])
	assert.Equal(t, roleAssistant, out["role"])
	assert.Equal(t, "gpt-4o-2024-11-20", out["model"])
	assert.Equal(t, "end_turn", out["stop_reason"])
	assert.True(t, strings.HasPrefix(out["id"].(string), "msg_"))

	content := out["content"].([]any)
	assert.Equal(t, 1, len(content))
	assert.Equal(t, "Hello", content[0].(map[string]any)["text"])

	usage := out["usage"].(map[string]any)
	assert.Equal(t, float64(10), usage["input_tokens"])
	assert.Equal(t, float64(5), usage["output_tokens"])

	assert.Equal(t, "chatcmpl_abc", res.reqCtx.LLMUpstreamResponse.ResponseID)
}

func TestTranslationAnthropicToOpenAIStream(t *testing.T) {
	o := newAnthropicToOpenAI(`{"model":"gpt-4o","max_tokens":64,"stream":true,` +
		`"messages":[{"role":"user","content":"Hi"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		writeSSE(w,
			`data: {"id":"chatcmpl_abc","object":"chat.completion.chunk","model":"gpt-4o",`+
				`"choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`+"\n\n",
			`data: {"id":"chatcmpl_abc","object":"chat.completion.chunk","model":"gpt-4o",`+
				`"choices":[{"index":0,"delta":{"content":"He"}}]}`+"\n\n",
			`data: {"id":"chatcmpl_abc","object":"chat.completion.chunk","model":"gpt-4o",`+
				`"choices":[{"index":0,"delta":{"content":"llo"}}]}`+"\n\n",
			`data: {"id":"chatcmpl_abc","object":"chat.completion.chunk","model":"gpt-4o",`+
				`"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`+"\n\n",
			`data: {"id":"chatcmpl_abc","object":"chat.completion.chunk","model":"gpt-4o",`+
				`"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":7,`+
				`"total_tokens":17}}`+"\n\n",
			`data: [DONE]`+"\n\n",
		)
	}

	res := serveTranslation(t, o)

	assert.True(t, res.upstream["stream_options"].(map[string]any)["include_usage"].(bool))

	assert.Equal(t, "text/event-stream", res.header.Get("Content-Type"))

	evs := res.events(t)
	assert.Equal(t, 7, len(evs))

	assert.Equal(t, "message_start", evs[0]["type"])
	assert.Equal(t, "gpt-4o", evs[0]["message"].(map[string]any)["model"])

	assert.Equal(t, "content_block_start", evs[1]["type"])
	assert.Equal(t, "content_block_delta", evs[2]["type"])
	assert.Equal(t, "He", evs[2]["delta"].(map[string]any)["text"])
	assert.Equal(t, "llo", evs[3]["delta"].(map[string]any)["text"])
	assert.Equal(t, "content_block_stop", evs[4]["type"])

	assert.Equal(t, "message_delta", evs[5]["type"])
	assert.Equal(t, "end_turn", evs[5]["delta"].(map[string]any)["stop_reason"])
	assert.Equal(t, float64(7), evs[5]["usage"].(map[string]any)["output_tokens"])

	assert.Equal(t, "message_stop", evs[6]["type"])

	assert.Contains(t, res.body, "event: message_start")
	assert.Contains(t, res.body, "event: message_stop")
}

func TestTranslationAnthropicToOpenAIStreamToolCall(t *testing.T) {
	o := newAnthropicToOpenAI(`{"model":"gpt-4o","max_tokens":64,"stream":true,` +
		`"messages":[{"role":"user","content":"Hi"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		writeSSE(w,
			`data: {"id":"chatcmpl_abc","model":"gpt-4o","choices":[{"index":0,`+
				`"delta":{"role":"assistant","content":""}}]}`+"\n\n",
			`data: {"id":"chatcmpl_abc","model":"gpt-4o","choices":[{"index":0,`+
				`"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function",`+
				`"function":{"name":"get_weather","arguments":""}}]}}]}`+"\n\n",
			`data: {"id":"chatcmpl_abc","model":"gpt-4o","choices":[{"index":0,`+
				`"delta":{"tool_calls":[{"index":0,"function":`+
				`{"arguments":"{\"city\":"}}]}}]}`+"\n\n",
			`data: {"id":"chatcmpl_abc","model":"gpt-4o","choices":[{"index":0,`+
				`"delta":{"tool_calls":[{"index":0,"function":`+
				`{"arguments":"\"Cairo\"}"}}]}}]}`+"\n\n",
			`data: {"id":"chatcmpl_abc","model":"gpt-4o","choices":[{"index":0,`+
				`"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n",
			`data: [DONE]`+"\n\n",
		)
	}

	res := serveTranslation(t, o)

	evs := res.events(t)
	assert.Equal(t, 6, len(evs))

	assert.Equal(t, "message_start", evs[0]["type"])

	assert.Equal(t, "content_block_start", evs[1]["type"])
	block := evs[1]["content_block"].(map[string]any)
	assert.Equal(t, "tool_use", block["type"])
	assert.Equal(t, "call_1", block["id"])
	assert.Equal(t, "get_weather", block["name"])

	assert.Equal(t, "content_block_delta", evs[2]["type"])
	assert.Equal(t, `{"city":"Cairo"}`,
		evs[2]["delta"].(map[string]any)["partial_json"])

	assert.Equal(t, "content_block_stop", evs[3]["type"])
	assert.Equal(t, "message_delta", evs[4]["type"])
	assert.Equal(t, "tool_use", evs[4]["delta"].(map[string]any)["stop_reason"])
	assert.Equal(t, "message_stop", evs[5]["type"])
}

func TestTranslationReasoning(t *testing.T) {
	{
		o := newOpenAIToAnthropic(
			`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hi"}]}`)
		o.reasoning = &corev1.Service_Spec_Config_LLM_Reasoning{
			Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{
				Level: corev1.Service_Spec_Config_LLM_Reasoning_MEDIUM,
			},
		}

		res := serveTranslation(t, o)

		thinking := res.upstream["thinking"].(map[string]any)
		assert.Equal(t, "enabled", thinking["type"])
		assert.Equal(t, float64(mediumReasoningBudget), thinking["budget_tokens"])
		assert.Equal(t, uint64(mediumReasoningBudget),
			res.reqCtx.LLMReasoning.TokenBudget)

		_, ok := res.upstream["reasoning_effort"]
		assert.False(t, ok)

		assert.Equal(t, float64(defaultTransMaxOutputTokens+mediumReasoningBudget),
			res.upstream["max_tokens"])
	}

	{
		o := newAnthropicToOpenAI(`{"model":"gpt-5","max_tokens":64,` +
			`"messages":[{"role":"user","content":"Hi"}]}`)
		o.reasoning = &corev1.Service_Spec_Config_LLM_Reasoning{
			Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{
				Level: corev1.Service_Spec_Config_LLM_Reasoning_HIGH,
			},
		}

		res := serveTranslation(t, o)

		assert.Equal(t, reasoningEffortHigh, res.upstream["reasoning_effort"])
		assert.Equal(t, reasoningEffortHigh, res.reqCtx.LLMReasoning.Effort)
	}

	{
		o := newOpenAIToAnthropic(`{"model":"claude-sonnet-4-5","reasoning_effort":"low",` +
			`"messages":[{"role":"user","content":"Hi"}]}`)

		res := serveTranslation(t, o)

		thinking := res.upstream["thinking"].(map[string]any)
		assert.Equal(t, "enabled", thinking["type"])
		assert.Equal(t, float64(lowReasoningBudget), thinking["budget_tokens"])
	}

	{
		o := newAnthropicToOpenAI(`{"model":"gpt-5","max_tokens":64,` +
			`"thinking":{"type":"disabled"},` +
			`"messages":[{"role":"user","content":"Hi"}]}`)

		res := serveTranslation(t, o)

		assert.Equal(t, reasoningEffortNone, res.upstream["reasoning_effort"])
	}

	{
		o := newAnthropicToOpenAI(`{"model":"gpt-5","max_tokens":64,` +
			`"thinking":{"type":"enabled","budget_tokens":4096},` +
			`"messages":[{"role":"user","content":"Hi"}]}`)

		res := serveTranslation(t, o)

		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}
}

func TestTranslationUnsupported(t *testing.T) {
	for _, body := range []string{
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hi"}],"n":2}`,
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hi"}],` +
			`"logprobs":true}`,
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hi"}],` +
			`"frequency_penalty":0.5}`,
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hi"}],` +
			`"seed":42}`,
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hi"}],` +
			`"response_format":{"type":"json_object"}}`,
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hi"}],` +
			`"tools":[{"type":"web_search"}]}`,
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hi"},` +
			`{"role":"system","content":"Late"}]}`,
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":[` +
			`{"type":"input_audio","input_audio":{"data":"AAA"}}]}]}`,
		`{"model":"claude-sonnet-4-5","messages":[{"role":"assistant","tool_calls":[` +
			`{"id":"c1","type":"function","function":{"name":"a","arguments":"not json"}}]},` +
			`{"role":"user","content":"Hi"}]}`,
		`{"model":"claude-sonnet-4-5","temperature":1.5,` +
			`"messages":[{"role":"user","content":"Hi"}]}`,
	} {
		res := serveTranslation(t, newOpenAIToAnthropic(body))

		assert.False(t, res.isNext, body)
		assert.Equal(t, http.StatusBadRequest, res.code, body)
		assert.Contains(t, res.body, ErrCodeTranslation, body)
	}

	for _, body := range []string{
		`{"model":"gpt-4o","max_tokens":64,"top_k":10,` +
			`"messages":[{"role":"user","content":"Hi"}]}`,
		`{"model":"gpt-4o","max_tokens":64,"messages":[{"role":"user","content":[` +
			`{"type":"thinking","thinking":"hmm","signature":"abc"}]}]}`,
		`{"model":"gpt-4o","max_tokens":64,"messages":[` +
			`{"role":"user","content":"Hi"},` +
			`{"role":"assistant","content":"Prefill"}]}`,
		`{"model":"gpt-4o","max_tokens":64,"messages":[{"role":"user","content":[` +
			`{"type":"document","source":{"type":"base64","data":"AAA"}}]}]}`,
		`{"model":"gpt-4o","max_tokens":64,"messages":[{"role":"user","content":"Hi"}],` +
			`"tools":[{"type":"web_search_20250305","name":"web_search"}]}`,
	} {
		res := serveTranslation(t, newAnthropicToOpenAI(body))

		assert.False(t, res.isNext, body)
		assert.Equal(t, http.StatusBadRequest, res.code, body)
	}
}

func TestTranslationUnsupportedRoute(t *testing.T) {
	o := &transOpts{
		protocol:         corev1.Service_Spec_Config_LLM_OPENAI,
		upstreamProtocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
		path:             "/v1/embeddings",
		body:             `{"model":"text-embedding-3-small","input":"Hello"}`,
	}

	res := serveTranslation(t, o)

	assert.False(t, res.isNext)
	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, ErrCodeTranslation)
}

func TestTranslationIgnoredFields(t *testing.T) {
	{
		body := `{"model":"claude-sonnet-4-5","store":false,"metadata":{"k":"v"},` +
			`"messages":[{"role":"user","content":[{"type":"image_url",` +
			`"image_url":{"url":"https://example.com/a.png","detail":"high"}}]}]}`

		res := serveTranslation(t, newOpenAIToAnthropic(body))

		assert.True(t, res.isNext)
		_, ok := res.upstream["store"]
		assert.False(t, ok)
	}

	{
		body := `{"model":"gpt-4o","max_tokens":64,"system":[{"type":"text",` +
			`"text":"Be terse","cache_control":{"type":"ephemeral"}}],` +
			`"messages":[{"role":"user","content":[{"type":"text","text":"Hi",` +
			`"cache_control":{"type":"ephemeral"}}]}],` +
			`"tools":[{"name":"a","input_schema":{"type":"object"},` +
			`"cache_control":{"type":"ephemeral"}}]}`

		res := serveTranslation(t, newAnthropicToOpenAI(body))

		assert.True(t, res.isNext)
		msgs := res.upstream["messages"].([]any)
		assert.Equal(t, "Be terse", msgs[0].(map[string]any)["content"])
		assert.Equal(t, "Hi", msgs[1].(map[string]any)["content"])
	}
}

func TestTranslationUpstreamError(t *testing.T) {
	o := newOpenAIToAnthropic(
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hi"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"type":"error","error":{"type":"not_found_error",` +
			`"message":"model: claude-nope"}}`))
	}

	res := serveTranslation(t, o)

	assert.Equal(t, http.StatusNotFound, res.code)

	out := res.json(t)
	errObj := out["error"].(map[string]any)
	assert.Equal(t, ErrTypeNotFound, errObj["type"])
	assert.Equal(t, ErrCodeTranslation, errObj["code"])
	assert.Contains(t, errObj["message"], "claude-nope")
}

func TestTranslationUpstreamInvalidResponse(t *testing.T) {
	o := newOpenAIToAnthropic(
		`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hi"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"id":"msg_abc","type":"message","content":[],`+
			`"stop_reason":"pause_turn"}`)
	}

	res := serveTranslation(t, o)

	assert.Equal(t, http.StatusBadGateway, res.code)
	assert.Contains(t, res.body, ErrCodeTranslation)
	assert.Equal(t, "pause_turn", res.reqCtx.LLMUpstreamResponse.FinishReason)
}

func TestTranslationCredentialHeaders(t *testing.T) {
	o := newAnthropicToOpenAI(
		`{"model":"gpt-4o","max_tokens":64,"messages":[{"role":"user","content":"Hi"}]}`)
	o.header = map[string]string{
		anthropicVersionHeader: "2023-06-01",
		"Anthropic-Beta":       "output-128k-2025-02-19",
	}

	res := serveTranslation(t, o)

	assert.True(t, res.isNext)
	assert.Equal(t, "", res.upstreamHeader.Get(anthropicVersionHeader))
	assert.Equal(t, "", res.upstreamHeader.Get("Anthropic-Beta"))
	assert.Equal(t, "identity", res.upstreamHeader.Get("Accept-Encoding"))
}

func TestTranslationRequestContextPreserved(t *testing.T) {
	body := `{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"Hello"}]}`

	res := serveTranslation(t, newOpenAIToAnthropic(body))

	assert.Equal(t, body, string(res.reqCtx.Body))
	assert.Equal(t, corev1.Service_Spec_Config_LLM_OPENAI, res.reqCtx.LLM.GetProtocol())
	assert.Equal(t, corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
		res.reqCtx.LLM.GetRoute())
	assert.Equal(t, uint64(0), res.reqCtx.LLM.GetMaxOutputTokens())
}

func newTransOpts(protocol,
	upstreamProtocol corev1.Service_Spec_Config_LLM_Protocol, body string) *transOpts {
	return &transOpts{
		protocol:         protocol,
		upstreamProtocol: upstreamProtocol,
		body:             body,
	}
}

const (
	transOpenAIBody = `{"model":"corp-model","messages":[` +
		`{"role":"developer","content":"You are concise."},` +
		`{"role":"user","content":"Weather in Cairo?"}],` +
		`"max_completion_tokens":500,"stop":["END"],"temperature":0.5,` +
		`"tools":[{"type":"function","function":{"name":"get_weather",` +
		`"description":"Get current weather","parameters":{"type":"object",` +
		`"properties":{"city":{"type":"string"}},"required":["city"]}}}],` +
		`"tool_choice":"auto"}`

	transAnthropicBody = `{"model":"corp-model","system":"You are concise.",` +
		`"max_tokens":500,"stop_sequences":["END"],"temperature":0.5,` +
		`"messages":[{"role":"user","content":"Weather in Cairo?"}],` +
		`"tools":[{"name":"get_weather","description":"Get current weather",` +
		`"input_schema":{"type":"object","properties":{"city":{"type":"string"}},` +
		`"required":["city"]}}],"tool_choice":{"type":"auto"}}`

	transGeminiBody = `{"systemInstruction":{"parts":[{"text":"You are concise."}]},` +
		`"contents":[{"role":"user","parts":[{"text":"Weather in Cairo?"}]}],` +
		`"generationConfig":{"maxOutputTokens":500,"stopSequences":["END"],` +
		`"temperature":0.5},` +
		`"tools":[{"functionDeclarations":[{"name":"get_weather",` +
		`"description":"Get current weather","parameters":{"type":"object",` +
		`"properties":{"city":{"type":"string"}},"required":["city"]}}]}],` +
		`"toolConfig":{"functionCallingConfig":{"mode":"AUTO"}}}`

	transBedrockBody = `{"system":[{"text":"You are concise."}],` +
		`"messages":[{"role":"user","content":[{"text":"Weather in Cairo?"}]}],` +
		`"inferenceConfig":{"maxTokens":500,"stopSequences":["END"],` +
		`"temperature":0.5},` +
		`"toolConfig":{"tools":[{"toolSpec":{"name":"get_weather",` +
		`"description":"Get current weather","inputSchema":{"json":{"type":"object",` +
		`"properties":{"city":{"type":"string"}},"required":["city"]}}}}],` +
		`"toolChoice":{"auto":{}}}}`
)

func transSourceBody(protocol corev1.Service_Spec_Config_LLM_Protocol) string {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return transAnthropicBody
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return transGeminiBody
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return transBedrockBody
	default:
		return transOpenAIBody
	}
}

var transProtocols = []corev1.Service_Spec_Config_LLM_Protocol{
	corev1.Service_Spec_Config_LLM_OPENAI,
	corev1.Service_Spec_Config_LLM_ANTHROPIC,
	corev1.Service_Spec_Config_LLM_GEMINI,
	corev1.Service_Spec_Config_LLM_BEDROCK,
}

func transUpstreamSystem(t *testing.T,
	protocol corev1.Service_Spec_Config_LLM_Protocol, upstream map[string]any) string {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		ret, ok := upstream["system"].(string)
		assert.True(t, ok)
		return ret
	case corev1.Service_Spec_Config_LLM_GEMINI:
		obj := upstream["systemInstruction"].(map[string]any)
		return obj["parts"].([]any)[0].(map[string]any)["text"].(string)
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return upstream["system"].([]any)[0].(map[string]any)["text"].(string)
	default:
		msgs := upstream["messages"].([]any)
		first := msgs[0].(map[string]any)
		assert.Equal(t, roleSystem, first["role"])
		return first["content"].(string)
	}
}

func transUpstreamMaxTokens(t *testing.T,
	protocol corev1.Service_Spec_Config_LLM_Protocol, upstream map[string]any) float64 {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return upstream["max_tokens"].(float64)
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return upstream["generationConfig"].(map[string]any)["maxOutputTokens"].(float64)
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return upstream["inferenceConfig"].(map[string]any)["maxTokens"].(float64)
	default:
		return upstream["max_completion_tokens"].(float64)
	}
}

func transUpstreamToolName(t *testing.T,
	protocol corev1.Service_Spec_Config_LLM_Protocol, upstream map[string]any) string {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return upstream["tools"].([]any)[0].(map[string]any)["name"].(string)
	case corev1.Service_Spec_Config_LLM_GEMINI:
		group := upstream["tools"].([]any)[0].(map[string]any)
		decl := group["functionDeclarations"].([]any)[0].(map[string]any)
		return decl["name"].(string)
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		cfg := upstream["toolConfig"].(map[string]any)
		spec := cfg["tools"].([]any)[0].(map[string]any)["toolSpec"].(map[string]any)
		return spec["name"].(string)
	default:
		fn := upstream["tools"].([]any)[0].(map[string]any)["function"].(map[string]any)
		return fn["name"].(string)
	}
}

func TestTranslationMatrixRequest(t *testing.T) {
	for _, from := range transProtocols {
		for _, to := range transProtocols {
			if from == to {
				continue
			}

			label := from.String() + "->" + to.String()

			o := newTransOpts(from, to, transSourceBody(from))
			o.upstream = func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, transUpstreamResponse(to))
			}

			res := serveTranslation(t, o)

			assert.True(t, res.isNext, label)
			assert.Equal(t, http.StatusOK, res.code, label+" "+res.body)

			expectedPath, _, _ := httputils.GetLLMRoutePath(to,
				getTransRoute(to, corev1.Service_Spec_Config_LLM_GENERATE),
				transTestModel, false)
			assert.Equal(t, expectedPath, res.upstreamPath, label)

			assert.Equal(t, "You are concise.",
				transUpstreamSystem(t, to, res.upstream), label)
			assert.Equal(t, float64(500),
				transUpstreamMaxTokens(t, to, res.upstream), label)
			assert.Equal(t, "get_weather",
				transUpstreamToolName(t, to, res.upstream), label)

			assert.Equal(t, to, res.reqCtx.LLMTranslation.UpstreamProtocol, label)
			assert.Equal(t, getTransRoute(to, corev1.Service_Spec_Config_LLM_GENERATE),
				res.reqCtx.LLMTranslation.UpstreamRoute, label)
		}
	}
}

func transUpstreamResponse(protocol corev1.Service_Spec_Config_LLM_Protocol) string {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return `{"id":"msg_abc","type":"message","role":"assistant","model":"m-1",` +
			`"content":[{"type":"text","text":"It is 31 C."}],` +
			`"stop_reason":"end_turn",` +
			`"usage":{"input_tokens":20,"output_tokens":10}}`
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return `{"candidates":[{"content":{"role":"model","parts":[` +
			`{"text":"It is 31 C."}]},"finishReason":"STOP"}],` +
			`"modelVersion":"m-1","responseId":"resp-abc",` +
			`"usageMetadata":{"promptTokenCount":20,"candidatesTokenCount":10,` +
			`"totalTokenCount":30}}`
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return `{"output":{"message":{"role":"assistant","content":[` +
			`{"text":"It is 31 C."}]}},"stopReason":"end_turn",` +
			`"usage":{"inputTokens":20,"outputTokens":10,"totalTokens":30}}`
	default:
		return `{"id":"chatcmpl_abc","object":"chat.completion","created":1,` +
			`"model":"m-1","choices":[{"index":0,"message":{"role":"assistant",` +
			`"content":"It is 31 C."},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30}}`
	}
}

func transDownstreamText(t *testing.T,
	protocol corev1.Service_Spec_Config_LLM_Protocol, out map[string]any) string {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return out["content"].([]any)[0].(map[string]any)["text"].(string)
	case corev1.Service_Spec_Config_LLM_GEMINI:
		candidate := out["candidates"].([]any)[0].(map[string]any)
		content := candidate["content"].(map[string]any)
		return content["parts"].([]any)[0].(map[string]any)["text"].(string)
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		msg := out["output"].(map[string]any)["message"].(map[string]any)
		return msg["content"].([]any)[0].(map[string]any)["text"].(string)
	default:
		choice := out["choices"].([]any)[0].(map[string]any)
		return choice["message"].(map[string]any)["content"].(string)
	}
}

func transDownstreamUsage(t *testing.T,
	protocol corev1.Service_Spec_Config_LLM_Protocol, out map[string]any) (float64, float64) {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		usage := out["usage"].(map[string]any)
		return usage["input_tokens"].(float64), usage["output_tokens"].(float64)
	case corev1.Service_Spec_Config_LLM_GEMINI:
		usage := out["usageMetadata"].(map[string]any)
		return usage["promptTokenCount"].(float64), usage["candidatesTokenCount"].(float64)
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		usage := out["usage"].(map[string]any)
		return usage["inputTokens"].(float64), usage["outputTokens"].(float64)
	default:
		usage := out["usage"].(map[string]any)
		return usage["prompt_tokens"].(float64), usage["completion_tokens"].(float64)
	}
}

func TestTranslationMatrixResponse(t *testing.T) {
	for _, from := range transProtocols {
		for _, to := range transProtocols {
			if from == to {
				continue
			}

			label := from.String() + "->" + to.String()

			o := newTransOpts(from, to, transSourceBody(from))
			o.upstream = func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, transUpstreamResponse(to))
			}

			res := serveTranslation(t, o)

			assert.Equal(t, http.StatusOK, res.code, label+" "+res.body)

			out := res.json(t)
			assert.Equal(t, "It is 31 C.", transDownstreamText(t, from, out), label)

			input, output := transDownstreamUsage(t, from, out)
			assert.Equal(t, float64(20), input, label)
			assert.Equal(t, float64(10), output, label)

			assert.Equal(t, uint64(20),
				res.reqCtx.LLMUpstreamResponse.Usage.InputTokens, label)
		}
	}
}

func transUpstreamStream(protocol corev1.Service_Spec_Config_LLM_Protocol) []string {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return []string{
			`data: {"type":"message_start","message":{"id":"msg_abc","type":"message",` +
				`"role":"assistant","model":"m-1",` +
				`"usage":{"input_tokens":20,"output_tokens":0}}}` + "\n\n",
			`data: {"type":"content_block_start","index":0,` +
				`"content_block":{"type":"text","text":""}}` + "\n\n",
			`data: {"type":"content_block_delta","index":0,` +
				`"delta":{"type":"text_delta","text":"It is "}}` + "\n\n",
			`data: {"type":"content_block_delta","index":0,` +
				`"delta":{"type":"text_delta","text":"31 C."}}` + "\n\n",
			`data: {"type":"content_block_stop","index":0}` + "\n\n",
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},` +
				`"usage":{"output_tokens":10}}` + "\n\n",
			`data: {"type":"message_stop"}` + "\n\n",
		}
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return []string{
			`data: {"candidates":[{"content":{"role":"model",` +
				`"parts":[{"text":"It is "}]}}],"modelVersion":"m-1",` +
				`"responseId":"resp-abc"}` + "\n\n",
			`data: {"candidates":[{"content":{"role":"model",` +
				`"parts":[{"text":"31 C."}]},"finishReason":"STOP"}],` +
				`"modelVersion":"m-1","responseId":"resp-abc",` +
				`"usageMetadata":{"promptTokenCount":20,"candidatesTokenCount":10,` +
				`"totalTokenCount":30}}` + "\n\n",
		}
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return []string{
			transBedrockEvent("messageStart", `{"role":"assistant"}`),
			transBedrockEvent("contentBlockStart",
				`{"contentBlockIndex":0,"start":{}}`),
			transBedrockEvent("contentBlockDelta",
				`{"contentBlockIndex":0,"delta":{"text":"It is "}}`),
			transBedrockEvent("contentBlockDelta",
				`{"contentBlockIndex":0,"delta":{"text":"31 C."}}`),
			transBedrockEvent("contentBlockStop", `{"contentBlockIndex":0}`),
			transBedrockEvent("messageStop", `{"stopReason":"end_turn"}`),
			transBedrockEvent("metadata",
				`{"usage":{"inputTokens":20,"outputTokens":10,"totalTokens":30}}`),
		}
	default:
		return []string{
			`data: {"id":"chatcmpl_abc","object":"chat.completion.chunk","model":"m-1",` +
				`"choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}` + "\n\n",
			`data: {"id":"chatcmpl_abc","object":"chat.completion.chunk","model":"m-1",` +
				`"choices":[{"index":0,"delta":{"content":"It is "}}]}` + "\n\n",
			`data: {"id":"chatcmpl_abc","object":"chat.completion.chunk","model":"m-1",` +
				`"choices":[{"index":0,"delta":{"content":"31 C."}}]}` + "\n\n",
			`data: {"id":"chatcmpl_abc","object":"chat.completion.chunk","model":"m-1",` +
				`"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n",
			`data: {"id":"chatcmpl_abc","object":"chat.completion.chunk","model":"m-1",` +
				`"choices":[],"usage":{"prompt_tokens":20,"completion_tokens":10,` +
				`"total_tokens":30}}` + "\n\n",
			"data: [DONE]\n\n",
		}
	}
}

func transBedrockEvent(eventType, payload string) string {
	return string(httputils.EncodeLLMEventStreamEvent(eventType, []byte(payload)))
}

func transStreamMediaType(protocol corev1.Service_Spec_Config_LLM_Protocol) string {
	if protocol == corev1.Service_Spec_Config_LLM_BEDROCK {
		return transEventStreamMediaType
	}
	return transSSEMediaType
}

func (r *transResult) streamEvents(t *testing.T,
	protocol corev1.Service_Spec_Config_LLM_Protocol) []map[string]any {

	if protocol != corev1.Service_Spec_Config_LLM_BEDROCK {
		return r.events(t)
	}

	var ret []map[string]any

	buf := []byte(r.body)
	for len(buf) > 0 {
		eventType, payload, n := httputils.NextLLMEventStreamEvent(buf)
		assert.True(t, n > 0, r.body)
		buf = buf[n:]

		cur := make(map[string]any)
		assert.Nil(t, json.Unmarshal(payload, &cur), string(payload))
		cur["__event"] = eventType

		ret = append(ret, cur)
	}

	return ret
}

func transStreamText(t *testing.T,
	protocol corev1.Service_Spec_Config_LLM_Protocol, evs []map[string]any) string {

	var ret string

	for _, ev := range evs {
		switch protocol {
		case corev1.Service_Spec_Config_LLM_ANTHROPIC:
			if ev["type"] != "content_block_delta" {
				continue
			}
			delta := ev["delta"].(map[string]any)
			if text, ok := delta["text"].(string); ok {
				ret = ret + text
			}
		case corev1.Service_Spec_Config_LLM_GEMINI:
			candidates, ok := ev["candidates"].([]any)
			if !ok || len(candidates) == 0 {
				continue
			}
			content := candidates[0].(map[string]any)["content"].(map[string]any)
			for _, part := range content["parts"].([]any) {
				if text, ok := part.(map[string]any)["text"].(string); ok {
					ret = ret + text
				}
			}
		case corev1.Service_Spec_Config_LLM_BEDROCK:
			if ev["__event"] != "contentBlockDelta" {
				continue
			}
			delta := ev["delta"].(map[string]any)
			if text, ok := delta["text"].(string); ok {
				ret = ret + text
			}
		default:
			choices, ok := ev["choices"].([]any)
			if !ok || len(choices) == 0 {
				continue
			}
			delta := choices[0].(map[string]any)["delta"].(map[string]any)
			if text, ok := delta["content"].(string); ok {
				ret = ret + text
			}
		}
	}

	return ret
}

func TestTranslationMatrixStream(t *testing.T) {
	for _, from := range transProtocols {
		for _, to := range transProtocols {
			if from == to {
				continue
			}

			label := from.String() + "->" + to.String()

			o := newTransOpts(from, to, transStreamBody(from))
			o.isStream = true
			o.upstream = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", transStreamMediaType(to))
				for _, event := range transUpstreamStream(to) {
					w.Write([]byte(event))
				}
			}

			res := serveTranslation(t, o)

			assert.Equal(t, http.StatusOK, res.code, label+" "+res.body)
			assert.Equal(t, transStreamMediaType(from),
				res.header.Get("Content-Type"), label)

			expectedPath, _, _ := httputils.GetLLMRoutePath(to,
				getTransRoute(to, corev1.Service_Spec_Config_LLM_GENERATE),
				transTestModel, true)
			assert.Equal(t, expectedPath, res.upstreamPath, label)

			evs := res.streamEvents(t, from)
			assert.Equal(t, "It is 31 C.", transStreamText(t, from, evs), label)

			assert.Equal(t, uint64(10),
				res.reqCtx.LLMUpstreamResponse.Usage.OutputTokens, label)
		}
	}
}

func transStreamBody(protocol corev1.Service_Spec_Config_LLM_Protocol) string {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return `{"model":"corp-model","max_tokens":500,"stream":true,` +
			`"messages":[{"role":"user","content":"Hi"}]}`
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return `{"contents":[{"role":"user","parts":[{"text":"Hi"}]}]}`
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return `{"messages":[{"role":"user","content":[{"text":"Hi"}]}]}`
	default:
		return `{"model":"corp-model","stream":true,` +
			`"stream_options":{"include_usage":true},` +
			`"messages":[{"role":"user","content":"Hi"}]}`
	}
}

func transToolHistoryBody(protocol corev1.Service_Spec_Config_LLM_Protocol) string {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return `{"model":"corp-model","max_tokens":500,"messages":[` +
			`{"role":"user","content":"Weather in Cairo?"},` +
			`{"role":"assistant","content":[{"type":"tool_use","id":"call_123",` +
			`"name":"get_weather","input":{"city":"Cairo"}}]},` +
			`{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_123",` +
			`"content":"31 C"}]}],` +
			`"tools":[{"name":"get_weather","input_schema":{"type":"object"}}]}`
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return `{"contents":[` +
			`{"role":"user","parts":[{"text":"Weather in Cairo?"}]},` +
			`{"role":"model","parts":[{"functionCall":{"id":"call_123",` +
			`"name":"get_weather","args":{"city":"Cairo"}}}]},` +
			`{"role":"user","parts":[{"functionResponse":{"id":"call_123",` +
			`"name":"get_weather","response":{"result":"31 C"}}}]}],` +
			`"tools":[{"functionDeclarations":[{"name":"get_weather",` +
			`"parameters":{"type":"object"}}]}]}`
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return `{"messages":[` +
			`{"role":"user","content":[{"text":"Weather in Cairo?"}]},` +
			`{"role":"assistant","content":[{"toolUse":{"toolUseId":"call_123",` +
			`"name":"get_weather","input":{"city":"Cairo"}}}]},` +
			`{"role":"user","content":[{"toolResult":{"toolUseId":"call_123",` +
			`"content":[{"text":"31 C"}],"status":"success"}}]}],` +
			`"toolConfig":{"tools":[{"toolSpec":{"name":"get_weather",` +
			`"inputSchema":{"json":{"type":"object"}}}}]}}`
	default:
		return `{"model":"corp-model","messages":[` +
			`{"role":"user","content":"Weather in Cairo?"},` +
			`{"role":"assistant","tool_calls":[{"id":"call_123","type":"function",` +
			`"function":{"name":"get_weather","arguments":"{\"city\":\"Cairo\"}"}}]},` +
			`{"role":"tool","tool_call_id":"call_123","content":"31 C"}],` +
			`"tools":[{"type":"function","function":{"name":"get_weather",` +
			`"parameters":{"type":"object"}}}]}`
	}
}

type transToolTurn struct {
	callID string
	name   string
	city   string

	resultID   string
	resultText string
}

func transUpstreamToolTurn(t *testing.T,
	protocol corev1.Service_Spec_Config_LLM_Protocol,
	upstream map[string]any) *transToolTurn {

	ret := &transToolTurn{}

	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		msgs := upstream["messages"].([]any)
		call := msgs[1].(map[string]any)["content"].([]any)[0].(map[string]any)
		ret.callID = call["id"].(string)
		ret.name = call["name"].(string)
		ret.city = call["input"].(map[string]any)["city"].(string)

		result := msgs[2].(map[string]any)["content"].([]any)[0].(map[string]any)
		ret.resultID = result["tool_use_id"].(string)
		ret.resultText = result["content"].(string)
	case corev1.Service_Spec_Config_LLM_GEMINI:
		contents := upstream["contents"].([]any)
		call := contents[1].(map[string]any)["parts"].([]any)[0].(map[string]any)
		fn := call["functionCall"].(map[string]any)
		ret.callID, _ = fn["id"].(string)
		ret.name = fn["name"].(string)
		ret.city = fn["args"].(map[string]any)["city"].(string)

		result := contents[2].(map[string]any)["parts"].([]any)[0].(map[string]any)
		resp := result["functionResponse"].(map[string]any)
		ret.resultID, _ = resp["id"].(string)
		ret.resultText = resp["response"].(map[string]any)["result"].(string)
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		msgs := upstream["messages"].([]any)
		call := msgs[1].(map[string]any)["content"].([]any)[0].(map[string]any)
		use := call["toolUse"].(map[string]any)
		ret.callID = use["toolUseId"].(string)
		ret.name = use["name"].(string)
		ret.city = use["input"].(map[string]any)["city"].(string)

		result := msgs[2].(map[string]any)["content"].([]any)[0].(map[string]any)
		res := result["toolResult"].(map[string]any)
		ret.resultID = res["toolUseId"].(string)
		content := res["content"].([]any)[0].(map[string]any)
		if text, ok := content["text"].(string); ok {
			ret.resultText = text
		} else {
			ret.resultText = content["json"].(map[string]any)["result"].(string)
		}
	default:
		msgs := upstream["messages"].([]any)
		call := msgs[1].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
		ret.callID = call["id"].(string)
		fn := call["function"].(map[string]any)
		ret.name = fn["name"].(string)

		args := make(map[string]any)
		assert.Nil(t, json.Unmarshal([]byte(fn["arguments"].(string)), &args))
		ret.city = args["city"].(string)

		result := msgs[2].(map[string]any)
		ret.resultID = result["tool_call_id"].(string)
		ret.resultText = result["content"].(string)
	}

	return ret
}

func TestTranslationMatrixToolHistory(t *testing.T) {
	for _, from := range transProtocols {
		for _, to := range transProtocols {
			if from == to {
				continue
			}

			label := from.String() + "->" + to.String()

			o := newTransOpts(from, to, transToolHistoryBody(from))
			o.upstream = func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, transUpstreamResponse(to))
			}

			res := serveTranslation(t, o)

			assert.Equal(t, http.StatusOK, res.code, label+" "+res.body)

			turn := transUpstreamToolTurn(t, to, res.upstream)
			assert.Equal(t, "get_weather", turn.name, label)
			assert.Equal(t, "Cairo", turn.city, label)
			assert.Equal(t, "31 C", turn.resultText, label)
			assert.Equal(t, turn.callID, turn.resultID, label)

			if to != corev1.Service_Spec_Config_LLM_GEMINI {
				assert.Equal(t, "call_123", turn.callID, label)
			}
		}
	}
}

func transUpstreamToolResponse(protocol corev1.Service_Spec_Config_LLM_Protocol) string {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return `{"id":"msg_abc","type":"message","role":"assistant","model":"m-1",` +
			`"content":[{"type":"tool_use","id":"tool_1","name":"get_weather",` +
			`"input":{"city":"Cairo"}}],"stop_reason":"tool_use",` +
			`"usage":{"input_tokens":20,"output_tokens":10}}`
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return `{"candidates":[{"content":{"role":"model","parts":[` +
			`{"functionCall":{"id":"tool_1","name":"get_weather",` +
			`"args":{"city":"Cairo"}}}]},"finishReason":"STOP"}],` +
			`"modelVersion":"m-1","responseId":"resp-abc",` +
			`"usageMetadata":{"promptTokenCount":20,"candidatesTokenCount":10}}`
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return `{"output":{"message":{"role":"assistant","content":[` +
			`{"toolUse":{"toolUseId":"tool_1","name":"get_weather",` +
			`"input":{"city":"Cairo"}}}]}},"stopReason":"tool_use",` +
			`"usage":{"inputTokens":20,"outputTokens":10,"totalTokens":30}}`
	default:
		return `{"id":"chatcmpl_abc","object":"chat.completion","created":1,` +
			`"model":"m-1","choices":[{"index":0,"message":{"role":"assistant",` +
			`"content":null,"tool_calls":[{"id":"tool_1","type":"function",` +
			`"function":{"name":"get_weather","arguments":"{\"city\":\"Cairo\"}"}}]},` +
			`"finish_reason":"tool_calls"}],` +
			`"usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30}}`
	}
}

func transDownstreamToolCall(t *testing.T,
	protocol corev1.Service_Spec_Config_LLM_Protocol,
	out map[string]any) (string, string, string) {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		assert.Equal(t, "tool_use", out["stop_reason"])
		block := out["content"].([]any)[0].(map[string]any)
		return block["id"].(string), block["name"].(string),
			block["input"].(map[string]any)["city"].(string)
	case corev1.Service_Spec_Config_LLM_GEMINI:
		candidate := out["candidates"].([]any)[0].(map[string]any)
		content := candidate["content"].(map[string]any)
		fn := content["parts"].([]any)[0].(map[string]any)["functionCall"].(map[string]any)
		id, _ := fn["id"].(string)
		return id, fn["name"].(string), fn["args"].(map[string]any)["city"].(string)
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		assert.Equal(t, "tool_use", out["stopReason"])
		msg := out["output"].(map[string]any)["message"].(map[string]any)
		use := msg["content"].([]any)[0].(map[string]any)["toolUse"].(map[string]any)
		return use["toolUseId"].(string), use["name"].(string),
			use["input"].(map[string]any)["city"].(string)
	default:
		choice := out["choices"].([]any)[0].(map[string]any)
		assert.Equal(t, "tool_calls", choice["finish_reason"])
		call := choice["message"].(map[string]any)["tool_calls"].([]any)[0].(map[string]any)
		fn := call["function"].(map[string]any)

		args := make(map[string]any)
		assert.Nil(t, json.Unmarshal([]byte(fn["arguments"].(string)), &args))

		return call["id"].(string), fn["name"].(string), args["city"].(string)
	}
}

func TestTranslationMatrixToolResponse(t *testing.T) {
	for _, from := range transProtocols {
		for _, to := range transProtocols {
			if from == to {
				continue
			}

			label := from.String() + "->" + to.String()

			o := newTransOpts(from, to, transSourceBody(from))
			o.upstream = func(w http.ResponseWriter, r *http.Request) {
				writeJSON(w, transUpstreamToolResponse(to))
			}

			res := serveTranslation(t, o)

			assert.Equal(t, http.StatusOK, res.code, label+" "+res.body)

			id, name, city := transDownstreamToolCall(t, from, res.json(t))
			assert.Equal(t, "tool_1", id, label)
			assert.Equal(t, "get_weather", name, label)
			assert.Equal(t, "Cairo", city, label)
		}
	}
}

func TestTranslationGeminiThoughtSignature(t *testing.T) {
	cacheC := newFakeCache()

	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_ANTHROPIC,
			corev1.Service_Spec_Config_LLM_GEMINI,
			`{"model":"corp-model","max_tokens":64,`+
				`"messages":[{"role":"user","content":"Hi"}]}`)
		o.cacheC = cacheC
		o.upstream = func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, `{"candidates":[{"content":{"role":"model","parts":[`+
				`{"functionCall":{"id":"call_123","name":"get_weather",`+
				`"args":{"city":"Cairo"}},"thoughtSignature":"sig-abc"}]},`+
				`"finishReason":"STOP"}],"modelVersion":"m-1"}`)
		}

		res := serveTranslation(t, o)

		assert.Equal(t, http.StatusOK, res.code)
		assert.Equal(t, 1, len(cacheC.entries))

		block := res.json(t)["content"].([]any)[0].(map[string]any)
		assert.Equal(t, "tool_use", block["type"])
		assert.Equal(t, "call_123", block["id"])
		assert.NotContains(t, res.body, "sig-abc")
	}

	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_ANTHROPIC,
			corev1.Service_Spec_Config_LLM_GEMINI,
			`{"model":"corp-model","max_tokens":64,"messages":[`+
				`{"role":"user","content":"Hi"},`+
				`{"role":"assistant","content":[{"type":"tool_use","id":"call_123",`+
				`"name":"get_weather","input":{"city":"Cairo"}}]},`+
				`{"role":"user","content":[{"type":"tool_result",`+
				`"tool_use_id":"call_123","content":"31 C"}]}]}`)
		o.cacheC = cacheC
		o.upstream = func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, transUpstreamResponse(corev1.Service_Spec_Config_LLM_GEMINI))
		}

		res := serveTranslation(t, o)

		assert.Equal(t, http.StatusOK, res.code)

		part := res.upstream["contents"].([]any)[1].(map[string]any)["parts"].([]any)[0]
		assert.Equal(t, "sig-abc", part.(map[string]any)["thoughtSignature"])
	}

	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_ANTHROPIC,
			corev1.Service_Spec_Config_LLM_GEMINI,
			`{"model":"corp-model","max_tokens":64,"messages":[`+
				`{"role":"user","content":"Hi"},`+
				`{"role":"assistant","content":[{"type":"tool_use","id":"unknown_1",`+
				`"name":"get_weather","input":{"city":"Cairo"}}]}]}`)
		o.cacheC = newFakeCache()
		o.upstream = func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, transUpstreamResponse(corev1.Service_Spec_Config_LLM_GEMINI))
		}

		res := serveTranslation(t, o)

		assert.Equal(t, http.StatusOK, res.code)

		part := res.upstream["contents"].([]any)[1].(map[string]any)["parts"].([]any)[0]
		_, ok := part.(map[string]any)["thoughtSignature"]
		assert.False(t, ok)
	}
}

func TestTranslationModelInPath(t *testing.T) {
	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_OPENAI,
			corev1.Service_Spec_Config_LLM_GEMINI,
			`{"model":"gemini-2.5-pro","messages":[{"role":"user","content":"Hi"}]}`)

		res := serveTranslation(t, o)

		assert.Equal(t, "/v1beta/models/gemini-2.5-pro:generateContent", res.upstreamPath)
		_, ok := res.upstream["model"]
		assert.False(t, ok)
	}

	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_GEMINI,
			corev1.Service_Spec_Config_LLM_OPENAI,
			`{"contents":[{"role":"user","parts":[{"text":"Hi"}]}]}`)

		res := serveTranslation(t, o)

		assert.Equal(t, openAIChatPath, res.upstreamPath)
		assert.Equal(t, transTestModel, res.upstream["model"])
	}

	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_OPENAI,
			corev1.Service_Spec_Config_LLM_BEDROCK,
			`{"messages":[{"role":"user","content":"Hi"}]}`)

		res := serveTranslation(t, o)

		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}

	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_BEDROCK,
			corev1.Service_Spec_Config_LLM_GEMINI,
			`{"messages":[{"role":"user","content":[{"text":"Hi"}]}]}`)
		o.path = "/model/anthropic.claude-sonnet-4-5-v1:0/converse"

		res := serveTranslation(t, o)

		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
		assert.Contains(t, res.body, "cannot be translated")
	}
}

func TestTranslationReasoningMatrix(t *testing.T) {
	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_OPENAI,
			corev1.Service_Spec_Config_LLM_GEMINI,
			`{"model":"corp-model","messages":[{"role":"user","content":"Hi"}]}`)
		o.reasoning = &corev1.Service_Spec_Config_LLM_Reasoning{
			Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{
				Level: corev1.Service_Spec_Config_LLM_Reasoning_LOW,
			},
		}

		res := serveTranslation(t, o)

		cfg := res.upstream["generationConfig"].(map[string]any)
		thinking := cfg["thinkingConfig"].(map[string]any)
		assert.Equal(t, float64(lowReasoningBudget), thinking["thinkingBudget"])
	}

	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_OPENAI,
			corev1.Service_Spec_Config_LLM_BEDROCK,
			`{"model":"corp-model","messages":[{"role":"user","content":"Hi"}]}`)
		o.reasoning = &corev1.Service_Spec_Config_LLM_Reasoning{
			Type: &corev1.Service_Spec_Config_LLM_Reasoning_Level_{
				Level: corev1.Service_Spec_Config_LLM_Reasoning_HIGH,
			},
		}

		res := serveTranslation(t, o)

		fields := res.upstream["additionalModelRequestFields"].(map[string]any)
		cfg := fields["reasoning_config"].(map[string]any)
		assert.Equal(t, "enabled", cfg["type"])
		assert.Equal(t, float64(highReasoningBudget), cfg["budget_tokens"])
	}

	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_GEMINI,
			corev1.Service_Spec_Config_LLM_ANTHROPIC,
			`{"contents":[{"role":"user","parts":[{"text":"Hi"}]}],`+
				`"generationConfig":{"thinkingConfig":{"thinkingBudget":8192}}}`)

		res := serveTranslation(t, o)

		thinking := res.upstream["thinking"].(map[string]any)
		assert.Equal(t, "enabled", thinking["type"])
		assert.Equal(t, float64(8192), thinking["budget_tokens"])
	}

	{
		o := newTransOpts(corev1.Service_Spec_Config_LLM_GEMINI,
			corev1.Service_Spec_Config_LLM_ANTHROPIC,
			`{"contents":[{"role":"user","parts":[{"text":"Hi"}]}],`+
				`"generationConfig":{"thinkingConfig":{"thinkingBudget":0}}}`)

		res := serveTranslation(t, o)

		thinking := res.upstream["thinking"].(map[string]any)
		assert.Equal(t, "disabled", thinking["type"])
	}
}

func TestTranslationUnsupportedGeminiBedrock(t *testing.T) {
	for _, body := range []string{
		`{"contents":[{"role":"user","parts":[{"text":"Hi"}]}],` +
			`"safetySettings":[{"category":"HARM_CATEGORY_HARASSMENT"}]}`,
		`{"contents":[{"role":"user","parts":[{"text":"Hi"}]}],` +
			`"cachedContent":"caches/abc"}`,
		`{"contents":[{"role":"user","parts":[{"text":"Hi"}]}],` +
			`"generationConfig":{"candidateCount":2}}`,
		`{"contents":[{"role":"user","parts":[{"text":"Hi"}]}],` +
			`"tools":[{"googleSearch":{}}]}`,
		`{"contents":[{"role":"user","parts":[{"fileData":` +
			`{"fileUri":"files/abc"}}]}]}`,
	} {
		res := serveTranslation(t, newTransOpts(
			corev1.Service_Spec_Config_LLM_GEMINI,
			corev1.Service_Spec_Config_LLM_OPENAI, body))

		assert.False(t, res.isNext, body)
		assert.Equal(t, http.StatusBadRequest, res.code, body)
		assert.Contains(t, res.body, "cannot be translated", body)
	}

	for _, body := range []string{
		`{"messages":[{"role":"user","content":[{"text":"Hi"}]}],` +
			`"guardrailConfig":{"guardrailIdentifier":"g1"}}`,
		`{"messages":[{"role":"user","content":[{"text":"Hi"}]}],` +
			`"additionalModelRequestFields":{"top_k":10}}`,
		`{"messages":[{"role":"user","content":[{"video":{"format":"mp4"}}]}]}`,
		`{"messages":[{"role":"user","content":[{"text":"Hi"}]}],` +
			`"promptVariables":{"a":{"text":"b"}}}`,
	} {
		o := newTransOpts(corev1.Service_Spec_Config_LLM_BEDROCK,
			corev1.Service_Spec_Config_LLM_OPENAI, body)

		res := serveTranslation(t, o)

		assert.False(t, res.isNext, body)
		assert.Equal(t, http.StatusBadRequest, res.code, body)
	}
}

func TestTranslationGeminiPromptBlocked(t *testing.T) {
	o := newTransOpts(corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_GEMINI,
		`{"model":"corp-model","messages":[{"role":"user","content":"Hi"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"promptFeedback":{"blockReason":"SAFETY"},`+
			`"usageMetadata":{"promptTokenCount":9}}`)
	}

	res := serveTranslation(t, o)

	assert.Equal(t, http.StatusBadGateway, res.code)
	assert.Contains(t, res.body, "SAFETY")
	assert.Equal(t, uint64(9), res.reqCtx.LLMUpstreamResponse.Usage.InputTokens)
}

func TestTranslationBedrockToolName(t *testing.T) {
	body := `{"model":"corp-model","messages":[{"role":"user","content":"Hi"}],` +
		`"tools":[{"type":"function","function":{"name":"get.weather",` +
		`"parameters":{"type":"object"}}}]}`

	res := serveTranslation(t, newTransOpts(
		corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_BEDROCK, body))

	assert.False(t, res.isNext)
	assert.Equal(t, http.StatusBadRequest, res.code)
	assert.Contains(t, res.body, "get.weather")
}

func TestTranslationBedrockToolCallID(t *testing.T) {
	body := `{"model":"corp-model","messages":[` +
		`{"role":"user","content":"Hi"},` +
		`{"role":"assistant","tool_calls":[{"id":"call/with:invalid",` +
		`"type":"function","function":{"name":"get_weather",` +
		`"arguments":"{\"city\":\"Cairo\"}"}}]},` +
		`{"role":"tool","tool_call_id":"call/with:invalid","content":"31 C"}]}`

	res := serveTranslation(t, newTransOpts(
		corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_BEDROCK, body))

	assert.True(t, res.isNext)

	turn := transUpstreamToolTurn(t, corev1.Service_Spec_Config_LLM_BEDROCK, res.upstream)
	assert.Equal(t, turn.callID, turn.resultID)
	assert.NotEqual(t, "call/with:invalid", turn.callID)
	assert.True(t, len(turn.callID) <= maxBedrockToolIDLen)
}

func TestTranslationBedrockResponseModel(t *testing.T) {
	o := newTransOpts(corev1.Service_Spec_Config_LLM_OPENAI,
		corev1.Service_Spec_Config_LLM_BEDROCK,
		`{"model":"corp-model","messages":[{"role":"user","content":"Hi"}]}`)
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, transUpstreamResponse(corev1.Service_Spec_Config_LLM_BEDROCK))
	}

	res := serveTranslation(t, o)

	assert.Equal(t, transTestModel, res.json(t)["model"])
	assert.Equal(t, "", res.reqCtx.LLMUpstreamResponse.Model)
}

func TestTranslationStreamEventStreamFraming(t *testing.T) {
	o := newTransOpts(corev1.Service_Spec_Config_LLM_BEDROCK,
		corev1.Service_Spec_Config_LLM_OPENAI,
		transStreamBody(corev1.Service_Spec_Config_LLM_BEDROCK))
	o.isStream = true
	o.upstream = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", transSSEMediaType)
		for _, event := range transUpstreamStream(corev1.Service_Spec_Config_LLM_OPENAI) {
			w.Write([]byte(event))
		}
	}

	res := serveTranslation(t, o)

	assert.Equal(t, transEventStreamMediaType, res.header.Get("Content-Type"))

	evs := res.streamEvents(t, corev1.Service_Spec_Config_LLM_BEDROCK)

	var kinds []string
	for _, ev := range evs {
		kinds = append(kinds, ev["__event"].(string))
	}

	assert.Equal(t, []string{
		"messageStart", "contentBlockDelta", "contentBlockDelta",
		"contentBlockStop", "messageStop", "metadata",
	}, kinds)

	assert.Equal(t, "end_turn", evs[4]["stopReason"])
	assert.Equal(t, float64(10),
		evs[5]["usage"].(map[string]any)["outputTokens"])
}

func TestTranslationEventStreamRoundTrip(t *testing.T) {
	payload := `{"contentBlockIndex":3,"delta":{"text":"Hello"}}`

	frame := httputils.EncodeLLMEventStreamEvent("contentBlockDelta", []byte(payload))

	eventType, out, n := httputils.NextLLMEventStreamEvent(frame)
	assert.Equal(t, len(frame), n)
	assert.Equal(t, "contentBlockDelta", eventType)
	assert.Equal(t, payload, string(out))

	_, _, n = httputils.NextLLMEventStreamEvent(frame[:len(frame)-1])
	assert.Equal(t, 0, n)
}
