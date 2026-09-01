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
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
)

const (
	maxLLMToolNames = 64
	maxLLMStringLen = 256
	maxLLMWalkDepth = 24
	maxLLMWalkNodes = 200000
)

type LLMRequest struct {
	Protocol  corev1.Service_Spec_Config_LLM_Protocol
	Operation corev1.RequestContext_Request_LLM_Operation

	IsKnownRoute bool
	HasBody      bool
	IsBodyValid  bool

	Model          string
	IsModelTooLong bool
	Stream         bool

	MaxOutputTokens uint64

	HasTools           bool
	ToolCount          uint32
	ToolNames          []string
	MaxToolSchemaBytes uint32

	InputItemCount uint32
	HasImageInput  bool
	HasAudioInput  bool

	EstimatedInputTokens uint64
	EstimateQuality      corev1.RequestContext_Request_LLM_EstimateQuality
}

func (r *LLMRequest) GetProtocol() corev1.Service_Spec_Config_LLM_Protocol {
	if r == nil {
		return corev1.Service_Spec_Config_LLM_PROTOCOL_UNSET
	}
	return r.Protocol
}

func (r *LLMRequest) GetOperation() corev1.RequestContext_Request_LLM_Operation {
	if r == nil {
		return corev1.RequestContext_Request_LLM_OPERATION_UNSET
	}
	return r.Operation
}

func (r *LLMRequest) GetModel() string {
	if r == nil {
		return ""
	}
	return r.Model
}

func (r *LLMRequest) GetStream() bool {
	if r == nil {
		return false
	}
	return r.Stream
}

func (r *LLMRequest) GetMaxOutputTokens() uint64 {
	if r == nil {
		return 0
	}
	return r.MaxOutputTokens
}

func (r *LLMRequest) GetToolCount() uint32 {
	if r == nil {
		return 0
	}
	return r.ToolCount
}

func (r *LLMRequest) GetMaxToolSchemaBytes() uint32 {
	if r == nil {
		return 0
	}
	return r.MaxToolSchemaBytes
}

func (r *LLMRequest) GetToolNames() []string {
	if r == nil {
		return nil
	}
	return r.ToolNames
}

func (r *LLMRequest) GetInputItemCount() uint32 {
	if r == nil {
		return 0
	}
	return r.InputItemCount
}

func (r *LLMRequest) GetHasImageInput() bool {
	if r == nil {
		return false
	}
	return r.HasImageInput
}

func (r *LLMRequest) GetHasAudioInput() bool {
	if r == nil {
		return false
	}
	return r.HasAudioInput
}

func (r *LLMRequest) GetEstimatedInputTokens() uint64 {
	if r == nil {
		return 0
	}
	return r.EstimatedInputTokens
}

func (r *LLMRequest) GetEstimateQuality() corev1.RequestContext_Request_LLM_EstimateQuality {
	if r == nil {
		return corev1.RequestContext_Request_LLM_ESTIMATE_QUALITY_UNSET
	}
	return r.EstimateQuality
}

func GetLLMProtocol(cfg *corev1.Service_Spec_Config_LLM) corev1.Service_Spec_Config_LLM_Protocol {
	switch cfg.GetProtocol() {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return corev1.Service_Spec_Config_LLM_ANTHROPIC
	default:
		return corev1.Service_Spec_Config_LLM_OPENAI
	}
}

type llmRoute struct {
	method    string
	path      string
	operation corev1.RequestContext_Request_LLM_Operation
}

var llmRoutesOpenAI = []llmRoute{
	{http.MethodPost, "/v1/chat/completions", corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS},
	{http.MethodPost, "/v1/responses", corev1.RequestContext_Request_LLM_RESPONSES},
	{http.MethodPost, "/v1/completions", corev1.RequestContext_Request_LLM_COMPLETIONS},
	{http.MethodPost, "/v1/embeddings", corev1.RequestContext_Request_LLM_EMBEDDINGS},
	{http.MethodPost, "/v1/moderations", corev1.RequestContext_Request_LLM_MODERATIONS},
	{http.MethodGet, "/v1/models", corev1.RequestContext_Request_LLM_MODELS_LIST},
}

var llmRoutesAnthropic = []llmRoute{
	{http.MethodPost, "/v1/messages", corev1.RequestContext_Request_LLM_MESSAGES},
	{http.MethodPost, "/v1/messages/count_tokens", corev1.RequestContext_Request_LLM_COUNT_TOKENS},
	{http.MethodGet, "/v1/models", corev1.RequestContext_Request_LLM_MODELS_LIST},
}

const llmModelsPrefix = "/v1/models/"

const LLMVersionPrefix = "/v1"

func getLLMRoutes(protocol corev1.Service_Spec_Config_LLM_Protocol) []llmRoute {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return llmRoutesAnthropic
	default:
		return llmRoutesOpenAI
	}
}

func MatchLLMRoute(protocol corev1.Service_Spec_Config_LLM_Protocol,
	method, path string) (corev1.RequestContext_Request_LLM_Operation, bool) {

	for _, route := range getLLMRoutes(protocol) {
		if route.path != path {
			continue
		}
		if route.method != method {
			return corev1.RequestContext_Request_LLM_OPERATION_UNSET, false
		}
		return route.operation, true
	}

	if strings.HasPrefix(path, llmModelsPrefix) {
		model := path[len(llmModelsPrefix):]
		if model == "" || strings.Contains(model, "/") {
			return corev1.RequestContext_Request_LLM_OPERATION_UNSET, false
		}
		if method != http.MethodGet {
			return corev1.RequestContext_Request_LLM_OPERATION_UNSET, false
		}
		return corev1.RequestContext_Request_LLM_MODELS_GET, true
	}

	return corev1.RequestContext_Request_LLM_OPERATION_UNSET, false
}

func IsLLMOperationBodyParsed(operation corev1.RequestContext_Request_LLM_Operation) bool {
	switch operation {
	case corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
		corev1.RequestContext_Request_LLM_RESPONSES,
		corev1.RequestContext_Request_LLM_COMPLETIONS,
		corev1.RequestContext_Request_LLM_EMBEDDINGS,
		corev1.RequestContext_Request_LLM_MODERATIONS,
		corev1.RequestContext_Request_LLM_MESSAGES,
		corev1.RequestContext_Request_LLM_COUNT_TOKENS:
		return true
	default:
		return false
	}
}

func IsLLMOperationStreamable(operation corev1.RequestContext_Request_LLM_Operation) bool {
	switch operation {
	case corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
		corev1.RequestContext_Request_LLM_RESPONSES,
		corev1.RequestContext_Request_LLM_COMPLETIONS,
		corev1.RequestContext_Request_LLM_MESSAGES:
		return true
	default:
		return false
	}
}

type llmEnvelope struct {
	Model  json.RawMessage `json:"model"`
	Stream json.RawMessage `json:"stream"`

	MaxTokens           json.RawMessage `json:"max_tokens"`
	MaxCompletionTokens json.RawMessage `json:"max_completion_tokens"`
	MaxOutputTokens     json.RawMessage `json:"max_output_tokens"`

	Messages     json.RawMessage `json:"messages"`
	Input        json.RawMessage `json:"input"`
	Prompt       json.RawMessage `json:"prompt"`
	Instructions json.RawMessage `json:"instructions"`
	System       json.RawMessage `json:"system"`

	Tools json.RawMessage `json:"tools"`
}

type llmTool struct {
	Name        string          `json:"name"`
	Function    *llmToolFn      `json:"function"`
	InputSchema json.RawMessage `json:"input_schema"`
	Parameters  json.RawMessage `json:"parameters"`
}

type llmToolFn struct {
	Name       string          `json:"name"`
	Parameters json.RawMessage `json:"parameters"`
}

func (t *llmTool) schemaLen() int {
	switch {
	case len(t.InputSchema) > 0:
		return len(t.InputSchema)
	case t.Function != nil && len(t.Function.Parameters) > 0:
		return len(t.Function.Parameters)
	default:
		return len(t.Parameters)
	}
}

func ParseLLMRequest(req *http.Request,
	protocol corev1.Service_Spec_Config_LLM_Protocol, body []byte) *LLMRequest {

	ret := &LLMRequest{
		Protocol:        GetLLMProtocol(&corev1.Service_Spec_Config_LLM{Protocol: protocol}),
		EstimateQuality: corev1.RequestContext_Request_LLM_UNAVAILABLE,
	}

	if req == nil || req.URL == nil {
		return ret
	}

	ret.Operation, ret.IsKnownRoute = MatchLLMRoute(ret.Protocol, req.Method, req.URL.Path)

	if !ret.IsKnownRoute {
		return ret
	}

	if ret.Operation == corev1.RequestContext_Request_LLM_MODELS_GET {
		ret.setModel(strings.TrimPrefix(req.URL.Path, llmModelsPrefix))
		return ret
	}

	if !IsLLMOperationBodyParsed(ret.Operation) {
		return ret
	}

	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return ret
	}

	ret.HasBody = true

	if trimmed[0] != '{' {
		return ret
	}

	env := &llmEnvelope{}
	if err := json.Unmarshal(body, env); err != nil {
		return ret
	}

	ret.IsBodyValid = true

	if len(env.Model) > 0 {
		var v string
		if err := json.Unmarshal(env.Model, &v); err == nil {
			ret.setModel(v)
		}
	}

	if len(env.Stream) > 0 {
		var v bool
		if err := json.Unmarshal(env.Stream, &v); err == nil {
			ret.Stream = v
		}
	}

	for _, raw := range []json.RawMessage{
		env.MaxOutputTokens, env.MaxCompletionTokens, env.MaxTokens,
	} {
		if len(raw) == 0 {
			continue
		}
		var v uint64
		if err := json.Unmarshal(raw, &v); err == nil {
			ret.MaxOutputTokens = max(ret.MaxOutputTokens, v)
		}
	}

	walker := &llmTextWalker{}

	for _, raw := range []json.RawMessage{
		env.Instructions, env.System, env.Prompt, env.Messages, env.Input,
	} {
		if len(raw) == 0 {
			continue
		}
		ret.InputItemCount += countLLMItems(raw)
		walker.walkRaw(raw, 0)
	}

	ret.parseTools(env.Tools, walker)

	ret.HasImageInput = walker.hasImage
	ret.HasAudioInput = walker.hasAudio

	ret.EstimatedInputTokens = walker.estimate(ret.InputItemCount, ret.ToolCount)
	ret.EstimateQuality = func() corev1.RequestContext_Request_LLM_EstimateQuality {
		if walker.hasImage || walker.hasAudio || walker.isTruncated {
			return corev1.RequestContext_Request_LLM_PARTIAL
		}
		return corev1.RequestContext_Request_LLM_COMPLETE
	}()

	return ret
}

func (r *LLMRequest) setModel(arg string) {
	if arg == "" {
		return
	}
	if len(arg) > maxLLMStringLen {
		r.IsModelTooLong = true
		return
	}
	r.Model = arg
}

func (r *LLMRequest) parseTools(raw json.RawMessage, walker *llmTextWalker) {
	if len(raw) == 0 {
		return
	}

	var tools []json.RawMessage
	if err := json.Unmarshal(raw, &tools); err != nil {
		return
	}

	if len(tools) == 0 {
		return
	}

	r.HasTools = true
	r.ToolCount = uint32(len(tools))

	for _, rawTool := range tools {
		tool := &llmTool{}
		if err := json.Unmarshal(rawTool, tool); err != nil {
			continue
		}

		name := tool.Name
		if name == "" && tool.Function != nil {
			name = tool.Function.Name
		}
		if name != "" && len(name) <= maxLLMStringLen &&
			len(r.ToolNames) < maxLLMToolNames {
			r.ToolNames = append(r.ToolNames, name)
		}

		if n := tool.schemaLen(); n > int(r.MaxToolSchemaBytes) {
			r.MaxToolSchemaBytes = uint32(n)
		}

		walker.walkRaw(rawTool, 0)
	}

	sort.Strings(r.ToolNames)
}

func countLLMItems(raw json.RawMessage) uint32 {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return 1
	}

	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return 1
	}

	return uint32(len(items))
}

type llmTextWalker struct {
	asciiBytes    uint64
	nonASCIIBytes uint64

	imageCount uint64

	hasImage bool
	hasAudio bool

	nodes       int
	isTruncated bool
}

var llmBinaryKeys = map[string]struct{}{
	"data":      {},
	"url":       {},
	"image_url": {},
	"file_data": {},
	"b64_json":  {},
}

func (w *llmTextWalker) walkRaw(raw json.RawMessage, depth int) {
	var val any
	if err := json.Unmarshal(raw, &val); err != nil {
		return
	}
	w.walk(val, depth)
}

func (w *llmTextWalker) walk(val any, depth int) {
	if depth > maxLLMWalkDepth {
		w.isTruncated = true
		return
	}

	w.nodes++
	if w.nodes > maxLLMWalkNodes {
		w.isTruncated = true
		return
	}

	switch v := val.(type) {
	case string:
		w.addText(v)
	case []any:
		for _, itm := range v {
			w.walk(itm, depth+1)
		}
	case map[string]any:
		w.walkObject(v, depth)
	}
}

func (w *llmTextWalker) walkObject(obj map[string]any, depth int) {
	switch getLLMModality(obj) {
	case llmModalityImage:
		w.hasImage = true
		w.imageCount++
	case llmModalityAudio:
		w.hasAudio = true
	}

	for key, val := range obj {
		if _, ok := llmBinaryKeys[key]; ok {
			continue
		}
		w.walk(val, depth+1)
	}
}

type llmModality int

const (
	llmModalityNone llmModality = iota
	llmModalityImage
	llmModalityAudio
)

func getLLMModality(obj map[string]any) llmModality {
	if typ, ok := obj["type"].(string); ok {
		switch typ {
		case "image", "image_url", "input_image":
			return llmModalityImage
		case "audio", "input_audio", "input_audio_buffer":
			return llmModalityAudio
		}
	}

	if src, ok := obj["source"].(map[string]any); ok {
		if mediaType, ok := src["media_type"].(string); ok {
			switch {
			case strings.HasPrefix(mediaType, "image/"):
				return llmModalityImage
			case strings.HasPrefix(mediaType, "audio/"):
				return llmModalityAudio
			}
		}
	}

	return llmModalityNone
}

func (w *llmTextWalker) addText(arg string) {
	for i := 0; i < len(arg); i++ {
		if arg[i] < 0x80 {
			w.asciiBytes++
		} else {
			w.nonASCIIBytes++
		}
	}
}

const (
	llmASCIIBytesPerToken    = 4
	llmNonASCIIBytesPerToken = 2

	llmTokensPerInputItem = 4
	llmTokensPerTool      = 8

	llmTokensPerImage = 1000
)

func (w *llmTextWalker) estimate(inputItemCount, toolCount uint32) uint64 {
	ret := ceilDiv(w.asciiBytes, llmASCIIBytesPerToken) +
		ceilDiv(w.nonASCIIBytes, llmNonASCIIBytesPerToken) +
		uint64(inputItemCount)*llmTokensPerInputItem +
		uint64(toolCount)*llmTokensPerTool +
		w.imageCount*llmTokensPerImage

	return ret
}

func ceilDiv(arg, divisor uint64) uint64 {
	if arg == 0 {
		return 0
	}
	return (arg + divisor - 1) / divisor
}

type LLMUsage struct {
	InputTokens  uint64
	OutputTokens uint64
	TotalTokens  uint64

	CacheReadInputTokens     uint64
	CacheCreationInputTokens uint64

	ReasoningTokens uint64

	IsSet bool

	providerTotalTokens uint64
	cacheTokensAdditive bool
}

func (u *LLMUsage) Merge(arg LLMUsage) {
	if !arg.IsSet {
		return
	}

	if arg.InputTokens > 0 {
		u.InputTokens = arg.InputTokens
	}
	if arg.OutputTokens > 0 {
		u.OutputTokens = arg.OutputTokens
	}
	if arg.CacheReadInputTokens > 0 {
		u.CacheReadInputTokens = arg.CacheReadInputTokens
	}
	if arg.CacheCreationInputTokens > 0 {
		u.CacheCreationInputTokens = arg.CacheCreationInputTokens
	}
	if arg.ReasoningTokens > 0 {
		u.ReasoningTokens = arg.ReasoningTokens
	}
	if arg.providerTotalTokens > 0 {
		u.providerTotalTokens = arg.providerTotalTokens
	}
	if arg.cacheTokensAdditive {
		u.cacheTokensAdditive = true
	}

	u.setTotalTokens()
	u.IsSet = true
}

func (u *LLMUsage) setTotalTokens() {
	if u.providerTotalTokens > 0 {
		u.TotalTokens = u.providerTotalTokens
		return
	}

	u.TotalTokens = u.InputTokens + u.OutputTokens
	if u.cacheTokensAdditive {
		u.TotalTokens += u.CacheReadInputTokens + u.CacheCreationInputTokens
	}
}

type LLMResponse struct {
	ResponseID string
	Model      string

	FinishReason string

	Usage LLMUsage

	HasContentDelta bool
}

type llmResponseEnvelope struct {
	ID    json.RawMessage `json:"id"`
	Model json.RawMessage `json:"model"`
	Type  json.RawMessage `json:"type"`

	Usage *llmUsageJSON `json:"usage"`

	Choices []struct {
		FinishReason string          `json:"finish_reason"`
		Delta        json.RawMessage `json:"delta"`
		Text         string          `json:"text"`
	} `json:"choices"`

	StopReason string `json:"stop_reason"`
	Status     string `json:"status"`

	Delta json.RawMessage `json:"delta"`

	Response json.RawMessage `json:"response"`
	Message  json.RawMessage `json:"message"`
}

type llmUsageJSON struct {
	PromptTokens     uint64 `json:"prompt_tokens"`
	CompletionTokens uint64 `json:"completion_tokens"`
	TotalTokens      uint64 `json:"total_tokens"`

	InputTokens  uint64 `json:"input_tokens"`
	OutputTokens uint64 `json:"output_tokens"`

	CacheReadInputTokens     uint64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens uint64 `json:"cache_creation_input_tokens"`

	PromptTokensDetails *struct {
		CachedTokens uint64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`

	InputTokensDetails *struct {
		CachedTokens uint64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`

	CompletionTokensDetails *struct {
		ReasoningTokens uint64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`

	OutputTokensDetails *struct {
		ReasoningTokens uint64 `json:"reasoning_tokens"`
	} `json:"output_tokens_details"`
}

func (u *llmUsageJSON) toUsage() LLMUsage {
	ret := LLMUsage{
		InputTokens:  max(u.PromptTokens, u.InputTokens),
		OutputTokens: max(u.CompletionTokens, u.OutputTokens),

		CacheReadInputTokens:     u.CacheReadInputTokens,
		CacheCreationInputTokens: u.CacheCreationInputTokens,

		providerTotalTokens: u.TotalTokens,
		cacheTokensAdditive: u.CacheReadInputTokens > 0 ||
			u.CacheCreationInputTokens > 0,
	}

	if u.PromptTokensDetails != nil {
		ret.CacheReadInputTokens = max(ret.CacheReadInputTokens,
			u.PromptTokensDetails.CachedTokens)
	}
	if u.InputTokensDetails != nil {
		ret.CacheReadInputTokens = max(ret.CacheReadInputTokens,
			u.InputTokensDetails.CachedTokens)
	}
	if u.CompletionTokensDetails != nil {
		ret.ReasoningTokens = u.CompletionTokensDetails.ReasoningTokens
	}
	if u.OutputTokensDetails != nil {
		ret.ReasoningTokens = max(ret.ReasoningTokens, u.OutputTokensDetails.ReasoningTokens)
	}

	ret.setTotalTokens()
	ret.IsSet = true

	return ret
}

func ParseLLMResponse(body []byte) *LLMResponse {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}

	env := &llmResponseEnvelope{}
	if err := json.Unmarshal(body, env); err != nil {
		return nil
	}

	ret := &LLMResponse{}
	ret.setFromEnvelope(env)

	for _, raw := range []json.RawMessage{env.Response, env.Message} {
		if len(raw) == 0 {
			continue
		}
		nested := &llmResponseEnvelope{}
		if err := json.Unmarshal(raw, nested); err != nil {
			continue
		}
		ret.setFromEnvelope(nested)
	}

	return ret
}

func (r *LLMResponse) setFromEnvelope(env *llmResponseEnvelope) {
	if len(env.ID) > 0 {
		var v string
		if err := json.Unmarshal(env.ID, &v); err == nil && v != "" {
			r.ResponseID = v
		}
	}

	if len(env.Model) > 0 {
		var v string
		if err := json.Unmarshal(env.Model, &v); err == nil && v != "" {
			r.Model = v
		}
	}

	delta := parseLLMDelta(env.Delta)

	switch {
	case env.StopReason != "":
		r.FinishReason = env.StopReason
	case len(env.Choices) > 0 && env.Choices[0].FinishReason != "":
		r.FinishReason = env.Choices[0].FinishReason
	case delta != nil && delta.StopReason != "":
		r.FinishReason = delta.StopReason
	case isLLMTerminalStatus(env.Status):
		r.FinishReason = env.Status
	}

	if env.Usage != nil {
		r.Usage.Merge(env.Usage.toUsage())
	}

	if delta != nil {
		if delta.Usage != nil {
			r.Usage.Merge(delta.Usage.toUsage())
		}

		if delta.Text != "" {
			r.HasContentDelta = true
		}
	}

	if len(env.Choices) > 0 {
		if env.Choices[0].Text != "" {
			r.HasContentDelta = true
		}
		if hasLLMDeltaContent(env.Choices[0].Delta) {
			r.HasContentDelta = true
		}
	}

	if len(env.Type) > 0 {
		var v string
		if err := json.Unmarshal(env.Type, &v); err == nil && isLLMContentEventType(v) {
			r.HasContentDelta = true
		}
	}
}

type llmDelta struct {
	Text       string        `json:"text"`
	StopReason string        `json:"stop_reason"`
	Usage      *llmUsageJSON `json:"usage"`
}

func parseLLMDelta(raw json.RawMessage) *llmDelta {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return nil
	}

	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil
		}
		return &llmDelta{Text: text}
	}

	ret := &llmDelta{}
	if err := json.Unmarshal(raw, ret); err != nil {
		return nil
	}

	return ret
}

type llmChoiceDelta struct {
	Content   json.RawMessage `json:"content"`
	ToolCalls json.RawMessage `json:"tool_calls"`
}

func hasLLMDeltaContent(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}

	delta := &llmChoiceDelta{}
	if err := json.Unmarshal(raw, delta); err != nil {
		return false
	}

	if len(delta.ToolCalls) > 0 {
		return true
	}

	if len(delta.Content) == 0 {
		return false
	}

	var content string
	if err := json.Unmarshal(delta.Content, &content); err == nil {
		return content != ""
	}

	return true
}

func isLLMTerminalStatus(arg string) bool {
	switch arg {
	case "completed", "failed", "cancelled", "incomplete":
		return true
	default:
		return false
	}
}

func isLLMContentEventType(arg string) bool {
	switch arg {
	case "response.output_text.delta",
		"response.refusal.delta",
		"response.function_call_arguments.delta",
		"content_block_delta":
		return true
	default:
		return false
	}
}

func IsLLMStreamDone(data []byte) bool {
	return bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]"))
}
