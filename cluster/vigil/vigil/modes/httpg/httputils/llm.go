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
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/url"
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
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return corev1.Service_Spec_Config_LLM_GEMINI
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return corev1.Service_Spec_Config_LLM_BEDROCK
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

const llmGeminiModelsPath = "/v1beta/models"

const llmBedrockModelPrefix = "/model/"

const LLMVersionPrefix = "/v1"

const llmGeminiVersionPrefix = "/v1beta"

func GetLLMVersionPrefix(protocol corev1.Service_Spec_Config_LLM_Protocol) string {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return llmGeminiVersionPrefix
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return ""
	default:
		return LLMVersionPrefix
	}
}

func getLLMRoutes(protocol corev1.Service_Spec_Config_LLM_Protocol) []llmRoute {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return llmRoutesAnthropic
	default:
		return llmRoutesOpenAI
	}
}

type llmRouteMatch struct {
	operation corev1.RequestContext_Request_LLM_Operation
	model     string
	isStream  bool
}

func MatchLLMRoute(protocol corev1.Service_Spec_Config_LLM_Protocol,
	method, path string) (corev1.RequestContext_Request_LLM_Operation, bool) {

	match, ok := matchLLMRoute(protocol, method, path)
	if !ok {
		return corev1.RequestContext_Request_LLM_OPERATION_UNSET, false
	}

	return match.operation, true
}

func matchLLMRoute(protocol corev1.Service_Spec_Config_LLM_Protocol,
	method, path string) (*llmRouteMatch, bool) {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return matchLLMRouteGemini(method, path)
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return matchLLMRouteBedrock(method, path)
	}

	for _, route := range getLLMRoutes(protocol) {
		if route.path != path {
			continue
		}
		if route.method != method {
			return nil, false
		}
		return &llmRouteMatch{operation: route.operation}, true
	}

	if strings.HasPrefix(path, llmModelsPrefix) {
		model := path[len(llmModelsPrefix):]
		if model == "" || strings.Contains(model, "/") {
			return nil, false
		}
		if method != http.MethodGet {
			return nil, false
		}
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_MODELS_GET,
			model:     model,
		}, true
	}

	return nil, false
}

func matchLLMRouteGemini(method, path string) (*llmRouteMatch, bool) {
	if path == llmGeminiModelsPath {
		if method != http.MethodGet {
			return nil, false
		}
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_MODELS_LIST,
		}, true
	}

	if !strings.HasPrefix(path, llmGeminiModelsPath+"/") {
		return nil, false
	}

	rest := path[len(llmGeminiModelsPath)+1:]
	if rest == "" || strings.Contains(rest, "/") {
		return nil, false
	}

	model, verb, hasVerb := strings.Cut(rest, ":")
	if model == "" {
		return nil, false
	}

	if !hasVerb {
		if method != http.MethodGet {
			return nil, false
		}
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_MODELS_GET,
			model:     model,
		}, true
	}

	if method != http.MethodPost {
		return nil, false
	}

	switch verb {
	case "generateContent":
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_GENERATE_CONTENT,
			model:     model,
		}, true
	case "streamGenerateContent":
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_GENERATE_CONTENT,
			model:     model,
			isStream:  true,
		}, true
	case "countTokens":
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_COUNT_TOKENS,
			model:     model,
		}, true
	case "embedContent", "batchEmbedContents":
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_EMBED_CONTENT,
			model:     model,
		}, true
	default:
		return nil, false
	}
}

func matchLLMRouteBedrock(method, path string) (*llmRouteMatch, bool) {
	if !strings.HasPrefix(path, llmBedrockModelPrefix) {
		return nil, false
	}

	rest := path[len(llmBedrockModelPrefix):]

	idx := strings.LastIndex(rest, "/")
	if idx <= 0 {
		return nil, false
	}

	model, verb := rest[:idx], rest[idx+1:]

	if method != http.MethodPost {
		return nil, false
	}

	switch verb {
	case "converse":
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_CONVERSE,
			model:     model,
		}, true
	case "converse-stream":
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_CONVERSE,
			model:     model,
			isStream:  true,
		}, true
	case "invoke":
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_INVOKE_MODEL,
			model:     model,
		}, true
	case "invoke-with-response-stream":
		return &llmRouteMatch{
			operation: corev1.RequestContext_Request_LLM_INVOKE_MODEL,
			model:     model,
			isStream:  true,
		}, true
	default:
		return nil, false
	}
}

func IsLLMModelInPath(protocol corev1.Service_Spec_Config_LLM_Protocol) bool {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_GEMINI,
		corev1.Service_Spec_Config_LLM_BEDROCK:
		return true
	default:
		return false
	}
}

func GetLLMModelPath(protocol corev1.Service_Spec_Config_LLM_Protocol,
	path string) string {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_GEMINI:
		rest, ok := strings.CutPrefix(path, llmGeminiModelsPath+"/")
		if !ok {
			return ""
		}
		model, _, hasVerb := strings.Cut(rest, ":")
		if !hasVerb {
			return ""
		}
		return model
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		rest, ok := strings.CutPrefix(path, llmBedrockModelPrefix)
		if !ok {
			return ""
		}
		idx := strings.LastIndex(rest, "/")
		if idx <= 0 {
			return ""
		}
		return rest[:idx]
	default:
		return ""
	}
}

func SetLLMModelPath(protocol corev1.Service_Spec_Config_LLM_Protocol,
	path, model string) (string, string) {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_GEMINI:
		rest, ok := strings.CutPrefix(path, llmGeminiModelsPath+"/")
		if !ok {
			return "", ""
		}
		_, verb, hasVerb := strings.Cut(rest, ":")
		if !hasVerb {
			return "", ""
		}
		return llmGeminiModelsPath + "/" + model + ":" + verb,
			llmGeminiModelsPath + "/" + url.PathEscape(model) + ":" + verb
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		rest, ok := strings.CutPrefix(path, llmBedrockModelPrefix)
		if !ok {
			return "", ""
		}
		idx := strings.LastIndex(rest, "/")
		if idx <= 0 {
			return "", ""
		}
		verb := rest[idx+1:]
		return llmBedrockModelPrefix + model + "/" + verb,
			llmBedrockModelPrefix + url.PathEscape(model) + "/" + verb
	default:
		return "", ""
	}
}

func isLLMStreamInBody(protocol corev1.Service_Spec_Config_LLM_Protocol) bool {
	switch protocol {
	case corev1.Service_Spec_Config_LLM_GEMINI,
		corev1.Service_Spec_Config_LLM_BEDROCK:
		return false
	default:
		return true
	}
}

func IsLLMOperationBodyParsed(operation corev1.RequestContext_Request_LLM_Operation) bool {
	switch operation {
	case corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
		corev1.RequestContext_Request_LLM_RESPONSES,
		corev1.RequestContext_Request_LLM_COMPLETIONS,
		corev1.RequestContext_Request_LLM_EMBEDDINGS,
		corev1.RequestContext_Request_LLM_MODERATIONS,
		corev1.RequestContext_Request_LLM_MESSAGES,
		corev1.RequestContext_Request_LLM_COUNT_TOKENS,
		corev1.RequestContext_Request_LLM_GENERATE_CONTENT,
		corev1.RequestContext_Request_LLM_EMBED_CONTENT,
		corev1.RequestContext_Request_LLM_CONVERSE:
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
		corev1.RequestContext_Request_LLM_MESSAGES,
		corev1.RequestContext_Request_LLM_GENERATE_CONTENT,
		corev1.RequestContext_Request_LLM_CONVERSE,
		corev1.RequestContext_Request_LLM_INVOKE_MODEL:
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

	Contents          json.RawMessage      `json:"contents"`
	SystemInstruction json.RawMessage      `json:"systemInstruction"`
	GenerationConfig  *llmGenerationConfig `json:"generationConfig"`

	Content                json.RawMessage `json:"content"`
	Requests               json.RawMessage `json:"requests"`
	GenerateContentRequest json.RawMessage `json:"generateContentRequest"`
	CachedContent          json.RawMessage `json:"cachedContent"`

	InferenceConfig *llmInferenceConfig `json:"inferenceConfig"`
	ToolConfig      *llmToolConfig      `json:"toolConfig"`
}

type llmGenerationConfig struct {
	MaxOutputTokens json.RawMessage `json:"maxOutputTokens"`
}

type llmInferenceConfig struct {
	MaxTokens json.RawMessage `json:"maxTokens"`
}

type llmToolConfig struct {
	Tools json.RawMessage `json:"tools"`
}

type llmToolGroup struct {
	FunctionDeclarations []json.RawMessage `json:"functionDeclarations"`
}

type llmTool struct {
	Name        string          `json:"name"`
	Function    *llmToolFn      `json:"function"`
	InputSchema json.RawMessage `json:"input_schema"`
	Parameters  json.RawMessage `json:"parameters"`
	ToolSpec    *llmToolSpec    `json:"toolSpec"`
}

type llmToolFn struct {
	Name       string          `json:"name"`
	Parameters json.RawMessage `json:"parameters"`
}

type llmToolSpec struct {
	Name        string          `json:"name"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

func (t *llmTool) schemaLen() int {
	switch {
	case len(t.InputSchema) > 0:
		return len(t.InputSchema)
	case t.Function != nil && len(t.Function.Parameters) > 0:
		return len(t.Function.Parameters)
	case t.ToolSpec != nil && len(t.ToolSpec.InputSchema) > 0:
		return len(t.ToolSpec.InputSchema)
	default:
		return len(t.Parameters)
	}
}

func (e *llmEnvelope) toolsRaw(
	protocol corev1.Service_Spec_Config_LLM_Protocol) json.RawMessage {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return flattenLLMToolGroups(e.Tools)
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		if e.ToolConfig == nil {
			return nil
		}
		return e.ToolConfig.Tools
	default:
		return e.Tools
	}
}

func flattenLLMToolGroups(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}

	var groups []json.RawMessage
	if err := json.Unmarshal(raw, &groups); err != nil {
		return nil
	}

	var ret []json.RawMessage
	for _, rawGroup := range groups {
		group := &llmToolGroup{}
		if err := json.Unmarshal(rawGroup, group); err != nil {
			continue
		}
		if len(group.FunctionDeclarations) == 0 {
			ret = append(ret, rawGroup)
			continue
		}
		ret = append(ret, group.FunctionDeclarations...)
	}

	if len(ret) == 0 {
		return nil
	}

	out, err := json.Marshal(ret)
	if err != nil {
		return nil
	}

	return out
}

func (e *llmEnvelope) inputRaw(
	protocol corev1.Service_Spec_Config_LLM_Protocol) []json.RawMessage {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return []json.RawMessage{e.SystemInstruction, e.Contents, e.Content,
			e.Requests, e.GenerateContentRequest}
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return []json.RawMessage{e.System, e.Messages}
	default:
		return []json.RawMessage{
			e.Instructions, e.System, e.Prompt, e.Messages, e.Input,
		}
	}
}

func (e *llmEnvelope) maxOutputTokensRaw(
	protocol corev1.Service_Spec_Config_LLM_Protocol) []json.RawMessage {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_GEMINI:
		if e.GenerationConfig == nil {
			return nil
		}
		return []json.RawMessage{e.GenerationConfig.MaxOutputTokens}
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		if e.InferenceConfig == nil {
			return nil
		}
		return []json.RawMessage{e.InferenceConfig.MaxTokens}
	default:
		return []json.RawMessage{
			e.MaxOutputTokens, e.MaxCompletionTokens, e.MaxTokens,
		}
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

	match, isKnownRoute := matchLLMRoute(ret.Protocol, req.Method, req.URL.Path)
	ret.IsKnownRoute = isKnownRoute

	if !ret.IsKnownRoute {
		return ret
	}

	ret.Operation = match.operation
	ret.Stream = match.isStream
	ret.setModel(match.model)

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

	if len(env.Model) > 0 && ret.Model == "" && !ret.IsModelTooLong {
		var v string
		if err := json.Unmarshal(env.Model, &v); err == nil {
			ret.setModel(v)
		}
	}

	if len(env.Stream) > 0 && isLLMStreamInBody(ret.Protocol) {
		var v bool
		if err := json.Unmarshal(env.Stream, &v); err == nil {
			ret.Stream = v
		}
	}

	for _, raw := range env.maxOutputTokensRaw(ret.Protocol) {
		if len(raw) == 0 {
			continue
		}
		var v uint64
		if err := json.Unmarshal(raw, &v); err == nil {
			ret.MaxOutputTokens = max(ret.MaxOutputTokens, v)
		}
	}

	walker := &llmTextWalker{}

	if len(env.CachedContent) > 0 {
		walker.isTruncated = true
	}

	for _, raw := range env.inputRaw(ret.Protocol) {
		if len(raw) == 0 {
			continue
		}
		ret.InputItemCount += countLLMItems(raw)
		walker.walkRaw(raw, 0)
	}

	ret.parseTools(env.toolsRaw(ret.Protocol), walker)

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
		if name == "" && tool.ToolSpec != nil {
			name = tool.ToolSpec.Name
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
	"data":        {},
	"url":         {},
	"image_url":   {},
	"file_data":   {},
	"b64_json":    {},
	"bytes":       {},
	"fileUri":     {},
	"file_uri":    {},
	"inlineData":  {},
	"inline_data": {},
	"fileData":    {},
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
	case llmModalityOpaque:
		w.isTruncated = true
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
	llmModalityOpaque
)

func getLLMModality(obj map[string]any) llmModality {
	if typ, ok := obj["type"].(string); ok {
		switch typ {
		case "image", "image_url", "input_image":
			return llmModalityImage
		case "audio", "input_audio", "input_audio_buffer":
			return llmModalityAudio
		case "document", "file", "input_file":
			return llmModalityOpaque
		}
	}

	if src, ok := obj["source"].(map[string]any); ok {
		if mediaType, ok := src["media_type"].(string); ok {
			return getLLMMediaModality(mediaType)
		}
	}

	for _, key := range []string{"inlineData", "inline_data", "fileData", "file_data"} {
		src, ok := obj[key].(map[string]any)
		if !ok {
			continue
		}
		for _, cur := range []string{"mimeType", "mime_type"} {
			if mimeType, ok := src[cur].(string); ok {
				return getLLMMediaModality(mimeType)
			}
		}
		return llmModalityOpaque
	}

	if _, ok := obj["image"].(map[string]any); ok {
		return llmModalityImage
	}

	for _, key := range []string{"video", "document"} {
		if _, ok := obj[key].(map[string]any); ok {
			return llmModalityOpaque
		}
	}

	return llmModalityNone
}

func getLLMMediaModality(mediaType string) llmModality {
	switch {
	case strings.HasPrefix(mediaType, "image/"):
		return llmModalityImage
	case strings.HasPrefix(mediaType, "audio/"):
		return llmModalityAudio
	default:
		return llmModalityOpaque
	}
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

	StopReasonCamel string `json:"stopReason"`

	Output json.RawMessage `json:"output"`

	Candidates []struct {
		FinishReason string          `json:"finishReason"`
		Content      json.RawMessage `json:"content"`
	} `json:"candidates"`

	UsageMetadata *llmUsageGemini `json:"usageMetadata"`

	ModelVersion json.RawMessage `json:"modelVersion"`
	ResponseID   json.RawMessage `json:"responseId"`
}

type llmUsageGemini struct {
	PromptTokenCount        uint64 `json:"promptTokenCount"`
	CandidatesTokenCount    uint64 `json:"candidatesTokenCount"`
	TotalTokenCount         uint64 `json:"totalTokenCount"`
	ThoughtsTokenCount      uint64 `json:"thoughtsTokenCount"`
	CachedContentTokenCount uint64 `json:"cachedContentTokenCount"`
}

func (u *llmUsageGemini) toUsage() LLMUsage {
	ret := LLMUsage{
		InputTokens:          u.PromptTokenCount,
		OutputTokens:         u.CandidatesTokenCount + u.ThoughtsTokenCount,
		ReasoningTokens:      u.ThoughtsTokenCount,
		CacheReadInputTokens: u.CachedContentTokenCount,

		providerTotalTokens: u.TotalTokenCount,
	}

	ret.setTotalTokens()
	ret.IsSet = true

	return ret
}

type llmUsageJSON struct {
	PromptTokens     uint64 `json:"prompt_tokens"`
	CompletionTokens uint64 `json:"completion_tokens"`
	TotalTokens      uint64 `json:"total_tokens"`

	InputTokens  uint64 `json:"input_tokens"`
	OutputTokens uint64 `json:"output_tokens"`

	CacheReadInputTokens     uint64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens uint64 `json:"cache_creation_input_tokens"`

	InputTokensCamel  uint64 `json:"inputTokens"`
	OutputTokensCamel uint64 `json:"outputTokens"`
	TotalTokensCamel  uint64 `json:"totalTokens"`

	CacheReadInputTokensCamel  uint64 `json:"cacheReadInputTokens"`
	CacheWriteInputTokensCamel uint64 `json:"cacheWriteInputTokens"`

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
		InputTokens:  max(u.PromptTokens, u.InputTokens, u.InputTokensCamel),
		OutputTokens: max(u.CompletionTokens, u.OutputTokens, u.OutputTokensCamel),

		CacheReadInputTokens: max(u.CacheReadInputTokens,
			u.CacheReadInputTokensCamel),
		CacheCreationInputTokens: max(u.CacheCreationInputTokens,
			u.CacheWriteInputTokensCamel),

		providerTotalTokens: max(u.TotalTokens, u.TotalTokensCamel),
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

	for _, raw := range []json.RawMessage{env.Response, env.Message, env.Output} {
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
	for _, raw := range []json.RawMessage{env.ID, env.ResponseID} {
		if len(raw) == 0 {
			continue
		}
		var v string
		if err := json.Unmarshal(raw, &v); err == nil && v != "" {
			r.ResponseID = v
		}
	}

	for _, raw := range []json.RawMessage{env.Model, env.ModelVersion} {
		if len(raw) == 0 {
			continue
		}
		var v string
		if err := json.Unmarshal(raw, &v); err == nil && v != "" {
			r.Model = v
		}
	}

	delta := parseLLMDelta(env.Delta)

	switch {
	case env.StopReason != "":
		r.FinishReason = env.StopReason
	case env.StopReasonCamel != "":
		r.FinishReason = env.StopReasonCamel
	case len(env.Choices) > 0 && env.Choices[0].FinishReason != "":
		r.FinishReason = env.Choices[0].FinishReason
	case len(env.Candidates) > 0 && env.Candidates[0].FinishReason != "":
		r.FinishReason = env.Candidates[0].FinishReason
	case delta != nil && delta.StopReason != "":
		r.FinishReason = delta.StopReason
	case isLLMTerminalStatus(env.Status):
		r.FinishReason = env.Status
	}

	if env.Usage != nil {
		r.Usage.Merge(env.Usage.toUsage())
	}

	if env.UsageMetadata != nil {
		r.Usage.Merge(env.UsageMetadata.toUsage())
	}

	if len(env.Candidates) > 0 && hasLLMPartsText(env.Candidates[0].Content) {
		r.HasContentDelta = true
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

const LLMEventStreamMediaType = "application/vnd.amazon.eventstream"

const (
	llmEventStreamPreludeLen = 12
	llmEventStreamCRCLen     = 4

	maxLLMEventStreamMessageLen = 24 * 1024 * 1024
)

func NextLLMEventStreamMessage(buf []byte) ([]byte, int) {
	if len(buf) < llmEventStreamPreludeLen {
		return nil, 0
	}

	totalLen := int(binary.BigEndian.Uint32(buf[0:4]))
	headersLen := int(binary.BigEndian.Uint32(buf[4:8]))

	if totalLen < llmEventStreamPreludeLen+llmEventStreamCRCLen ||
		totalLen > maxLLMEventStreamMessageLen {
		return nil, -1
	}

	if headersLen > totalLen-llmEventStreamPreludeLen-llmEventStreamCRCLen {
		return nil, -1
	}

	if len(buf) < totalLen {
		return nil, 0
	}

	payload := buf[llmEventStreamPreludeLen+headersLen : totalLen-llmEventStreamCRCLen]

	return bytes.Clone(payload), totalLen
}

func NextLLMJSONArrayMessage(buf []byte) ([]byte, int) {
	idx := 0
	for idx < len(buf) {
		switch buf[idx] {
		case ' ', '\t', '\r', '\n', ',', '[', ']':
			idx++
			continue
		case '{':
		default:
			return nil, -1
		}
		break
	}

	if idx >= len(buf) {
		return nil, idx
	}

	var depth int
	var isString bool
	var isEscaped bool

	for i := idx; i < len(buf); i++ {
		cur := buf[i]
		switch {
		case isEscaped:
			isEscaped = false
		case isString && cur == '\\':
			isEscaped = true
		case cur == '"':
			isString = !isString
		case isString:
		case cur == '{':
			depth++
		case cur == '}':
			depth--
			if depth == 0 {
				return bytes.Clone(buf[idx : i+1]), i + 1
			}
		}
	}

	return nil, 0
}

func hasLLMPartsText(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}

	var content struct {
		Parts []struct {
			Text         string          `json:"text"`
			FunctionCall json.RawMessage `json:"functionCall"`
		} `json:"parts"`
	}
	if err := json.Unmarshal(raw, &content); err != nil {
		return false
	}

	for _, part := range content.Parts {
		if part.Text != "" || len(part.FunctionCall) > 0 {
			return true
		}
	}

	return false
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
