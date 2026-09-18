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
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

const geminiAPIKeyHeader = "X-Goog-Api-Key"

const transSyntheticToolIDPrefix = "octl_"

var geminiContentFields = newTransFields([]string{
	"contents", "systemInstruction", "tools", "toolConfig", "generationConfig",
}, []string{"labels"})

var geminiGenerationConfigFields = newTransFields([]string{
	"maxOutputTokens", "temperature", "topP", "stopSequences",
	"candidateCount", "thinkingConfig",
}, nil)

var geminiContentEntryFields = newTransFields([]string{"role", "parts"}, nil)

var geminiTextPartFields = newTransFields([]string{
	"text",
}, []string{"thought", "thoughtSignature"})

var geminiInlineDataFields = newTransFields([]string{
	"inlineData",
}, []string{"thought", "thoughtSignature"})

var geminiFunctionCallFields = newTransFields([]string{
	"functionCall",
}, []string{"thought", "thoughtSignature"})

var geminiFunctionResponseFields = newTransFields([]string{
	"functionResponse",
}, []string{"thought", "thoughtSignature"})

var geminiFunctionCallInnerFields = newTransFields([]string{"id", "name", "args"}, nil)

var geminiFunctionResponseInnerFields = newTransFields([]string{
	"id", "name", "response",
}, nil)

var geminiToolGroupFields = newTransFields([]string{"functionDeclarations"}, nil)

var geminiFunctionDeclarationFields = newTransFields([]string{
	"name", "description", "parameters",
}, []string{"parametersJsonSchema", "behavior"})

var geminiToolConfigFields = newTransFields([]string{"functionCallingConfig"}, nil)

var geminiFunctionCallingConfigFields = newTransFields([]string{
	"mode", "allowedFunctionNames",
}, nil)

var geminiInlineDataInnerFields = newTransFields([]string{"mimeType", "data"}, nil)

type geminiContentCodec struct{}

func (c *geminiContentCodec) protocol() corev1.Service_Spec_Config_LLM_Protocol {
	return corev1.Service_Spec_Config_LLM_GEMINI
}

func (c *geminiContentCodec) route() corev1.RequestContext_Request_LLM_Route {
	return corev1.RequestContext_Request_LLM_GENERATE_CONTENT
}

func (c *geminiContentCodec) streamMediaType() string {
	return transSSEMediaType
}

func (c *geminiContentCodec) decodeRequest(body []byte) (*transRequest, error) {
	root, err := transObject(body)
	if err != nil {
		return nil, transUnsupported("the request body is not a JSON object")
	}

	if err := geminiContentFields.check(root, "Gemini GenerateContent request"); err != nil {
		return nil, err
	}

	ret := &transRequest{}

	if raw, ok := root["generationConfig"]; ok && !transIsNull(raw) {
		if err := c.decodeGenerationConfig(ret, raw); err != nil {
			return nil, err
		}
	}

	if raw, ok := root["systemInstruction"]; ok && !transIsNull(raw) {
		if err := c.decodeSystem(ret, raw); err != nil {
			return nil, err
		}
	}

	if raw, ok := root["tools"]; ok && !transIsNull(raw) {
		if ret.tools, err = c.decodeTools(raw); err != nil {
			return nil, err
		}
	}

	if raw, ok := root["toolConfig"]; ok && !transIsNull(raw) {
		if ret.toolChoice, err = c.decodeToolConfig(raw); err != nil {
			return nil, err
		}
	}

	if err := c.decodeContents(ret, root["contents"]); err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *geminiContentCodec) decodeGenerationConfig(ret *transRequest,
	raw json.RawMessage) error {

	obj, err := transObject(raw)
	if err != nil {
		return transUnsupported("the `generationConfig` field is not a JSON object")
	}

	if err := geminiGenerationConfigFields.check(obj, "`generationConfig` field"); err != nil {
		return err
	}

	for key, cur := range obj {
		if transIsNull(cur) {
			continue
		}

		var err error
		switch key {
		case "maxOutputTokens":
			ret.maxOutputTokens, err = transUint(cur, key)
		case "stopSequences":
			ret.stopSequences, err = transStrings(cur, key)
		case "temperature":
			var val float64
			if val, err = transFloat(cur, key); err == nil {
				ret.temperature = &val
			}
		case "topP":
			var val float64
			if val, err = transFloat(cur, key); err == nil {
				ret.topP = &val
			}
		case "candidateCount":
			var val uint64
			if val, err = transUint(cur, key); err == nil && val > 1 {
				err = transUnsupported(
					"a `candidateCount` above 1 cannot be translated")
			}
		case "thinkingConfig":
			err = c.decodeThinking(ret, cur)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *geminiContentCodec) decodeThinking(ret *transRequest, raw json.RawMessage) error {
	obj, err := transObject(raw)
	if err != nil {
		return transUnsupported("the `thinkingConfig` field is not a JSON object")
	}

	cur, ok := obj["thinkingBudget"]
	if !ok || transIsNull(cur) {
		return nil
	}

	budget, err := transUint(cur, "thinkingBudget")
	if err != nil {
		return err
	}

	if budget == 0 {
		ret.reasoningTarget = newReasoningLevel(
			corev1.Service_Spec_Config_LLM_Reasoning_NONE)
		return nil
	}

	ret.reasoningTarget = newReasoningTokenBudget(budget)

	return nil
}

func (c *geminiContentCodec) decodeSystem(ret *transRequest, raw json.RawMessage) error {
	obj, err := transObject(raw)
	if err != nil {
		return transUnsupported("the `systemInstruction` field is not a JSON object")
	}

	blocks, err := c.decodeParts(obj["parts"])
	if err != nil {
		return err
	}

	for _, block := range blocks {
		if block.kind != transBlockText {
			return transUnsupported(
				"the `systemInstruction` field carries content that cannot be translated")
		}
		ret.system = append(ret.system, block.text)
	}

	return nil
}

func (c *geminiContentCodec) decodeContents(ret *transRequest, raw json.RawMessage) error {
	if transIsNull(raw) {
		return transUnsupported("the request declares no contents")
	}

	entries, err := transArray(raw, "contents")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		obj, err := transObject(entry)
		if err != nil {
			return transUnsupported("a content entry is not a JSON object")
		}

		if err := geminiContentEntryFields.check(obj, "content entry"); err != nil {
			return err
		}

		role := roleUser
		if cur, ok := obj["role"]; ok && !transIsNull(cur) {
			if role, err = transString(cur, "role"); err != nil {
				return err
			}
		}

		switch role {
		case roleUser:
		case roleModel:
			role = roleAssistant
		default:
			return transUnsupported(
				"a content entry of the `%s` role cannot be translated", role)
		}

		blocks, err := c.decodeParts(obj["parts"])
		if err != nil {
			return err
		}

		ret.messages = append(ret.messages, &transMessage{
			role:   role,
			blocks: blocks,
		})
	}

	return nil
}

func (c *geminiContentCodec) decodeParts(raw json.RawMessage) ([]*transBlock, error) {
	if transIsNull(raw) {
		return nil, nil
	}

	entries, err := transArray(raw, "parts")
	if err != nil {
		return nil, err
	}

	var ret []*transBlock
	for i, entry := range entries {
		obj, err := transObject(entry)
		if err != nil {
			return nil, transUnsupported("a content part is not a JSON object")
		}

		block, err := c.decodePart(i, obj)
		if err != nil {
			return nil, err
		}
		if block == nil {
			continue
		}

		block.toolSignature = geminiThoughtSignature(obj)

		ret = append(ret, block)
	}

	return ret, nil
}

func geminiThoughtSignature(obj map[string]json.RawMessage) string {
	raw, ok := obj["thoughtSignature"]
	if !ok || transIsNull(raw) {
		return ""
	}

	ret, err := transString(raw, "thoughtSignature")
	if err != nil {
		return ""
	}

	return ret
}

func (c *geminiContentCodec) decodePart(idx int,
	obj map[string]json.RawMessage) (*transBlock, error) {

	switch {
	case hasTransField(obj, "text"):
		if err := geminiTextPartFields.check(obj, "content part"); err != nil {
			return nil, err
		}
		if isGeminiThought(obj) {
			return nil, nil
		}
		text, err := transString(obj["text"], "text")
		if err != nil {
			return nil, err
		}
		return &transBlock{kind: transBlockText, text: text}, nil
	case hasTransField(obj, "inlineData"):
		if err := geminiInlineDataFields.check(obj, "content part"); err != nil {
			return nil, err
		}
		return c.decodeInlineData(obj["inlineData"])
	case hasTransField(obj, "functionCall"):
		if err := geminiFunctionCallFields.check(obj, "content part"); err != nil {
			return nil, err
		}
		return c.decodeFunctionCall(idx, obj["functionCall"])
	case hasTransField(obj, "functionResponse"):
		if err := geminiFunctionResponseFields.check(obj, "content part"); err != nil {
			return nil, err
		}
		return c.decodeFunctionResponse(idx, obj["functionResponse"])
	default:
		return nil, transUnsupported(
			"a content part carries content that cannot be translated")
	}
}

func isGeminiThought(obj map[string]json.RawMessage) bool {
	raw, ok := obj["thought"]
	if !ok || transIsNull(raw) {
		return false
	}

	ret, err := transBool(raw, "thought")
	if err != nil {
		return false
	}

	return ret
}

func (c *geminiContentCodec) decodeInlineData(raw json.RawMessage) (*transBlock, error) {
	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("an `inlineData` part is not a JSON object")
	}

	if err := geminiInlineDataInnerFields.check(obj, "`inlineData` part"); err != nil {
		return nil, err
	}

	mediaType, err := transString(obj["mimeType"], "mimeType")
	if err != nil {
		return nil, err
	}

	data, err := transString(obj["data"], "data")
	if err != nil {
		return nil, err
	}

	if len(data) > maxTransImageBytes {
		return nil, transUnsupported("an `inlineData` part is too large")
	}

	return &transBlock{
		kind: transBlockImage,
		image: &transImage{
			mediaType: mediaType,
			data:      data,
		},
	}, nil
}

func (c *geminiContentCodec) decodeFunctionCall(idx int,
	raw json.RawMessage) (*transBlock, error) {

	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("a `functionCall` part is not a JSON object")
	}

	if err := geminiFunctionCallInnerFields.check(obj, "`functionCall` part"); err != nil {
		return nil, err
	}

	name, err := transString(obj["name"], "name")
	if err != nil {
		return nil, err
	}

	input := json.RawMessage(`{}`)
	if cur, ok := obj["args"]; ok && !transIsNull(cur) {
		if input, err = transToolInput(cur); err != nil {
			return nil, err
		}
	}

	ret := &transBlock{
		kind:      transBlockToolCall,
		toolName:  name,
		toolInput: input,
	}

	if cur, ok := obj["id"]; ok && !transIsNull(cur) {
		if ret.toolCallID, err = transString(cur, "id"); err != nil {
			return nil, err
		}
	}

	if ret.toolCallID == "" {
		ret.toolCallID = transSyntheticID(transSyntheticToolIDPrefix,
			name, string(input), strconv.Itoa(idx))
	}

	return ret, nil
}

func (c *geminiContentCodec) decodeFunctionResponse(idx int,
	raw json.RawMessage) (*transBlock, error) {

	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("a `functionResponse` part is not a JSON object")
	}

	if err := geminiFunctionResponseInnerFields.check(obj,
		"`functionResponse` part"); err != nil {
		return nil, err
	}

	name, err := transString(obj["name"], "name")
	if err != nil {
		return nil, err
	}

	ret := &transBlock{
		kind:       transBlockToolResult,
		toolName:   name,
		toolResult: json.RawMessage(`{}`),
	}

	if cur, ok := obj["id"]; ok && !transIsNull(cur) {
		if ret.toolCallID, err = transString(cur, "id"); err != nil {
			return nil, err
		}
	}

	if cur, ok := obj["response"]; ok && !transIsNull(cur) {
		ret.toolResult, ret.isToolError = transUnwrapToolResult(cur)
	}

	if ret.toolCallID == "" {
		ret.toolCallID = transSyntheticID(transSyntheticToolIDPrefix,
			name, strconv.Itoa(idx))
	}

	return ret, nil
}

func (c *geminiContentCodec) decodeTools(raw json.RawMessage) ([]*transTool, error) {
	groups, err := transArray(raw, "tools")
	if err != nil {
		return nil, err
	}

	var ret []*transTool
	for _, group := range groups {
		obj, err := transObject(group)
		if err != nil {
			return nil, transUnsupported("a declared tool group is not a JSON object")
		}

		if err := geminiToolGroupFields.check(obj, "declared tool group"); err != nil {
			return nil, err
		}

		entries, err := transArray(obj["functionDeclarations"], "functionDeclarations")
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			cur, err := transObject(entry)
			if err != nil {
				return nil, transUnsupported("a declared tool is not a JSON object")
			}

			if err := geminiFunctionDeclarationFields.check(cur,
				"declared tool"); err != nil {
				return nil, err
			}

			tool := &transTool{}
			if tool.name, err = transString(cur["name"], "name"); err != nil {
				return nil, err
			}

			if val, ok := cur["description"]; ok && !transIsNull(val) {
				if tool.description, err = transString(val, "description"); err != nil {
					return nil, err
				}
			}

			if val, ok := cur["parameters"]; ok && !transIsNull(val) {
				tool.schema = val
			}

			ret = append(ret, tool)
		}
	}

	return ret, nil
}

func (c *geminiContentCodec) decodeToolConfig(raw json.RawMessage) (*transToolChoice, error) {
	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("the `toolConfig` field is not a JSON object")
	}

	if err := geminiToolConfigFields.check(obj, "`toolConfig` field"); err != nil {
		return nil, err
	}

	cfg, ok := obj["functionCallingConfig"]
	if !ok || transIsNull(cfg) {
		return nil, nil
	}

	inner, err := transObject(cfg)
	if err != nil {
		return nil, transUnsupported(
			"the `functionCallingConfig` field is not a JSON object")
	}

	if err := geminiFunctionCallingConfigFields.check(inner,
		"`functionCallingConfig` field"); err != nil {
		return nil, err
	}

	var names []string
	if cur, ok := inner["allowedFunctionNames"]; ok && !transIsNull(cur) {
		if names, err = transStrings(cur, "allowedFunctionNames"); err != nil {
			return nil, err
		}
	}

	var mode string
	if cur, ok := inner["mode"]; ok && !transIsNull(cur) {
		if mode, err = transString(cur, "mode"); err != nil {
			return nil, err
		}
	}

	ret := &transToolChoice{}

	switch mode {
	case "", "MODE_UNSPECIFIED", "AUTO", "VALIDATED":
		ret.kind = transToolChoiceAuto
	case "NONE":
		ret.kind = transToolChoiceNone
	case "ANY":
		ret.kind = transToolChoiceRequired
	default:
		return nil, transUnsupported(
			"a `functionCallingConfig` mode of `%s` cannot be translated", mode)
	}

	if len(names) == 1 && ret.kind == transToolChoiceRequired {
		ret.kind = transToolChoiceNamed
		ret.name = names[0]
	} else if len(names) > 1 {
		return nil, transUnsupported(
			"an `allowedFunctionNames` list of more than one tool cannot be translated")
	}

	return ret, nil
}

func (c *geminiContentCodec) encodeRequest(req *transRequest,
	o *transEncodeOpts) (map[string]json.RawMessage, error) {

	ret := make(map[string]json.RawMessage)

	contents, err := c.encodeContents(req.messages)
	if err != nil {
		return nil, err
	}
	if err := setRawField(ret, "contents", contents); err != nil {
		return nil, err
	}

	if len(req.system) > 0 {
		parts := make([]any, 0, len(req.system))
		for _, cur := range req.system {
			if cur == "" {
				continue
			}
			parts = append(parts, map[string]any{"text": cur})
		}
		if len(parts) > 0 {
			if err := setRawField(ret, "systemInstruction", map[string]any{
				"parts": parts,
			}); err != nil {
				return nil, err
			}
		}
	}

	generationConfig := make(map[string]any)
	if req.maxOutputTokens > 0 {
		generationConfig["maxOutputTokens"] = req.maxOutputTokens
	}
	if len(req.stopSequences) > 0 {
		generationConfig["stopSequences"] = req.stopSequences
	}
	if req.temperature != nil {
		generationConfig["temperature"] = *req.temperature
	}
	if req.topP != nil {
		generationConfig["topP"] = *req.topP
	}
	if len(generationConfig) > 0 {
		if err := setRawField(ret, "generationConfig", generationConfig); err != nil {
			return nil, err
		}
	}

	if len(req.tools) > 0 {
		declarations := make([]any, 0, len(req.tools))
		for _, tool := range req.tools {
			cur := map[string]any{"name": tool.name}
			if tool.description != "" {
				cur["description"] = tool.description
			}
			if len(tool.schema) > 0 {
				cur["parameters"] = tool.schema
			}
			declarations = append(declarations, cur)
		}
		if err := setRawField(ret, "tools", []any{
			map[string]any{"functionDeclarations": declarations},
		}); err != nil {
			return nil, err
		}
	}

	if err := c.encodeToolConfig(ret, req.toolChoice); err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *geminiContentCodec) encodeToolConfig(root map[string]json.RawMessage,
	choice *transToolChoice) error {

	if choice == nil {
		return nil
	}

	cfg := make(map[string]any)

	switch choice.kind {
	case transToolChoiceAuto:
		cfg["mode"] = "AUTO"
	case transToolChoiceNone:
		cfg["mode"] = "NONE"
	case transToolChoiceRequired:
		cfg["mode"] = "ANY"
	case transToolChoiceNamed:
		cfg["mode"] = "ANY"
		cfg["allowedFunctionNames"] = []string{choice.name}
	default:
		return nil
	}

	return setRawField(root, "toolConfig", map[string]any{
		"functionCallingConfig": cfg,
	})
}

func (c *geminiContentCodec) encodeContents(msgs []*transMessage) ([]any, error) {
	ret := make([]any, 0, len(msgs))

	for _, msg := range msgs {
		parts, err := c.encodeParts(msg.blocks)
		if err != nil {
			return nil, err
		}
		if len(parts) == 0 {
			continue
		}

		role := msg.role
		if role == roleAssistant {
			role = roleModel
		}

		ret = append(ret, map[string]any{
			"role":  role,
			"parts": parts,
		})
	}

	return ret, nil
}

func (c *geminiContentCodec) encodeParts(blocks []*transBlock) ([]any, error) {
	var ret []any

	for _, block := range blocks {
		var part map[string]any

		switch block.kind {
		case transBlockText:
			if block.text == "" {
				continue
			}
			part = map[string]any{"text": block.text}
		case transBlockImage:
			if block.image.url != "" {
				return nil, transUnsupported(
					"an image referenced by a URL cannot be translated to the GEMINI protocol")
			}
			part = map[string]any{
				"inlineData": map[string]any{
					"mimeType": block.image.mediaType,
					"data":     block.image.data,
				},
			}
		case transBlockToolCall:
			call := map[string]any{
				"name": block.toolName,
				"args": block.toolInput,
			}
			if id := geminiToolCallID(block.toolCallID); id != "" {
				call["id"] = id
			}
			part = map[string]any{"functionCall": call}
		case transBlockToolResult:
			if block.toolName == "" {
				return nil, transUnsupported(
					"a tool result whose tool is unknown cannot be translated " +
						"to the GEMINI protocol")
			}
			response, err := transToolResultObject(block.toolResult, block.isToolError)
			if err != nil {
				return nil, err
			}
			resp := map[string]any{
				"name":     block.toolName,
				"response": response,
			}
			if id := geminiToolCallID(block.toolCallID); id != "" {
				resp["id"] = id
			}
			part = map[string]any{"functionResponse": resp}
		default:
			continue
		}

		if block.toolSignature != "" {
			part["thoughtSignature"] = block.toolSignature
		}

		ret = append(ret, part)
	}

	return ret, nil
}

func geminiToolCallID(arg string) string {
	if isTransSyntheticToolID(arg) {
		return ""
	}
	return arg
}

func isTransSyntheticToolID(arg string) bool {
	return len(arg) > len(transSyntheticToolIDPrefix) &&
		arg[:len(transSyntheticToolIDPrefix)] == transSyntheticToolIDPrefix
}

type geminiResponseEnvelope struct {
	Candidates []struct {
		Content struct {
			Parts []json.RawMessage `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`

	PromptFeedback *struct {
		BlockReason string `json:"blockReason"`
	} `json:"promptFeedback"`

	UsageMetadata *geminiUsage `json:"usageMetadata"`

	ModelVersion string `json:"modelVersion"`
	ResponseID   string `json:"responseId"`
}

type geminiUsage struct {
	PromptTokenCount        uint64 `json:"promptTokenCount"`
	CandidatesTokenCount    uint64 `json:"candidatesTokenCount"`
	ThoughtsTokenCount      uint64 `json:"thoughtsTokenCount"`
	TotalTokenCount         uint64 `json:"totalTokenCount"`
	CachedContentTokenCount uint64 `json:"cachedContentTokenCount"`
}

func (u *geminiUsage) toTransUsage() transUsage {
	return transUsage{
		inputTokens:     u.PromptTokenCount,
		outputTokens:    u.CandidatesTokenCount + u.ThoughtsTokenCount,
		reasoningTokens: u.ThoughtsTokenCount,
		cacheReadTokens: u.CachedContentTokenCount,
		totalTokens:     u.TotalTokenCount,
		isSet:           true,
	}
}

func encodeGeminiUsage(usage transUsage) map[string]any {
	ret := map[string]any{
		"promptTokenCount":     usage.inputTokens,
		"candidatesTokenCount": usage.outputTokens - usage.reasoningTokens,
		"totalTokenCount":      usage.total(),
	}

	if usage.reasoningTokens > 0 {
		ret["thoughtsTokenCount"] = usage.reasoningTokens
	}
	if usage.cacheReadTokens > 0 {
		ret["cachedContentTokenCount"] = usage.cacheReadTokens
	}

	return ret
}

func (c *geminiContentCodec) decodeResponse(body []byte) (*transResponse, error) {
	env := &geminiResponseEnvelope{}
	if err := json.Unmarshal(body, env); err != nil {
		return nil, transInvalidResponse(
			"the upstream response is not a valid Gemini response")
	}

	ret := &transResponse{
		id:    env.ResponseID,
		model: env.ModelVersion,
	}

	if env.UsageMetadata != nil {
		ret.usage = env.UsageMetadata.toTransUsage()
	}

	if len(env.Candidates) == 0 {
		reason := "the inference upstream returned no candidate"
		if env.PromptFeedback != nil && env.PromptFeedback.BlockReason != "" {
			reason = "the inference upstream blocked the prompt: " +
				env.PromptFeedback.BlockReason
		}
		return ret, transInvalidResponse("%s", reason)
	}

	candidate := env.Candidates[0]

	ret.finishReason = geminiFinishReason(candidate.FinishReason)
	if candidate.FinishReason != "" && ret.finishReason == transFinishUnset {
		return ret, transInvalidResponse(
			"the inference upstream reported a `%s` finish reason that cannot be translated",
			candidate.FinishReason)
	}

	blocks, err := c.decodeResponseParts(candidate.Content.Parts)
	if err != nil {
		return ret, err
	}
	ret.blocks = blocks

	if ret.finishReason == transFinishStop {
		for _, block := range blocks {
			if block.kind == transBlockToolCall {
				ret.finishReason = transFinishToolCall
				break
			}
		}
	}

	return ret, nil
}

func (c *geminiContentCodec) decodeResponseParts(
	entries []json.RawMessage) ([]*transBlock, error) {

	var ret []*transBlock

	for i, entry := range entries {
		obj, err := transObject(entry)
		if err != nil {
			continue
		}

		signature := geminiThoughtSignature(obj)

		switch {
		case hasTransField(obj, "text"):
			if isGeminiThought(obj) {
				continue
			}
			text, err := transString(obj["text"], "text")
			if err != nil {
				continue
			}
			ret = append(ret, &transBlock{kind: transBlockText, text: text})
		case hasTransField(obj, "functionCall"):
			block, err := c.decodeFunctionCall(i, obj["functionCall"])
			if err != nil {
				return nil, transInvalidResponse(
					"the inference upstream returned a tool call that cannot be translated")
			}
			block.toolSignature = signature
			ret = append(ret, block)
		}
	}

	return ret, nil
}

func geminiFinishReason(arg string) transFinishReason {
	switch arg {
	case "":
		return transFinishUnset
	case "STOP":
		return transFinishStop
	case "MAX_TOKENS":
		return transFinishLength
	case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII",
		"IMAGE_SAFETY", "LANGUAGE", "IMAGE_PROHIBITED_CONTENT":
		return transFinishContentFilter
	default:
		return transFinishUnset
	}
}

func toGeminiFinishReason(arg transFinishReason) string {
	switch arg {
	case transFinishStop, transFinishStopSequence, transFinishToolCall:
		return "STOP"
	case transFinishLength:
		return "MAX_TOKENS"
	case transFinishContentFilter:
		return "SAFETY"
	default:
		return ""
	}
}

func (c *geminiContentCodec) encodeResponse(resp *transResponse,
	o *transEncodeOpts) ([]byte, error) {

	parts, err := c.encodeParts(resp.blocks)
	if err != nil {
		return nil, err
	}
	if parts == nil {
		parts = []any{}
	}

	candidate := map[string]any{
		"content": map[string]any{
			"role":  roleModel,
			"parts": parts,
		},
		"index": 0,
	}
	if val := toGeminiFinishReason(resp.finishReason); val != "" {
		candidate["finishReason"] = val
	}

	ret := map[string]any{
		"candidates":   []any{candidate},
		"modelVersion": transResponseModel(resp.model, o),
		"responseId":   newGeminiResponseID(),
	}

	if resp.usage.isSet {
		ret["usageMetadata"] = encodeGeminiUsage(resp.usage)
	}

	return json.Marshal(ret)
}

func newGeminiResponseID() string {
	return utilrand.GetRandomStringLowercase(24)
}

func (c *geminiContentCodec) newStreamDecoder() transStreamDecoder {
	return &geminiStreamDecoder{}
}

func (c *geminiContentCodec) newStreamEncoder(o *transEncodeOpts) transStreamEncoder {
	return &geminiStreamEncoder{
		id:    newGeminiResponseID(),
		model: o.model,
	}
}

type geminiStreamDecoder struct {
	isStarted  bool
	isFinished bool

	codec geminiContentCodec

	id    string
	model string

	finishReason transFinishReason
	usage        transUsage

	toolIndex int
}

func (d *geminiStreamDecoder) decode(eventType string, data []byte) ([]*transEvent, error) {
	env := &geminiResponseEnvelope{}
	if err := json.Unmarshal(data, env); err != nil {
		return nil, nil
	}

	var ret []*transEvent

	if env.ResponseID != "" {
		d.id = env.ResponseID
	}
	if env.ModelVersion != "" {
		d.model = env.ModelVersion
	}

	if !d.isStarted {
		d.isStarted = true
		ret = append(ret, &transEvent{
			kind:  transEventStart,
			id:    d.id,
			model: d.model,
		})
	}

	if env.UsageMetadata != nil {
		d.usage.merge(env.UsageMetadata.toTransUsage())
	}

	if env.PromptFeedback != nil && env.PromptFeedback.BlockReason != "" {
		return nil, transInvalidResponse(
			"the inference upstream blocked the prompt: %s",
			env.PromptFeedback.BlockReason)
	}

	if len(env.Candidates) == 0 {
		return ret, nil
	}

	candidate := env.Candidates[0]

	if candidate.FinishReason != "" {
		d.finishReason = geminiFinishReason(candidate.FinishReason)
		if d.finishReason == transFinishUnset {
			return nil, transInvalidResponse(
				"the inference upstream reported a `%s` finish reason "+
					"that cannot be translated", candidate.FinishReason)
		}
	}

	for i, entry := range candidate.Content.Parts {
		obj, err := transObject(entry)
		if err != nil {
			continue
		}

		switch {
		case hasTransField(obj, "text"):
			if isGeminiThought(obj) {
				continue
			}
			text, err := transString(obj["text"], "text")
			if err != nil || text == "" {
				continue
			}
			ret = append(ret, &transEvent{kind: transEventTextDelta, text: text})
		case hasTransField(obj, "functionCall"):
			block, err := d.codec.decodeFunctionCall(i, obj["functionCall"])
			if err != nil {
				return nil, transInvalidResponse(
					"the inference upstream returned a tool call that cannot be translated")
			}

			index := d.toolIndex
			d.toolIndex++

			ret = append(ret,
				&transEvent{
					kind:          transEventToolCallStart,
					index:         index,
					toolCallID:    block.toolCallID,
					toolName:      block.toolName,
					toolSignature: geminiThoughtSignature(obj),
				},
				&transEvent{
					kind:  transEventToolCallDelta,
					index: index,
					text:  string(block.toolInput),
				})

			if d.finishReason == transFinishUnset || d.finishReason == transFinishStop {
				d.finishReason = transFinishToolCall
			}
		}
	}

	return ret, nil
}

func (d *geminiStreamDecoder) finish() []*transEvent {
	if d.isFinished {
		return nil
	}
	d.isFinished = true

	return []*transEvent{{
		kind:         transEventFinish,
		id:           d.id,
		model:        d.model,
		finishReason: d.finishReason,
		usage:        d.usage,
	}}
}

type geminiStreamToolCall struct {
	index int
	id    string
	name  string
	input []byte
}

type geminiStreamEncoder struct {
	id    string
	model string

	toolCalls []*geminiStreamToolCall
}

func (e *geminiStreamEncoder) chunk(parts []any, finishReason string,
	usage map[string]any) ([]byte, error) {

	candidate := map[string]any{
		"content": map[string]any{
			"role":  roleModel,
			"parts": parts,
		},
		"index": 0,
	}
	if finishReason != "" {
		candidate["finishReason"] = finishReason
	}

	ret := map[string]any{
		"candidates":   []any{candidate},
		"modelVersion": e.model,
		"responseId":   e.id,
	}
	if usage != nil {
		ret["usageMetadata"] = usage
	}

	return sseEventOf("", ret)
}

func (e *geminiStreamEncoder) encode(ev *transEvent) ([]byte, error) {
	switch ev.kind {
	case transEventStart:
		if ev.model != "" {
			e.model = ev.model
		}
		return nil, nil
	case transEventTextDelta:
		return e.chunk([]any{map[string]any{"text": ev.text}}, "", nil)
	case transEventToolCallStart:
		e.toolCalls = append(e.toolCalls, &geminiStreamToolCall{
			index: ev.index,
			id:    ev.toolCallID,
			name:  ev.toolName,
		})
		return nil, nil
	case transEventToolCallDelta:
		return nil, appendTransToolInput(e.toolCalls, ev,
			func(cur *geminiStreamToolCall) int { return cur.index },
			func(cur *geminiStreamToolCall) *[]byte { return &cur.input })
	case transEventFinish:
		return e.encodeFinish(ev)
	default:
		return nil, nil
	}
}

func (e *geminiStreamEncoder) encodeFinish(ev *transEvent) ([]byte, error) {
	var parts []any

	for _, cur := range e.toolCalls {
		input := json.RawMessage(cur.input)
		if len(input) == 0 {
			input = json.RawMessage(`{}`)
		}
		if _, err := transToolInput(input); err != nil {
			return nil, transInvalidResponse(
				"the inference upstream sent a tool call whose arguments are not a JSON object")
		}

		call := map[string]any{
			"name": cur.name,
			"args": input,
		}
		if id := geminiToolCallID(cur.id); id != "" {
			call["id"] = id
		}
		parts = append(parts, map[string]any{"functionCall": call})
	}

	if parts == nil {
		parts = []any{}
	}

	finishReason := toGeminiFinishReason(ev.finishReason)
	if finishReason == "" {
		finishReason = "STOP"
	}

	var usage map[string]any
	if ev.usage.isSet {
		usage = encodeGeminiUsage(ev.usage)
	}

	return e.chunk(parts, finishReason, usage)
}

func (e *geminiStreamEncoder) encodeError(message string) []byte {
	ret, err := sseEventOf("", &geminiErrorResponse{
		Error: &geminiError{
			Code:    http.StatusBadGateway,
			Message: message,
			Status:  getGeminiErrorStatus(http.StatusBadGateway),
		},
	})
	if err != nil {
		return nil
	}

	return ret
}
