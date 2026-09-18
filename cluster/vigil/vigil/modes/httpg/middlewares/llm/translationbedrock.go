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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
)

const maxBedrockToolIDLen = 64

var bedrockConverseFields = newTransFields([]string{
	"messages", "system", "inferenceConfig", "toolConfig",
}, nil)

var bedrockInferenceConfigFields = newTransFields([]string{
	"maxTokens", "temperature", "topP", "stopSequences",
}, nil)

var bedrockMessageFields = newTransFields([]string{"role", "content"}, nil)

var bedrockTextBlockFields = newTransFields([]string{"text"}, nil)

var bedrockImageBlockFields = newTransFields([]string{"image"}, nil)

var bedrockImageFields = newTransFields([]string{"format", "source"}, nil)

var bedrockToolUseBlockFields = newTransFields([]string{"toolUse"}, nil)

var bedrockToolUseFields = newTransFields([]string{
	"toolUseId", "name", "input",
}, nil)

var bedrockToolResultBlockFields = newTransFields([]string{"toolResult"}, nil)

var bedrockToolResultFields = newTransFields([]string{
	"toolUseId", "content", "status",
}, nil)

var bedrockToolConfigFields = newTransFields([]string{"tools", "toolChoice"}, nil)

var bedrockToolFields = newTransFields([]string{"toolSpec"}, nil)

var bedrockToolSpecFields = newTransFields([]string{
	"name", "description", "inputSchema",
}, nil)

var bedrockSystemBlockFields = newTransFields([]string{"text"}, nil)

type bedrockConverseCodec struct{}

func (c *bedrockConverseCodec) protocol() corev1.Service_Spec_Config_LLM_Protocol {
	return corev1.Service_Spec_Config_LLM_BEDROCK
}

func (c *bedrockConverseCodec) route() corev1.RequestContext_Request_LLM_Route {
	return corev1.RequestContext_Request_LLM_CONVERSE
}

func (c *bedrockConverseCodec) streamMediaType() string {
	return transEventStreamMediaType
}

func (c *bedrockConverseCodec) decodeRequest(body []byte) (*transRequest, error) {
	root, err := transObject(body)
	if err != nil {
		return nil, transUnsupported("the request body is not a JSON object")
	}

	if err := bedrockConverseFields.check(root, "Bedrock Converse request"); err != nil {
		return nil, err
	}

	ret := &transRequest{}

	if raw, ok := root["inferenceConfig"]; ok && !transIsNull(raw) {
		if err := c.decodeInferenceConfig(ret, raw); err != nil {
			return nil, err
		}
	}

	if raw, ok := root["system"]; ok && !transIsNull(raw) {
		if err := c.decodeSystem(ret, raw); err != nil {
			return nil, err
		}
	}

	if raw, ok := root["toolConfig"]; ok && !transIsNull(raw) {
		if err := c.decodeToolConfig(ret, raw); err != nil {
			return nil, err
		}
	}

	if err := c.decodeMessages(ret, root["messages"]); err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *bedrockConverseCodec) decodeInferenceConfig(ret *transRequest,
	raw json.RawMessage) error {

	obj, err := transObject(raw)
	if err != nil {
		return transUnsupported("the `inferenceConfig` field is not a JSON object")
	}

	if err := bedrockInferenceConfigFields.check(obj, "`inferenceConfig` field"); err != nil {
		return err
	}

	for key, cur := range obj {
		if transIsNull(cur) {
			continue
		}

		var err error
		switch key {
		case "maxTokens":
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
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *bedrockConverseCodec) decodeSystem(ret *transRequest, raw json.RawMessage) error {
	entries, err := transArray(raw, "system")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		obj, err := transObject(entry)
		if err != nil {
			return transUnsupported("a `system` block is not a JSON object")
		}

		if err := bedrockSystemBlockFields.check(obj, "`system` block"); err != nil {
			return err
		}

		text, err := transString(obj["text"], "text")
		if err != nil {
			return err
		}

		ret.system = append(ret.system, text)
	}

	return nil
}

func (c *bedrockConverseCodec) decodeMessages(ret *transRequest, raw json.RawMessage) error {
	if transIsNull(raw) {
		return transUnsupported("the request declares no messages")
	}

	entries, err := transArray(raw, "messages")
	if err != nil {
		return err
	}

	for _, entry := range entries {
		obj, err := transObject(entry)
		if err != nil {
			return transUnsupported("a message is not a JSON object")
		}

		if err := bedrockMessageFields.check(obj, "message"); err != nil {
			return err
		}

		role, err := transString(obj["role"], "role")
		if err != nil {
			return err
		}

		switch role {
		case roleUser, roleAssistant:
		default:
			return transUnsupported("a message of the `%s` role cannot be translated", role)
		}

		blocks, err := c.decodeBlocks(obj["content"])
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

func (c *bedrockConverseCodec) decodeBlocks(raw json.RawMessage) ([]*transBlock, error) {
	if transIsNull(raw) {
		return nil, nil
	}

	entries, err := transArray(raw, "content")
	if err != nil {
		return nil, err
	}

	var ret []*transBlock
	for _, entry := range entries {
		obj, err := transObject(entry)
		if err != nil {
			return nil, transUnsupported("a content block is not a JSON object")
		}

		block, err := c.decodeBlock(obj)
		if err != nil {
			return nil, err
		}

		ret = append(ret, block)
	}

	return ret, nil
}

func (c *bedrockConverseCodec) decodeBlock(
	obj map[string]json.RawMessage) (*transBlock, error) {

	switch {
	case hasTransField(obj, "text"):
		if err := bedrockTextBlockFields.check(obj, "content block"); err != nil {
			return nil, err
		}
		text, err := transString(obj["text"], "text")
		if err != nil {
			return nil, err
		}
		return &transBlock{kind: transBlockText, text: text}, nil
	case hasTransField(obj, "image"):
		if err := bedrockImageBlockFields.check(obj, "content block"); err != nil {
			return nil, err
		}
		return c.decodeImage(obj["image"])
	case hasTransField(obj, "toolUse"):
		if err := bedrockToolUseBlockFields.check(obj, "content block"); err != nil {
			return nil, err
		}
		return c.decodeToolUse(obj["toolUse"])
	case hasTransField(obj, "toolResult"):
		if err := bedrockToolResultBlockFields.check(obj, "content block"); err != nil {
			return nil, err
		}
		return c.decodeToolResult(obj["toolResult"])
	default:
		return nil, transUnsupported(
			"a content block carries content that cannot be translated")
	}
}

func (c *bedrockConverseCodec) decodeImage(raw json.RawMessage) (*transBlock, error) {
	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("an `image` block is not a JSON object")
	}

	if err := bedrockImageFields.check(obj, "`image` block"); err != nil {
		return nil, err
	}

	format, err := transString(obj["format"], "format")
	if err != nil {
		return nil, err
	}

	source, err := transObject(obj["source"])
	if err != nil {
		return nil, transUnsupported("an `image` block declares no `source`")
	}

	raw, ok := source["bytes"]
	if !ok || transIsNull(raw) {
		return nil, transUnsupported(
			"an `image` block whose source is not inline bytes cannot be translated")
	}

	data, err := transString(raw, "bytes")
	if err != nil {
		return nil, err
	}

	if len(data) > maxTransImageBytes {
		return nil, transUnsupported("an `image` block is too large")
	}

	return &transBlock{
		kind: transBlockImage,
		image: &transImage{
			mediaType: "image/" + format,
			data:      data,
		},
	}, nil
}

func (c *bedrockConverseCodec) decodeToolUse(raw json.RawMessage) (*transBlock, error) {
	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("a `toolUse` block is not a JSON object")
	}

	if err := bedrockToolUseFields.check(obj, "`toolUse` block"); err != nil {
		return nil, err
	}

	id, err := transString(obj["toolUseId"], "toolUseId")
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, transUnsupported("a `toolUse` block declares no `toolUseId`")
	}

	name, err := transString(obj["name"], "name")
	if err != nil {
		return nil, err
	}

	input := json.RawMessage(`{}`)
	if cur, ok := obj["input"]; ok && !transIsNull(cur) {
		if input, err = transToolInput(cur); err != nil {
			return nil, err
		}
	}

	return &transBlock{
		kind:       transBlockToolCall,
		toolCallID: id,
		toolName:   name,
		toolInput:  input,
	}, nil
}

func (c *bedrockConverseCodec) decodeToolResult(raw json.RawMessage) (*transBlock, error) {
	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("a `toolResult` block is not a JSON object")
	}

	if err := bedrockToolResultFields.check(obj, "`toolResult` block"); err != nil {
		return nil, err
	}

	id, err := transString(obj["toolUseId"], "toolUseId")
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, transUnsupported("a `toolResult` block declares no `toolUseId`")
	}

	ret := &transBlock{
		kind:       transBlockToolResult,
		toolCallID: id,
		toolResult: json.RawMessage(`""`),
	}

	if cur, ok := obj["status"]; ok && !transIsNull(cur) {
		status, err := transString(cur, "status")
		if err != nil {
			return nil, err
		}
		ret.isToolError = status == "error"
	}

	entries, err := transArray(obj["content"], "content")
	if err != nil {
		return nil, err
	}

	var texts []string
	for _, entry := range entries {
		cur, err := transObject(entry)
		if err != nil {
			return nil, transUnsupported("a `toolResult` content block is not a JSON object")
		}

		switch {
		case hasTransField(cur, "json"):
			ret.toolResult = cur["json"]
			return ret, nil
		case hasTransField(cur, "text"):
			text, err := transString(cur["text"], "text")
			if err != nil {
				return nil, err
			}
			texts = append(texts, text)
		default:
			return nil, transUnsupported(
				"a `toolResult` content block carries content that cannot be translated")
		}
	}

	ret.toolResult = transToolResultOf(transJoinLines(texts))

	return ret, nil
}

func (c *bedrockConverseCodec) decodeToolConfig(ret *transRequest,
	raw json.RawMessage) error {

	obj, err := transObject(raw)
	if err != nil {
		return transUnsupported("the `toolConfig` field is not a JSON object")
	}

	if err := bedrockToolConfigFields.check(obj, "`toolConfig` field"); err != nil {
		return err
	}

	if cur, ok := obj["tools"]; ok && !transIsNull(cur) {
		entries, err := transArray(cur, "tools")
		if err != nil {
			return err
		}

		for _, entry := range entries {
			tool, err := c.decodeTool(entry)
			if err != nil {
				return err
			}
			ret.tools = append(ret.tools, tool)
		}
	}

	if cur, ok := obj["toolChoice"]; ok && !transIsNull(cur) {
		if ret.toolChoice, err = c.decodeToolChoice(cur); err != nil {
			return err
		}
	}

	return nil
}

func (c *bedrockConverseCodec) decodeTool(entry json.RawMessage) (*transTool, error) {
	obj, err := transObject(entry)
	if err != nil {
		return nil, transUnsupported("a declared tool is not a JSON object")
	}

	if err := bedrockToolFields.check(obj, "declared tool"); err != nil {
		return nil, err
	}

	spec, err := transObject(obj["toolSpec"])
	if err != nil {
		return nil, transUnsupported("a declared tool declares no `toolSpec`")
	}

	if err := bedrockToolSpecFields.check(spec, "declared tool"); err != nil {
		return nil, err
	}

	ret := &transTool{}
	if ret.name, err = transString(spec["name"], "name"); err != nil {
		return nil, err
	}

	if cur, ok := spec["description"]; ok && !transIsNull(cur) {
		if ret.description, err = transString(cur, "description"); err != nil {
			return nil, err
		}
	}

	if cur, ok := spec["inputSchema"]; ok && !transIsNull(cur) {
		schema, err := transObject(cur)
		if err != nil {
			return nil, transUnsupported("a declared tool declares an invalid `inputSchema`")
		}
		if val, ok := schema["json"]; ok && !transIsNull(val) {
			ret.schema = val
		} else {
			return nil, transUnsupported(
				"a declared tool whose `inputSchema` is not a JSON Schema cannot be translated")
		}
	}

	return ret, nil
}

func (c *bedrockConverseCodec) decodeToolChoice(
	raw json.RawMessage) (*transToolChoice, error) {

	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("the `toolChoice` field is not a JSON object")
	}

	switch {
	case hasTransField(obj, "auto"):
		return &transToolChoice{kind: transToolChoiceAuto}, nil
	case hasTransField(obj, "any"):
		return &transToolChoice{kind: transToolChoiceRequired}, nil
	case hasTransField(obj, "tool"):
		inner, err := transObject(obj["tool"])
		if err != nil {
			return nil, transUnsupported("the `toolChoice` field declares no tool")
		}
		name, err := transString(inner["name"], "name")
		if err != nil {
			return nil, err
		}
		return &transToolChoice{kind: transToolChoiceNamed, name: name}, nil
	default:
		return nil, transUnsupported("the `toolChoice` field cannot be translated")
	}
}

func (c *bedrockConverseCodec) encodeRequest(req *transRequest,
	o *transEncodeOpts) (map[string]json.RawMessage, error) {

	ret := make(map[string]json.RawMessage)

	msgs, err := c.encodeMessages(req.messages)
	if err != nil {
		return nil, err
	}
	if err := setRawField(ret, "messages", msgs); err != nil {
		return nil, err
	}

	if len(req.system) > 0 {
		blocks := make([]any, 0, len(req.system))
		for _, cur := range req.system {
			if cur == "" {
				continue
			}
			blocks = append(blocks, map[string]any{"text": cur})
		}
		if len(blocks) > 0 {
			if err := setRawField(ret, "system", blocks); err != nil {
				return nil, err
			}
		}
	}

	inferenceConfig := make(map[string]any)
	if req.maxOutputTokens > 0 {
		inferenceConfig["maxTokens"] = req.maxOutputTokens
	}
	if len(req.stopSequences) > 0 {
		inferenceConfig["stopSequences"] = req.stopSequences
	}
	if req.temperature != nil {
		inferenceConfig["temperature"] = *req.temperature
	}
	if req.topP != nil {
		inferenceConfig["topP"] = *req.topP
	}
	if len(inferenceConfig) > 0 {
		if err := setRawField(ret, "inferenceConfig", inferenceConfig); err != nil {
			return nil, err
		}
	}

	if err := c.encodeToolConfig(ret, req); err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *bedrockConverseCodec) encodeToolConfig(root map[string]json.RawMessage,
	req *transRequest) error {

	if len(req.tools) == 0 {
		return nil
	}

	tools := make([]any, 0, len(req.tools))
	for _, tool := range req.tools {
		if err := checkBedrockToolName(tool.name); err != nil {
			return err
		}

		spec := map[string]any{"name": tool.name}
		if tool.description != "" {
			spec["description"] = tool.description
		}

		schema := tool.schema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		spec["inputSchema"] = map[string]any{"json": schema}

		tools = append(tools, map[string]any{"toolSpec": spec})
	}

	cfg := map[string]any{"tools": tools}

	if choice := req.toolChoice; choice != nil {
		switch choice.kind {
		case transToolChoiceAuto:
			cfg["toolChoice"] = map[string]any{"auto": map[string]any{}}
		case transToolChoiceRequired:
			cfg["toolChoice"] = map[string]any{"any": map[string]any{}}
		case transToolChoiceNamed:
			cfg["toolChoice"] = map[string]any{
				"tool": map[string]any{"name": choice.name},
			}
		case transToolChoiceNone:
			return nil
		}
	}

	return setRawField(root, "toolConfig", cfg)
}

func checkBedrockToolName(arg string) error {
	if arg == "" || len(arg) > maxBedrockToolIDLen {
		return transUnsupported(
			"a tool name of %d characters cannot be translated to the BEDROCK protocol",
			len(arg))
	}

	for i := 0; i < len(arg); i++ {
		if !isBedrockNameChar(arg[i]) {
			return transUnsupported(
				"the `%s` tool name cannot be translated to the BEDROCK protocol", arg)
		}
	}

	return nil
}

func isBedrockNameChar(arg byte) bool {
	switch {
	case arg >= 'a' && arg <= 'z':
		return true
	case arg >= 'A' && arg <= 'Z':
		return true
	case arg >= '0' && arg <= '9':
		return true
	case arg == '_' || arg == '-':
		return true
	default:
		return false
	}
}

func bedrockToolCallID(arg string) string {
	if arg != "" && len(arg) <= maxBedrockToolIDLen {
		isValid := true
		for i := 0; i < len(arg); i++ {
			if !isBedrockNameChar(arg[i]) {
				isValid = false
				break
			}
		}
		if isValid {
			return arg
		}
	}

	return transSyntheticID("oct_", arg)
}

func (c *bedrockConverseCodec) encodeMessages(msgs []*transMessage) ([]any, error) {
	ret := make([]any, 0, len(msgs))

	for _, msg := range msgs {
		blocks, err := c.encodeBlocks(msg.blocks)
		if err != nil {
			return nil, err
		}
		if len(blocks) == 0 {
			continue
		}

		ret = append(ret, map[string]any{
			"role":    msg.role,
			"content": blocks,
		})
	}

	return ret, nil
}

func (c *bedrockConverseCodec) encodeBlocks(blocks []*transBlock) ([]any, error) {
	var results []any
	var rest []any

	for _, block := range blocks {
		switch block.kind {
		case transBlockText:
			if block.text == "" {
				continue
			}
			rest = append(rest, map[string]any{"text": block.text})
		case transBlockImage:
			if block.image.url != "" {
				return nil, transUnsupported(
					"an image referenced by a URL cannot be translated to the BEDROCK protocol")
			}
			format, ok := bedrockImageFormat(block.image.mediaType)
			if !ok {
				return nil, transUnsupported(
					"an image of the `%s` media type cannot be translated "+
						"to the BEDROCK protocol", block.image.mediaType)
			}
			rest = append(rest, map[string]any{
				"image": map[string]any{
					"format": format,
					"source": map[string]any{"bytes": block.image.data},
				},
			})
		case transBlockToolCall:
			if err := checkBedrockToolName(block.toolName); err != nil {
				return nil, err
			}
			rest = append(rest, map[string]any{
				"toolUse": map[string]any{
					"toolUseId": bedrockToolCallID(block.toolCallID),
					"name":      block.toolName,
					"input":     block.toolInput,
				},
			})
		case transBlockToolResult:
			cur := map[string]any{
				"toolUseId": bedrockToolCallID(block.toolCallID),
				"content":   []any{bedrockToolResultContent(block.toolResult)},
			}
			if block.isToolError {
				cur["status"] = "error"
			} else {
				cur["status"] = "success"
			}
			results = append(results, map[string]any{"toolResult": cur})
		}
	}

	return append(results, rest...), nil
}

func bedrockToolResultContent(raw json.RawMessage) map[string]any {
	if len(raw) > 0 && raw[0] == '{' {
		return map[string]any{"json": raw}
	}

	return map[string]any{"text": transToolResultText(raw)}
}

func bedrockImageFormat(mediaType string) (string, bool) {
	switch mediaType {
	case "image/png":
		return "png", true
	case "image/jpeg", "image/jpg":
		return "jpeg", true
	case "image/gif":
		return "gif", true
	case "image/webp":
		return "webp", true
	default:
		return "", false
	}
}

type bedrockResponseEnvelope struct {
	Output struct {
		Message struct {
			Content []json.RawMessage `json:"content"`
		} `json:"message"`
	} `json:"output"`

	StopReason string `json:"stopReason"`

	Usage *bedrockUsage `json:"usage"`
}

type bedrockUsage struct {
	InputTokens  uint64 `json:"inputTokens"`
	OutputTokens uint64 `json:"outputTokens"`
	TotalTokens  uint64 `json:"totalTokens"`

	CacheReadInputTokens  uint64 `json:"cacheReadInputTokens"`
	CacheWriteInputTokens uint64 `json:"cacheWriteInputTokens"`
}

func (u *bedrockUsage) toTransUsage() transUsage {
	return transUsage{
		inputTokens:         u.InputTokens,
		outputTokens:        u.OutputTokens,
		totalTokens:         u.TotalTokens,
		cacheReadTokens:     u.CacheReadInputTokens,
		cacheCreationTokens: u.CacheWriteInputTokens,
		isSet:               true,
	}
}

func encodeBedrockUsage(usage transUsage) map[string]any {
	ret := map[string]any{
		"inputTokens":  usage.inputTokens,
		"outputTokens": usage.outputTokens,
		"totalTokens":  usage.total(),
	}

	if usage.cacheReadTokens > 0 {
		ret["cacheReadInputTokens"] = usage.cacheReadTokens
	}
	if usage.cacheCreationTokens > 0 {
		ret["cacheWriteInputTokens"] = usage.cacheCreationTokens
	}

	return ret
}

func (c *bedrockConverseCodec) decodeResponse(body []byte) (*transResponse, error) {
	env := &bedrockResponseEnvelope{}
	if err := json.Unmarshal(body, env); err != nil {
		return nil, transInvalidResponse(
			"the upstream response is not a valid Bedrock response")
	}

	ret := &transResponse{
		finishReason: bedrockFinishReason(env.StopReason),
	}

	if env.Usage != nil {
		ret.usage = env.Usage.toTransUsage()
	}

	if env.StopReason != "" && ret.finishReason == transFinishUnset {
		return ret, transInvalidResponse(
			"the inference upstream reported a `%s` stop reason that cannot be translated",
			env.StopReason)
	}

	for _, entry := range env.Output.Message.Content {
		obj, err := transObject(entry)
		if err != nil {
			continue
		}

		switch {
		case hasTransField(obj, "text"):
			text, err := transString(obj["text"], "text")
			if err != nil {
				continue
			}
			ret.blocks = append(ret.blocks, &transBlock{
				kind: transBlockText,
				text: text,
			})
		case hasTransField(obj, "toolUse"):
			block, err := c.decodeToolUse(obj["toolUse"])
			if err != nil {
				return ret, transInvalidResponse(
					"the inference upstream returned a tool call that cannot be translated")
			}
			ret.blocks = append(ret.blocks, block)
		}
	}

	return ret, nil
}

func bedrockFinishReason(arg string) transFinishReason {
	switch arg {
	case "":
		return transFinishUnset
	case "end_turn":
		return transFinishStop
	case "stop_sequence":
		return transFinishStopSequence
	case "max_tokens", "model_context_window_exceeded":
		return transFinishLength
	case "tool_use":
		return transFinishToolCall
	case "content_filtered", "guardrail_intervened":
		return transFinishContentFilter
	default:
		return transFinishUnset
	}
}

func toBedrockFinishReason(arg transFinishReason) string {
	switch arg {
	case transFinishStop:
		return "end_turn"
	case transFinishStopSequence:
		return "stop_sequence"
	case transFinishLength:
		return "max_tokens"
	case transFinishToolCall:
		return "tool_use"
	case transFinishContentFilter:
		return "content_filtered"
	default:
		return ""
	}
}

func (c *bedrockConverseCodec) encodeResponse(resp *transResponse,
	o *transEncodeOpts) ([]byte, error) {

	content, err := c.encodeBlocks(resp.blocks)
	if err != nil {
		return nil, err
	}
	if content == nil {
		content = []any{}
	}

	ret := map[string]any{
		"output": map[string]any{
			"message": map[string]any{
				"role":    roleAssistant,
				"content": content,
			},
		},
	}

	if val := toBedrockFinishReason(resp.finishReason); val != "" {
		ret["stopReason"] = val
	}

	if resp.usage.isSet {
		ret["usage"] = encodeBedrockUsage(resp.usage)
	}

	return json.Marshal(ret)
}

func (c *bedrockConverseCodec) newStreamDecoder() transStreamDecoder {
	return &bedrockStreamDecoder{
		blockKinds: make(map[int]transBlockKind),
	}
}

func (c *bedrockConverseCodec) newStreamEncoder(o *transEncodeOpts) transStreamEncoder {
	return &bedrockStreamEncoder{}
}

type bedrockStreamEventEnvelope struct {
	Role string `json:"role"`

	ContentBlockIndex int `json:"contentBlockIndex"`

	Start *struct {
		ToolUse *struct {
			ToolUseID string `json:"toolUseId"`
			Name      string `json:"name"`
		} `json:"toolUse"`
	} `json:"start"`

	Delta *struct {
		Text    string `json:"text"`
		ToolUse *struct {
			Input string `json:"input"`
		} `json:"toolUse"`
	} `json:"delta"`

	StopReason string `json:"stopReason"`

	Usage *bedrockUsage `json:"usage"`

	Message string `json:"message"`
}

type bedrockStreamDecoder struct {
	isStarted  bool
	isFinished bool

	finishReason transFinishReason
	usage        transUsage

	blockKinds map[int]transBlockKind
}

func (d *bedrockStreamDecoder) decode(eventType string,
	data []byte) ([]*transEvent, error) {

	env := &bedrockStreamEventEnvelope{}
	if err := json.Unmarshal(data, env); err != nil {
		return nil, nil
	}

	switch eventType {
	case "messageStart":
		if d.isStarted {
			return nil, nil
		}
		d.isStarted = true
		return []*transEvent{{kind: transEventStart}}, nil
	case "contentBlockStart":
		if env.Start == nil || env.Start.ToolUse == nil {
			d.blockKinds[env.ContentBlockIndex] = transBlockText
			return nil, nil
		}
		d.blockKinds[env.ContentBlockIndex] = transBlockToolCall
		return []*transEvent{{
			kind:       transEventToolCallStart,
			index:      env.ContentBlockIndex,
			toolCallID: env.Start.ToolUse.ToolUseID,
			toolName:   env.Start.ToolUse.Name,
		}}, nil
	case "contentBlockDelta":
		if env.Delta == nil {
			return nil, nil
		}
		if env.Delta.ToolUse != nil {
			if env.Delta.ToolUse.Input == "" {
				return nil, nil
			}
			return []*transEvent{{
				kind:  transEventToolCallDelta,
				index: env.ContentBlockIndex,
				text:  env.Delta.ToolUse.Input,
			}}, nil
		}
		if env.Delta.Text == "" {
			return nil, nil
		}
		return []*transEvent{{kind: transEventTextDelta, text: env.Delta.Text}}, nil
	case "messageStop":
		if env.StopReason != "" {
			d.finishReason = bedrockFinishReason(env.StopReason)
			if d.finishReason == transFinishUnset {
				return nil, transInvalidResponse(
					"the inference upstream reported a `%s` stop reason "+
						"that cannot be translated", env.StopReason)
			}
		}
		return nil, nil
	case "metadata":
		if env.Usage != nil {
			d.usage.merge(env.Usage.toTransUsage())
		}
		return nil, nil
	case "internalServerException", "modelStreamErrorException",
		"validationException", "throttlingException", "serviceUnavailableException":
		message := env.Message
		if message == "" {
			message = eventType
		}
		return nil, transInvalidResponse(
			"the inference upstream reported a streaming error: %s", message)
	default:
		return nil, nil
	}
}

func (d *bedrockStreamDecoder) finish() []*transEvent {
	if d.isFinished {
		return nil
	}
	d.isFinished = true

	return []*transEvent{{
		kind:         transEventFinish,
		finishReason: d.finishReason,
		usage:        d.usage,
	}}
}

type bedrockStreamToolCall struct {
	index int
	id    string
	name  string
	input []byte
}

type bedrockStreamEncoder struct {
	isStarted bool

	nextIndex  int
	isTextOpen bool

	toolCalls []*bedrockStreamToolCall
}

func (e *bedrockStreamEncoder) event(eventType string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, transInternal("could not serialize a translated stream event")
	}

	return httputils.EncodeLLMEventStreamEvent(eventType, body), nil
}

func (e *bedrockStreamEncoder) encode(ev *transEvent) ([]byte, error) {
	switch ev.kind {
	case transEventStart:
		return e.encodeStart()
	case transEventTextDelta:
		return e.encodeTextDelta(ev)
	case transEventToolCallStart:
		e.toolCalls = append(e.toolCalls, &bedrockStreamToolCall{
			index: ev.index,
			id:    ev.toolCallID,
			name:  ev.toolName,
		})
		return nil, nil
	case transEventToolCallDelta:
		return nil, appendTransToolInput(e.toolCalls, ev,
			func(cur *bedrockStreamToolCall) int { return cur.index },
			func(cur *bedrockStreamToolCall) *[]byte { return &cur.input })
	case transEventFinish:
		return e.encodeFinish(ev)
	default:
		return nil, nil
	}
}

func (e *bedrockStreamEncoder) encodeStart() ([]byte, error) {
	if e.isStarted {
		return nil, nil
	}
	e.isStarted = true

	return e.event("messageStart", map[string]any{"role": roleAssistant})
}

func (e *bedrockStreamEncoder) encodeTextDelta(ev *transEvent) ([]byte, error) {
	ret, err := e.encodeStart()
	if err != nil {
		return nil, err
	}

	e.isTextOpen = true

	out, err := e.event("contentBlockDelta", map[string]any{
		"contentBlockIndex": e.nextIndex,
		"delta":             map[string]any{"text": ev.text},
	})
	if err != nil {
		return nil, err
	}

	return append(ret, out...), nil
}

func (e *bedrockStreamEncoder) encodeFinish(ev *transEvent) ([]byte, error) {
	ret, err := e.encodeStart()
	if err != nil {
		return nil, err
	}

	if e.isTextOpen {
		e.isTextOpen = false
		out, err := e.encodeBlockStop(e.nextIndex)
		if err != nil {
			return nil, err
		}
		ret = append(ret, out...)
		e.nextIndex++
	}

	for _, cur := range e.toolCalls {
		out, err := e.encodeToolCall(cur)
		if err != nil {
			return nil, err
		}
		ret = append(ret, out...)
	}

	stopReason := toBedrockFinishReason(ev.finishReason)
	if stopReason == "" {
		stopReason = "end_turn"
	}

	out, err := e.event("messageStop", map[string]any{"stopReason": stopReason})
	if err != nil {
		return nil, err
	}
	ret = append(ret, out...)

	if !ev.usage.isSet {
		return ret, nil
	}

	out, err = e.event("metadata", map[string]any{
		"usage":   encodeBedrockUsage(ev.usage),
		"metrics": map[string]any{"latencyMs": 0},
	})
	if err != nil {
		return nil, err
	}

	return append(ret, out...), nil
}

func (e *bedrockStreamEncoder) encodeToolCall(
	arg *bedrockStreamToolCall) ([]byte, error) {

	if err := checkBedrockToolName(arg.name); err != nil {
		return nil, err
	}

	index := e.nextIndex
	e.nextIndex++

	ret, err := e.event("contentBlockStart", map[string]any{
		"contentBlockIndex": index,
		"start": map[string]any{
			"toolUse": map[string]any{
				"toolUseId": bedrockToolCallID(arg.id),
				"name":      arg.name,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	input := string(arg.input)
	if input == "" {
		input = "{}"
	}

	out, err := e.event("contentBlockDelta", map[string]any{
		"contentBlockIndex": index,
		"delta":             map[string]any{"toolUse": map[string]any{"input": input}},
	})
	if err != nil {
		return nil, err
	}
	ret = append(ret, out...)

	out, err = e.encodeBlockStop(index)
	if err != nil {
		return nil, err
	}

	return append(ret, out...), nil
}

func (e *bedrockStreamEncoder) encodeBlockStop(index int) ([]byte, error) {
	return e.event("contentBlockStop", map[string]any{"contentBlockIndex": index})
}

func (e *bedrockStreamEncoder) encodeError(message string) []byte {
	ret, err := e.event("internalServerException", &bedrockErrorResponse{
		Message: message,
	})
	if err != nil {
		return nil
	}

	return ret
}
