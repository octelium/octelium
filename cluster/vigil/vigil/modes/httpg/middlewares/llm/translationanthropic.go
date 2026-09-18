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
	"fmt"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

const anthropicMessagesPath = "/v1/messages"

const (
	anthropicVersionHeader  = "Anthropic-Version"
	anthropicDefaultVersion = "2023-06-01"
)

var anthropicMessagesFields = newTransFields([]string{
	"model", "messages", "system", "max_tokens", "stream",
	"stop_sequences", "tools", "tool_choice",
	"temperature", "top_p", "metadata", "thinking",
}, nil)

var anthropicMessageFields = newTransFields([]string{"role", "content"}, nil)

var anthropicTextBlockFields = newTransFields([]string{
	"type", "text",
}, []string{"cache_control", "citations"})

var anthropicImageBlockFields = newTransFields([]string{
	"type", "source",
}, []string{"cache_control"})

var anthropicImageSourceFields = newTransFields([]string{
	"type", "media_type", "data", "url",
}, nil)

var anthropicToolUseFields = newTransFields([]string{
	"type", "id", "name", "input",
}, []string{"cache_control"})

var anthropicToolResultFields = newTransFields([]string{
	"type", "tool_use_id", "content", "is_error",
}, []string{"cache_control"})

var anthropicToolFields = newTransFields([]string{
	"type", "name", "description", "input_schema",
}, []string{"cache_control", "strict"})

var anthropicToolChoiceFields = newTransFields([]string{
	"type", "name", "disable_parallel_tool_use",
}, nil)

var anthropicThinkingFields = newTransFields([]string{"type", "budget_tokens"}, nil)

var anthropicMetadataFields = newTransFields([]string{"user_id"}, nil)

type anthropicMessagesCodec struct{}

func (c *anthropicMessagesCodec) route() corev1.RequestContext_Request_LLM_Route {
	return corev1.RequestContext_Request_LLM_MESSAGES
}

func (c *anthropicMessagesCodec) path() string {
	return anthropicMessagesPath
}

func (c *anthropicMessagesCodec) decodeRequest(body []byte) (*transRequest, error) {
	root, err := transObject(body)
	if err != nil {
		return nil, transUnsupported("the request body is not a JSON object")
	}

	if err := anthropicMessagesFields.check(root, "Anthropic Messages request"); err != nil {
		return nil, err
	}

	ret := &transRequest{}

	for key, raw := range root {
		if transIsNull(raw) {
			continue
		}

		var err error
		switch key {
		case "model":
			ret.model, err = transString(raw, key)
		case "stream":
			ret.stream, err = transBool(raw, key)
		case "max_tokens":
			ret.maxOutputTokens, err = transUint(raw, key)
		case "stop_sequences":
			ret.stopSequences, err = transStrings(raw, key)
		case "temperature":
			var val float64
			if val, err = transFloat(raw, key); err == nil {
				ret.temperature = &val
			}
		case "top_p":
			var val float64
			if val, err = transFloat(raw, key); err == nil {
				ret.topP = &val
			}
		case "metadata":
			err = c.decodeMetadata(ret, raw)
		case "thinking":
			err = c.decodeThinking(ret, raw)
		case "system":
			err = c.decodeSystem(ret, raw)
		case "tools":
			ret.tools, err = c.decodeTools(raw)
		case "tool_choice":
			ret.toolChoice, err = c.decodeToolChoice(raw)
		}

		if err != nil {
			return nil, err
		}
	}

	if err := c.decodeMessages(ret, root["messages"]); err != nil {
		return nil, err
	}

	ret.streamUsage = ret.stream

	return ret, nil
}

func (c *anthropicMessagesCodec) decodeMetadata(ret *transRequest,
	raw json.RawMessage) error {

	obj, err := transObject(raw)
	if err != nil {
		return transUnsupported("the `metadata` field is not a JSON object")
	}

	if err := anthropicMetadataFields.check(obj, "`metadata` field"); err != nil {
		return err
	}

	if cur, ok := obj["user_id"]; ok && !transIsNull(cur) {
		if ret.userID, err = transString(cur, "user_id"); err != nil {
			return err
		}
	}

	return nil
}

func (c *anthropicMessagesCodec) decodeThinking(ret *transRequest,
	raw json.RawMessage) error {

	obj, err := transObject(raw)
	if err != nil {
		return transUnsupported("the `thinking` field is not a JSON object")
	}

	if err := anthropicThinkingFields.check(obj, "`thinking` field"); err != nil {
		return err
	}

	typ, err := transType(obj)
	if err != nil {
		return err
	}

	switch typ {
	case "disabled":
		ret.reasoningTarget = newReasoningLevel(
			corev1.Service_Spec_Config_LLM_Reasoning_NONE)
		return nil
	case "enabled":
		budget, err := transUint(obj["budget_tokens"], "budget_tokens")
		if err != nil {
			return err
		}
		ret.reasoningTarget = newReasoningTokenBudget(budget)
		return nil
	default:
		return transUnsupported("a `thinking` configuration of the `%s` type "+
			"cannot be translated", typ)
	}
}

func (c *anthropicMessagesCodec) decodeSystem(ret *transRequest,
	raw json.RawMessage) error {

	if raw[0] == '"' {
		text, err := transString(raw, "system")
		if err != nil {
			return err
		}
		if text != "" {
			ret.system = append(ret.system, text)
		}
		return nil
	}

	blocks, err := c.decodeBlocks(raw)
	if err != nil {
		return err
	}

	for _, block := range blocks {
		if block.kind != transBlockText {
			return transUnsupported(
				"the `system` field carries content that cannot be translated")
		}
		ret.system = append(ret.system, block.text)
	}

	return nil
}

func (c *anthropicMessagesCodec) decodeMessages(ret *transRequest,
	raw json.RawMessage) error {

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

		if err := anthropicMessageFields.check(obj, "message"); err != nil {
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

		blocks, err := c.decodeContent(obj["content"])
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

func (c *anthropicMessagesCodec) decodeContent(raw json.RawMessage) ([]*transBlock, error) {
	if transIsNull(raw) {
		return nil, nil
	}

	if raw[0] == '"' {
		text, err := transString(raw, "content")
		if err != nil {
			return nil, err
		}
		if text == "" {
			return nil, nil
		}
		return []*transBlock{{kind: transBlockText, text: text}}, nil
	}

	return c.decodeBlocks(raw)
}

func (c *anthropicMessagesCodec) decodeBlocks(raw json.RawMessage) ([]*transBlock, error) {
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

		typ, err := transType(obj)
		if err != nil {
			return nil, err
		}

		block, err := c.decodeBlock(typ, obj)
		if err != nil {
			return nil, err
		}

		ret = append(ret, block)
	}

	return ret, nil
}

func (c *anthropicMessagesCodec) decodeBlock(typ string,
	obj map[string]json.RawMessage) (*transBlock, error) {

	switch typ {
	case "text":
		if err := anthropicTextBlockFields.check(obj, "content block"); err != nil {
			return nil, err
		}
		text, err := transString(obj["text"], "text")
		if err != nil {
			return nil, err
		}
		return &transBlock{kind: transBlockText, text: text}, nil
	case "image":
		if err := anthropicImageBlockFields.check(obj, "content block"); err != nil {
			return nil, err
		}
		return c.decodeImage(obj["source"])
	case "tool_use":
		if err := anthropicToolUseFields.check(obj, "content block"); err != nil {
			return nil, err
		}
		return c.decodeToolUse(obj)
	case "tool_result":
		if err := anthropicToolResultFields.check(obj, "content block"); err != nil {
			return nil, err
		}
		return c.decodeToolResult(obj)
	default:
		return nil, transUnsupported(
			"a content block of the `%s` type cannot be translated", typ)
	}
}

func (c *anthropicMessagesCodec) decodeImage(raw json.RawMessage) (*transBlock, error) {
	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("an image content block declares no `source`")
	}

	if err := anthropicImageSourceFields.check(obj, "image `source`"); err != nil {
		return nil, err
	}

	typ, err := transType(obj)
	if err != nil {
		return nil, err
	}

	switch typ {
	case "base64":
		mediaType, err := transString(obj["media_type"], "media_type")
		if err != nil {
			return nil, err
		}
		data, err := transString(obj["data"], "data")
		if err != nil {
			return nil, err
		}
		if len(data) > maxTransImageBytes {
			return nil, transUnsupported("an image content block is too large")
		}
		return &transBlock{
			kind: transBlockImage,
			image: &transImage{
				mediaType: mediaType,
				data:      data,
			},
		}, nil
	case "url":
		url, err := transString(obj["url"], "url")
		if err != nil {
			return nil, err
		}
		return &transBlock{
			kind:  transBlockImage,
			image: &transImage{url: url},
		}, nil
	default:
		return nil, transUnsupported(
			"an image `source` of the `%s` type cannot be translated", typ)
	}
}

func (c *anthropicMessagesCodec) decodeToolUse(
	obj map[string]json.RawMessage) (*transBlock, error) {

	id, err := transString(obj["id"], "id")
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, transUnsupported("a `tool_use` block declares no identifier")
	}

	name, err := transString(obj["name"], "name")
	if err != nil {
		return nil, err
	}

	input := json.RawMessage(`{}`)
	if raw, ok := obj["input"]; ok && !transIsNull(raw) {
		if input, err = transToolInput(raw); err != nil {
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

func (c *anthropicMessagesCodec) decodeToolResult(
	obj map[string]json.RawMessage) (*transBlock, error) {

	id, err := transString(obj["tool_use_id"], "tool_use_id")
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, transUnsupported("a `tool_result` block declares no `tool_use_id`")
	}

	ret := &transBlock{
		kind:       transBlockToolResult,
		toolCallID: id,
	}

	if raw, ok := obj["is_error"]; ok && !transIsNull(raw) {
		if ret.isToolError, err = transBool(raw, "is_error"); err != nil {
			return nil, err
		}
	}

	blocks, err := c.decodeContent(obj["content"])
	if err != nil {
		return nil, err
	}

	for _, block := range blocks {
		if block.kind != transBlockText {
			return nil, transUnsupported(
				"a `tool_result` block carries content that cannot be translated")
		}
	}

	ret.toolResult = transBlocksText(blocks)

	return ret, nil
}

func (c *anthropicMessagesCodec) decodeTools(raw json.RawMessage) ([]*transTool, error) {
	entries, err := transArray(raw, "tools")
	if err != nil {
		return nil, err
	}

	var ret []*transTool
	for _, entry := range entries {
		obj, err := transObject(entry)
		if err != nil {
			return nil, transUnsupported("a declared tool is not a JSON object")
		}

		if err := anthropicToolFields.check(obj, "declared tool"); err != nil {
			return nil, err
		}

		typ, err := transType(obj)
		if err != nil {
			return nil, err
		}
		if typ != "" && typ != "custom" {
			return nil, transUnsupported(
				"a declared tool of the `%s` type cannot be translated", typ)
		}

		tool := &transTool{}
		if tool.name, err = transString(obj["name"], "name"); err != nil {
			return nil, err
		}

		if cur, ok := obj["description"]; ok && !transIsNull(cur) {
			if tool.description, err = transString(cur, "description"); err != nil {
				return nil, err
			}
		}

		if cur, ok := obj["input_schema"]; ok && !transIsNull(cur) {
			tool.schema = cur
		}

		ret = append(ret, tool)
	}

	return ret, nil
}

func (c *anthropicMessagesCodec) decodeToolChoice(
	raw json.RawMessage) (*transToolChoice, error) {

	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("the `tool_choice` field is not a JSON object")
	}

	if err := anthropicToolChoiceFields.check(obj, "`tool_choice` field"); err != nil {
		return nil, err
	}

	ret := &transToolChoice{}

	if cur, ok := obj["disable_parallel_tool_use"]; ok && !transIsNull(cur) {
		if ret.disableParallel, err = transBool(cur,
			"disable_parallel_tool_use"); err != nil {
			return nil, err
		}
	}

	typ, err := transType(obj)
	if err != nil {
		return nil, err
	}

	switch typ {
	case "auto":
		ret.kind = transToolChoiceAuto
	case "any":
		ret.kind = transToolChoiceRequired
	case "none":
		ret.kind = transToolChoiceNone
	case "tool":
		ret.kind = transToolChoiceNamed
		if ret.name, err = transString(obj["name"], "name"); err != nil {
			return nil, err
		}
	default:
		return nil, transUnsupported(
			"a `tool_choice` of the `%s` type cannot be translated", typ)
	}

	return ret, nil
}

func (c *anthropicMessagesCodec) encodeRequest(req *transRequest,
	o *transEncodeOpts) (map[string]json.RawMessage, error) {

	ret := make(map[string]json.RawMessage)

	if err := setRawField(ret, "model", req.model); err != nil {
		return nil, err
	}

	if req.stream {
		if err := setRawField(ret, "stream", true); err != nil {
			return nil, err
		}
	}

	maxOutputTokens := req.maxOutputTokens
	if maxOutputTokens == 0 {
		maxOutputTokens = o.defaultMaxOutputTokens
	}
	if err := setRawField(ret, "max_tokens", maxOutputTokens); err != nil {
		return nil, err
	}

	if len(req.stopSequences) > 0 {
		if err := setRawField(ret, "stop_sequences", req.stopSequences); err != nil {
			return nil, err
		}
	}

	if req.temperature != nil {
		if *req.temperature > 1 {
			return nil, transUnsupported(
				"a `temperature` above 1 cannot be translated to the ANTHROPIC protocol")
		}
		if err := setRawField(ret, "temperature", *req.temperature); err != nil {
			return nil, err
		}
	}

	if req.topP != nil {
		if err := setRawField(ret, "top_p", *req.topP); err != nil {
			return nil, err
		}
	}

	if req.userID != "" {
		if err := setRawField(ret, "metadata", map[string]any{
			"user_id": req.userID,
		}); err != nil {
			return nil, err
		}
	}

	if err := c.encodeSystem(ret, req.system); err != nil {
		return nil, err
	}

	msgs, err := c.encodeMessages(req.messages)
	if err != nil {
		return nil, err
	}
	if err := setRawField(ret, "messages", msgs); err != nil {
		return nil, err
	}

	if len(req.tools) > 0 {
		tools := make([]any, 0, len(req.tools))
		for _, tool := range req.tools {
			cur := map[string]any{"name": tool.name}
			if tool.description != "" {
				cur["description"] = tool.description
			}
			if len(tool.schema) > 0 {
				cur["input_schema"] = tool.schema
			} else {
				cur["input_schema"] = map[string]any{"type": "object"}
			}
			tools = append(tools, cur)
		}
		if err := setRawField(ret, "tools", tools); err != nil {
			return nil, err
		}
	}

	if err := c.encodeToolChoice(ret, req.toolChoice); err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *anthropicMessagesCodec) encodeSystem(root map[string]json.RawMessage,
	system []string) error {

	var texts []string
	for _, cur := range system {
		if cur == "" {
			continue
		}
		texts = append(texts, cur)
	}

	switch len(texts) {
	case 0:
		return nil
	case 1:
		return setRawField(root, "system", texts[0])
	default:
		blocks := make([]any, 0, len(texts))
		for _, cur := range texts {
			blocks = append(blocks, map[string]any{"type": "text", "text": cur})
		}
		return setRawField(root, "system", blocks)
	}
}

func (c *anthropicMessagesCodec) encodeMessages(msgs []*transMessage) ([]any, error) {
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

func (c *anthropicMessagesCodec) encodeBlocks(blocks []*transBlock) ([]any, error) {
	var results []any
	var rest []any

	for _, block := range blocks {
		switch block.kind {
		case transBlockText:
			if block.text == "" {
				continue
			}
			rest = append(rest, map[string]any{
				"type": "text",
				"text": block.text,
			})
		case transBlockImage:
			source, err := encodeAnthropicImageSource(block.image)
			if err != nil {
				return nil, err
			}
			rest = append(rest, map[string]any{
				"type":   "image",
				"source": source,
			})
		case transBlockToolCall:
			rest = append(rest, map[string]any{
				"type":  "tool_use",
				"id":    block.toolCallID,
				"name":  block.toolName,
				"input": block.toolInput,
			})
		case transBlockToolResult:
			cur := map[string]any{
				"type":        "tool_result",
				"tool_use_id": block.toolCallID,
				"content":     block.toolResult,
			}
			if block.isToolError {
				cur["is_error"] = true
			}
			results = append(results, cur)
		}
	}

	return append(results, rest...), nil
}

func encodeAnthropicImageSource(arg *transImage) (map[string]any, error) {
	if arg.url != "" {
		return map[string]any{
			"type": "url",
			"url":  arg.url,
		}, nil
	}

	if arg.mediaType == "" {
		return nil, transUnsupported(
			"an image whose media type is unknown cannot be translated")
	}

	return map[string]any{
		"type":       "base64",
		"media_type": arg.mediaType,
		"data":       arg.data,
	}, nil
}

func (c *anthropicMessagesCodec) encodeToolChoice(root map[string]json.RawMessage,
	choice *transToolChoice) error {

	if choice == nil {
		return nil
	}

	ret := make(map[string]any)

	switch choice.kind {
	case transToolChoiceAuto:
		ret["type"] = "auto"
	case transToolChoiceNone:
		ret["type"] = "none"
	case transToolChoiceRequired:
		ret["type"] = "any"
	case transToolChoiceNamed:
		ret["type"] = "tool"
		ret["name"] = choice.name
	default:
		if !choice.disableParallel {
			return nil
		}
		ret["type"] = "auto"
	}

	if choice.disableParallel {
		ret["disable_parallel_tool_use"] = true
	}

	return setRawField(root, "tool_choice", ret)
}

type anthropicResponseEnvelope struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Content []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`

	StopReason   string `json:"stop_reason"`
	StopSequence string `json:"stop_sequence"`

	Usage *anthropicUsage `json:"usage"`
}

type anthropicUsage struct {
	InputTokens  uint64 `json:"input_tokens"`
	OutputTokens uint64 `json:"output_tokens"`

	CacheReadInputTokens     uint64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens uint64 `json:"cache_creation_input_tokens"`
}

func (u *anthropicUsage) toTransUsage() transUsage {
	return transUsage{
		inputTokens: u.InputTokens + u.CacheReadInputTokens +
			u.CacheCreationInputTokens,
		outputTokens:        u.OutputTokens,
		cacheReadTokens:     u.CacheReadInputTokens,
		cacheCreationTokens: u.CacheCreationInputTokens,
		isSet:               true,
	}
}

func encodeAnthropicUsage(usage transUsage) map[string]any {
	ret := map[string]any{
		"input_tokens":  usage.uncachedInputTokens(),
		"output_tokens": usage.outputTokens,
	}

	if usage.cacheReadTokens > 0 {
		ret["cache_read_input_tokens"] = usage.cacheReadTokens
	}
	if usage.cacheCreationTokens > 0 {
		ret["cache_creation_input_tokens"] = usage.cacheCreationTokens
	}

	return ret
}

func (c *anthropicMessagesCodec) decodeResponse(body []byte) (*transResponse, error) {
	env := &anthropicResponseEnvelope{}
	if err := json.Unmarshal(body, env); err != nil {
		return nil, transInvalidResponse(
			"the upstream response is not a valid Anthropic response")
	}

	ret := &transResponse{
		id:           env.ID,
		model:        env.Model,
		finishReason: anthropicFinishReason(env.StopReason),
		stopSequence: env.StopSequence,
	}

	if env.StopReason != "" && ret.finishReason == transFinishUnset {
		return nil, transInvalidResponse(
			"the upstream response carries a `%s` stop reason that cannot be translated",
			env.StopReason)
	}

	if env.Usage != nil {
		ret.usage = env.Usage.toTransUsage()
	}

	for _, block := range env.Content {
		switch block.Type {
		case "text":
			ret.blocks = append(ret.blocks, &transBlock{
				kind: transBlockText,
				text: block.Text,
			})
		case "tool_use":
			input, err := transToolInput(block.Input)
			if err != nil {
				return nil, transInvalidResponse(
					"the upstream response carries a tool call whose input is not a JSON object")
			}
			ret.blocks = append(ret.blocks, &transBlock{
				kind:       transBlockToolCall,
				toolCallID: block.ID,
				toolName:   block.Name,
				toolInput:  input,
			})
		}
	}

	return ret, nil
}

func anthropicFinishReason(arg string) transFinishReason {
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
	case "refusal":
		return transFinishContentFilter
	default:
		return transFinishUnset
	}
}

func toAnthropicFinishReason(arg transFinishReason) string {
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
		return "refusal"
	default:
		return ""
	}
}

func (c *anthropicMessagesCodec) encodeResponse(resp *transResponse,
	o *transEncodeOpts) ([]byte, error) {

	content := make([]any, 0, len(resp.blocks))
	for _, block := range resp.blocks {
		switch block.kind {
		case transBlockText:
			content = append(content, map[string]any{
				"type": "text",
				"text": block.text,
			})
		case transBlockToolCall:
			content = append(content, map[string]any{
				"type":  "tool_use",
				"id":    block.toolCallID,
				"name":  block.toolName,
				"input": block.toolInput,
			})
		}
	}

	ret := map[string]any{
		"id":            newAnthropicResponseID(),
		"type":          "message",
		"role":          roleAssistant,
		"model":         resp.model,
		"content":       content,
		"stop_reason":   nil,
		"stop_sequence": nil,
	}

	if val := toAnthropicFinishReason(resp.finishReason); val != "" {
		ret["stop_reason"] = val
	}
	if resp.stopSequence != "" {
		ret["stop_sequence"] = resp.stopSequence
	}

	ret["usage"] = encodeAnthropicUsage(resp.usage)

	return json.Marshal(ret)
}

func newAnthropicResponseID() string {
	return fmt.Sprintf("msg_%s", utilrand.GetRandomStringLowercase(24))
}

func (c *anthropicMessagesCodec) newStreamDecoder() transStreamDecoder {
	return &anthropicStreamDecoder{
		blockKinds: make(map[int]transBlockKind),
	}
}

func (c *anthropicMessagesCodec) newStreamEncoder(o *transEncodeOpts) transStreamEncoder {
	return &anthropicStreamEncoder{
		id: newAnthropicResponseID(),
	}
}

type anthropicStreamEventEnvelope struct {
	Type  string `json:"type"`
	Index int    `json:"index"`

	Message *struct {
		ID    string          `json:"id"`
		Model string          `json:"model"`
		Usage *anthropicUsage `json:"usage"`
	} `json:"message"`

	ContentBlock *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"content_block"`

	Delta *struct {
		Type         string `json:"type"`
		Text         string `json:"text"`
		PartialJSON  string `json:"partial_json"`
		StopReason   string `json:"stop_reason"`
		StopSequence string `json:"stop_sequence"`
	} `json:"delta"`

	Usage *anthropicUsage `json:"usage"`

	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

type anthropicStreamDecoder struct {
	isFinished bool

	id    string
	model string

	finishReason transFinishReason
	stopSequence string
	usage        transUsage

	blockKinds map[int]transBlockKind
}

func (d *anthropicStreamDecoder) decode(data []byte) ([]*transEvent, error) {
	env := &anthropicStreamEventEnvelope{}
	if err := json.Unmarshal(data, env); err != nil {
		return nil, nil
	}

	switch env.Type {
	case "message_start":
		if env.Message == nil {
			return nil, nil
		}
		d.id = env.Message.ID
		d.model = env.Message.Model
		if env.Message.Usage != nil {
			d.usage.merge(env.Message.Usage.toTransUsage())
		}
		return []*transEvent{{
			kind:  transEventStart,
			id:    d.id,
			model: d.model,
		}}, nil
	case "content_block_start":
		if env.ContentBlock == nil {
			return nil, nil
		}
		switch env.ContentBlock.Type {
		case "text":
			d.blockKinds[env.Index] = transBlockText
		case "tool_use":
			d.blockKinds[env.Index] = transBlockToolCall
			return []*transEvent{{
				kind:       transEventToolCallStart,
				index:      env.Index,
				toolCallID: env.ContentBlock.ID,
				toolName:   env.ContentBlock.Name,
			}}, nil
		}
		return nil, nil
	case "content_block_delta":
		if env.Delta == nil {
			return nil, nil
		}
		switch env.Delta.Type {
		case "text_delta":
			if env.Delta.Text == "" {
				return nil, nil
			}
			return []*transEvent{{
				kind: transEventTextDelta,
				text: env.Delta.Text,
			}}, nil
		case "input_json_delta":
			if env.Delta.PartialJSON == "" {
				return nil, nil
			}
			return []*transEvent{{
				kind:  transEventToolCallDelta,
				index: env.Index,
				text:  env.Delta.PartialJSON,
			}}, nil
		}
		return nil, nil
	case "message_delta":
		if env.Delta != nil && env.Delta.StopReason != "" {
			d.finishReason = anthropicFinishReason(env.Delta.StopReason)
			if d.finishReason == transFinishUnset {
				return nil, transInvalidResponse(
					"the inference upstream sent a `%s` stop reason that cannot be translated",
					env.Delta.StopReason)
			}
			d.stopSequence = env.Delta.StopSequence
		}
		if env.Usage != nil {
			d.usage.merge(env.Usage.toTransUsage())
		}
		return nil, nil
	case "error":
		message := "the upstream reported a streaming error"
		if env.Error != nil && env.Error.Message != "" {
			message = env.Error.Message
		}
		return nil, transInvalidResponse("%s", message)
	default:
		return nil, nil
	}
}

func (d *anthropicStreamDecoder) finish() []*transEvent {
	if d.isFinished {
		return nil
	}
	d.isFinished = true

	return []*transEvent{{
		kind:         transEventFinish,
		id:           d.id,
		model:        d.model,
		finishReason: d.finishReason,
		stopSequence: d.stopSequence,
		usage:        d.usage,
	}}
}

type anthropicStreamToolCall struct {
	index int
	id    string
	name  string
	input []byte
}

type anthropicStreamEncoder struct {
	id    string
	model string

	nextIndex int

	isStarted  bool
	isTextOpen bool

	toolCalls []*anthropicStreamToolCall
}

func (e *anthropicStreamEncoder) encode(ev *transEvent) ([]byte, error) {
	switch ev.kind {
	case transEventStart:
		return e.encodeStart(ev.model)
	case transEventTextDelta:
		return e.encodeTextDelta(ev)
	case transEventToolCallStart:
		e.toolCalls = append(e.toolCalls, &anthropicStreamToolCall{
			index: ev.index,
			id:    ev.toolCallID,
			name:  ev.toolName,
		})
		return nil, nil
	case transEventToolCallDelta:
		return nil, e.appendToolCall(ev)
	case transEventFinish:
		return e.encodeFinish(ev)
	default:
		return nil, nil
	}
}

func (e *anthropicStreamEncoder) appendToolCall(ev *transEvent) error {
	for _, cur := range e.toolCalls {
		if cur.index != ev.index {
			continue
		}
		if len(cur.input)+len(ev.text) > maxTransToolInputBytes {
			return transInvalidResponse(
				"the inference upstream sent a tool call whose arguments are too large")
		}
		cur.input = append(cur.input, ev.text...)
		return nil
	}

	return nil
}

func (e *anthropicStreamEncoder) encodeStart(model string) ([]byte, error) {
	if e.isStarted {
		return nil, nil
	}
	e.isStarted = true
	e.model = model

	return sseEventOf("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id":            e.id,
			"type":          "message",
			"role":          roleAssistant,
			"model":         e.model,
			"content":       []any{},
			"stop_reason":   nil,
			"stop_sequence": nil,
			"usage": map[string]any{
				"input_tokens":  0,
				"output_tokens": 0,
			},
		},
	})
}

func (e *anthropicStreamEncoder) encodeTextDelta(ev *transEvent) ([]byte, error) {
	ret, err := e.encodeStart(e.model)
	if err != nil {
		return nil, err
	}

	if !e.isTextOpen {
		e.isTextOpen = true
		out, err := sseEventOf("content_block_start", map[string]any{
			"type":  "content_block_start",
			"index": e.nextIndex,
			"content_block": map[string]any{
				"type": "text",
				"text": "",
			},
		})
		if err != nil {
			return nil, err
		}
		ret = append(ret, out...)
	}

	out, err := sseEventOf("content_block_delta", map[string]any{
		"type":  "content_block_delta",
		"index": e.nextIndex,
		"delta": map[string]any{
			"type": "text_delta",
			"text": ev.text,
		},
	})
	if err != nil {
		return nil, err
	}

	return append(ret, out...), nil
}

func (e *anthropicStreamEncoder) encodeFinish(ev *transEvent) ([]byte, error) {
	ret, err := e.encodeStart(ev.model)
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

	delta := map[string]any{
		"stop_reason":   nil,
		"stop_sequence": nil,
	}
	if val := toAnthropicFinishReason(ev.finishReason); val != "" {
		delta["stop_reason"] = val
	}
	if ev.stopSequence != "" {
		delta["stop_sequence"] = ev.stopSequence
	}

	out, err := sseEventOf("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": delta,
		"usage": encodeAnthropicUsage(ev.usage),
	})
	if err != nil {
		return nil, err
	}
	ret = append(ret, out...)

	out, err = sseEventOf("message_stop", map[string]any{
		"type": "message_stop",
	})
	if err != nil {
		return nil, err
	}

	return append(ret, out...), nil
}

func (e *anthropicStreamEncoder) encodeToolCall(
	arg *anthropicStreamToolCall) ([]byte, error) {

	index := e.nextIndex
	e.nextIndex++

	ret, err := sseEventOf("content_block_start", map[string]any{
		"type":  "content_block_start",
		"index": index,
		"content_block": map[string]any{
			"type":  "tool_use",
			"id":    arg.id,
			"name":  arg.name,
			"input": map[string]any{},
		},
	})
	if err != nil {
		return nil, err
	}

	input := string(arg.input)
	if input == "" {
		input = "{}"
	}

	out, err := sseEventOf("content_block_delta", map[string]any{
		"type":  "content_block_delta",
		"index": index,
		"delta": map[string]any{
			"type":         "input_json_delta",
			"partial_json": input,
		},
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

func (e *anthropicStreamEncoder) encodeBlockStop(index int) ([]byte, error) {
	return sseEventOf("content_block_stop", map[string]any{
		"type":  "content_block_stop",
		"index": index,
	})
}

func (e *anthropicStreamEncoder) encodeError(message string) []byte {
	ret, err := sseEventOf("error", &anthropicErrorResponse{
		Type: "error",
		Error: &anthropicError{
			Type:    ErrTypeAPI,
			Message: message,
		},
	})
	if err != nil {
		return nil
	}

	return ret
}
