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
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

const openAIChatPath = "/v1/chat/completions"

const (
	openAIObjectCompletion = "chat.completion"
	openAIObjectChunk      = "chat.completion.chunk"
)

var openAIChatFields = newTransFields([]string{
	"model", "messages", "stream", "stream_options",
	"max_tokens", "max_completion_tokens", "stop",
	"tools", "tool_choice", "parallel_tool_calls",
	"temperature", "top_p", "reasoning_effort", "user",
}, []string{"store", "metadata"})

var openAIMessageFields = newTransFields([]string{
	"role", "content", "tool_calls", "tool_call_id",
}, []string{"refusal", "annotations"})

var openAITextPartFields = newTransFields([]string{"type", "text"}, nil)

var openAIImagePartFields = newTransFields([]string{"type", "image_url"}, nil)

var openAIImageURLFields = newTransFields([]string{"url"}, []string{"detail"})

var openAIToolCallFields = newTransFields([]string{
	"id", "type", "function",
}, []string{"index"})

var openAIToolCallFunctionFields = newTransFields([]string{"name", "arguments"}, nil)

var openAIToolFields = newTransFields([]string{"type", "function"}, nil)

var openAIToolFunctionFields = newTransFields([]string{
	"name", "description", "parameters",
}, []string{"strict"})

var openAIStreamOptionsFields = newTransFields([]string{"include_usage"}, nil)

type openAIChatCodec struct{}

func (c *openAIChatCodec) route() corev1.RequestContext_Request_LLM_Route {
	return corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS
}

func (c *openAIChatCodec) path() string {
	return openAIChatPath
}

func (c *openAIChatCodec) decodeRequest(body []byte) (*transRequest, error) {
	root, err := transObject(body)
	if err != nil {
		return nil, transUnsupported("the request body is not a JSON object")
	}

	if err := openAIChatFields.check(root, "OpenAI Chat Completions request"); err != nil {
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
		case "stream_options":
			err = c.decodeStreamOptions(ret, raw)
		case "max_tokens", "max_completion_tokens":
			var val uint64
			if val, err = transUint(raw, key); err == nil && val > ret.maxOutputTokens {
				ret.maxOutputTokens = val
			}
		case "stop":
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
		case "user":
			ret.userID, err = transString(raw, key)
		case "parallel_tool_calls":
			var val bool
			if val, err = transBool(raw, key); err == nil && !val {
				ret.toolChoice = c.withToolChoice(ret.toolChoice)
				ret.toolChoice.disableParallel = true
			}
		case "reasoning_effort":
			var val string
			if val, err = transString(raw, key); err == nil {
				ret.reasoningTarget, err = parseReasoningTarget(val)
			}
		}

		if err != nil {
			return nil, err
		}
	}

	if raw, ok := root["tools"]; ok && !transIsNull(raw) {
		if ret.tools, err = c.decodeTools(raw); err != nil {
			return nil, err
		}
	}

	if raw, ok := root["tool_choice"]; ok && !transIsNull(raw) {
		choice, err := c.decodeToolChoice(raw)
		if err != nil {
			return nil, err
		}
		cur := c.withToolChoice(ret.toolChoice)
		cur.kind = choice.kind
		cur.name = choice.name
		ret.toolChoice = cur
	}

	if err := c.decodeMessages(ret, root["messages"]); err != nil {
		return nil, err
	}

	return ret, nil
}

func (c *openAIChatCodec) withToolChoice(arg *transToolChoice) *transToolChoice {
	if arg != nil {
		return arg
	}
	return &transToolChoice{}
}

func (c *openAIChatCodec) decodeStreamOptions(ret *transRequest, raw json.RawMessage) error {
	obj, err := transObject(raw)
	if err != nil {
		return transUnsupported("the `stream_options` field is not a JSON object")
	}

	if err := openAIStreamOptionsFields.check(obj, "`stream_options` field"); err != nil {
		return err
	}

	if cur, ok := obj["include_usage"]; ok && !transIsNull(cur) {
		if ret.streamUsage, err = transBool(cur, "include_usage"); err != nil {
			return err
		}
	}

	return nil
}

func (c *openAIChatCodec) decodeMessages(ret *transRequest, raw json.RawMessage) error {
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

		if err := openAIMessageFields.check(obj, "message"); err != nil {
			return err
		}

		role, err := transString(obj["role"], "role")
		if err != nil {
			return err
		}

		switch role {
		case roleSystem, roleDeveloper:
			if len(ret.messages) > 0 {
				return transUnsupported(
					"a `%s` message that follows a conversation message cannot be translated",
					role)
			}
			text, err := c.decodeText(obj["content"])
			if err != nil {
				return err
			}
			ret.system = append(ret.system, text)
		case roleUser:
			blocks, err := c.decodeContent(obj["content"])
			if err != nil {
				return err
			}
			ret.messages = append(ret.messages, &transMessage{
				role:   roleUser,
				blocks: blocks,
			})
		case roleAssistant:
			if err := c.decodeAssistant(ret, obj); err != nil {
				return err
			}
		case "tool":
			if err := c.decodeToolResult(ret, obj); err != nil {
				return err
			}
		default:
			return transUnsupported("a message of the `%s` role cannot be translated", role)
		}
	}

	return nil
}

func (c *openAIChatCodec) decodeAssistant(ret *transRequest,
	obj map[string]json.RawMessage) error {

	blocks, err := c.decodeContent(obj["content"])
	if err != nil {
		return err
	}

	for _, block := range blocks {
		if block.kind != transBlockText {
			return transUnsupported(
				"an assistant message carries content that cannot be translated")
		}
	}

	if raw, ok := obj["tool_calls"]; ok && !transIsNull(raw) {
		entries, err := transArray(raw, "tool_calls")
		if err != nil {
			return err
		}

		for _, entry := range entries {
			block, err := c.decodeToolCall(entry)
			if err != nil {
				return err
			}
			blocks = append(blocks, block)
		}
	}

	ret.messages = append(ret.messages, &transMessage{
		role:   roleAssistant,
		blocks: blocks,
	})

	return nil
}

func (c *openAIChatCodec) decodeToolCall(entry json.RawMessage) (*transBlock, error) {
	obj, err := transObject(entry)
	if err != nil {
		return nil, transUnsupported("a tool call is not a JSON object")
	}

	if err := openAIToolCallFields.check(obj, "tool call"); err != nil {
		return nil, err
	}

	typ, err := transType(obj)
	if err != nil {
		return nil, err
	}
	if typ != "" && typ != functionToolKind {
		return nil, transUnsupported("a tool call of the `%s` type cannot be translated", typ)
	}

	id, err := transString(obj["id"], "id")
	if err != nil {
		return nil, err
	}
	if id == "" {
		return nil, transUnsupported("a tool call declares no identifier")
	}

	fn, err := transObject(obj["function"])
	if err != nil {
		return nil, transUnsupported("a tool call declares no function")
	}

	if err := openAIToolCallFunctionFields.check(fn, "tool call function"); err != nil {
		return nil, err
	}

	name, err := transString(fn["name"], "name")
	if err != nil {
		return nil, err
	}

	var args string
	if raw, ok := fn["arguments"]; ok && !transIsNull(raw) {
		if args, err = transString(raw, "arguments"); err != nil {
			return nil, err
		}
	}

	input, err := transToolArguments(args)
	if err != nil {
		return nil, err
	}

	return &transBlock{
		kind:       transBlockToolCall,
		toolCallID: id,
		toolName:   name,
		toolInput:  input,
	}, nil
}

func (c *openAIChatCodec) decodeToolResult(ret *transRequest,
	obj map[string]json.RawMessage) error {

	id, err := transString(obj["tool_call_id"], "tool_call_id")
	if err != nil {
		return err
	}
	if id == "" {
		return transUnsupported("a tool message declares no `tool_call_id`")
	}

	text, err := c.decodeText(obj["content"])
	if err != nil {
		return err
	}

	block := &transBlock{
		kind:       transBlockToolResult,
		toolCallID: id,
		toolResult: text,
	}

	if len(ret.messages) > 0 {
		last := ret.messages[len(ret.messages)-1]
		if last.role == roleUser && last.hasKind(transBlockToolResult) &&
			!last.hasKind(transBlockText) && !last.hasKind(transBlockImage) {
			last.blocks = append(last.blocks, block)
			return nil
		}
	}

	ret.messages = append(ret.messages, &transMessage{
		role:   roleUser,
		blocks: []*transBlock{block},
	})

	return nil
}

func (c *openAIChatCodec) decodeText(raw json.RawMessage) (string, error) {
	blocks, err := c.decodeContent(raw)
	if err != nil {
		return "", err
	}

	for _, block := range blocks {
		if block.kind != transBlockText {
			return "", transUnsupported("a message carries content that cannot be translated")
		}
	}

	return transBlocksText(blocks), nil
}

func (c *openAIChatCodec) decodeContent(raw json.RawMessage) ([]*transBlock, error) {
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

	entries, err := transArray(raw, "content")
	if err != nil {
		return nil, err
	}

	var ret []*transBlock
	for _, entry := range entries {
		obj, err := transObject(entry)
		if err != nil {
			return nil, transUnsupported("a content part is not a JSON object")
		}

		typ, err := transType(obj)
		if err != nil {
			return nil, err
		}

		switch typ {
		case "text":
			if err := openAITextPartFields.check(obj, "content part"); err != nil {
				return nil, err
			}
			text, err := transString(obj["text"], "text")
			if err != nil {
				return nil, err
			}
			ret = append(ret, &transBlock{kind: transBlockText, text: text})
		case "image_url":
			if err := openAIImagePartFields.check(obj, "content part"); err != nil {
				return nil, err
			}
			block, err := c.decodeImage(obj["image_url"])
			if err != nil {
				return nil, err
			}
			ret = append(ret, block)
		default:
			return nil, transUnsupported(
				"a content part of the `%s` type cannot be translated", typ)
		}
	}

	return ret, nil
}

func (c *openAIChatCodec) decodeImage(raw json.RawMessage) (*transBlock, error) {
	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("an image content part declares no `image_url`")
	}

	if err := openAIImageURLFields.check(obj, "`image_url` field"); err != nil {
		return nil, err
	}

	url, err := transString(obj["url"], "url")
	if err != nil {
		return nil, err
	}
	if len(url) > maxTransImageBytes {
		return nil, transUnsupported("an image content part is too large")
	}

	if mediaType, data, ok := transDataURL(url); ok {
		return &transBlock{
			kind: transBlockImage,
			image: &transImage{
				mediaType: mediaType,
				data:      data,
			},
		}, nil
	}

	return &transBlock{
		kind:  transBlockImage,
		image: &transImage{url: url},
	}, nil
}

func (c *openAIChatCodec) decodeTools(raw json.RawMessage) ([]*transTool, error) {
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

		if err := openAIToolFields.check(obj, "declared tool"); err != nil {
			return nil, err
		}

		typ, err := transType(obj)
		if err != nil {
			return nil, err
		}
		if typ != "" && typ != functionToolKind {
			return nil, transUnsupported(
				"a declared tool of the `%s` type cannot be translated", typ)
		}

		fn, err := transObject(obj["function"])
		if err != nil {
			return nil, transUnsupported("a declared tool declares no function")
		}

		if err := openAIToolFunctionFields.check(fn, "declared tool function"); err != nil {
			return nil, err
		}

		tool := &transTool{}
		if tool.name, err = transString(fn["name"], "name"); err != nil {
			return nil, err
		}

		if cur, ok := fn["description"]; ok && !transIsNull(cur) {
			if tool.description, err = transString(cur, "description"); err != nil {
				return nil, err
			}
		}

		if cur, ok := fn["parameters"]; ok && !transIsNull(cur) {
			tool.schema = cur
		}

		ret = append(ret, tool)
	}

	return ret, nil
}

func (c *openAIChatCodec) decodeToolChoice(raw json.RawMessage) (*transToolChoice, error) {
	if raw[0] == '"' {
		val, err := transString(raw, "tool_choice")
		if err != nil {
			return nil, err
		}

		switch val {
		case "auto":
			return &transToolChoice{kind: transToolChoiceAuto}, nil
		case "none":
			return &transToolChoice{kind: transToolChoiceNone}, nil
		case "required":
			return &transToolChoice{kind: transToolChoiceRequired}, nil
		default:
			return nil, transUnsupported(
				"a `tool_choice` of `%s` cannot be translated", val)
		}
	}

	obj, err := transObject(raw)
	if err != nil {
		return nil, transUnsupported("the `tool_choice` field is not a JSON object")
	}

	typ, err := transType(obj)
	if err != nil {
		return nil, err
	}
	if typ != functionToolKind {
		return nil, transUnsupported(
			"a `tool_choice` of the `%s` type cannot be translated", typ)
	}

	fn, err := transObject(obj["function"])
	if err != nil {
		return nil, transUnsupported("the `tool_choice` field declares no function")
	}

	name, err := transString(fn["name"], "name")
	if err != nil {
		return nil, err
	}

	return &transToolChoice{kind: transToolChoiceNamed, name: name}, nil
}

type openAIOutMessage struct {
	Role       string            `json:"role"`
	Content    json.RawMessage   `json:"content,omitempty"`
	ToolCalls  []json.RawMessage `json:"tool_calls,omitempty"`
	ToolCallID string            `json:"tool_call_id,omitempty"`
}

func (c *openAIChatCodec) encodeRequest(req *transRequest,
	o *transEncodeOpts) (map[string]json.RawMessage, error) {

	if len(req.messages) > 0 &&
		req.messages[len(req.messages)-1].role == roleAssistant {
		return nil, transUnsupported(
			"a trailing assistant message, or assistant prefill, cannot be translated")
	}

	ret := make(map[string]json.RawMessage)

	if err := setRawField(ret, "model", req.model); err != nil {
		return nil, err
	}

	if req.stream {
		if err := setRawField(ret, "stream", true); err != nil {
			return nil, err
		}
		if err := setRawField(ret, "stream_options", map[string]any{
			"include_usage": true,
		}); err != nil {
			return nil, err
		}
	}

	if req.maxOutputTokens > 0 {
		if err := setRawField(ret, "max_completion_tokens", req.maxOutputTokens); err != nil {
			return nil, err
		}
	}

	if len(req.stopSequences) > 0 {
		if err := setRawField(ret, "stop", req.stopSequences); err != nil {
			return nil, err
		}
	}

	if req.temperature != nil {
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
		if err := setRawField(ret, "user", req.userID); err != nil {
			return nil, err
		}
	}

	msgs, err := c.encodeMessages(req)
	if err != nil {
		return nil, err
	}
	if err := setRawField(ret, "messages", msgs); err != nil {
		return nil, err
	}

	if len(req.tools) > 0 {
		tools, err := c.encodeTools(req.tools)
		if err != nil {
			return nil, err
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

func (c *openAIChatCodec) encodeMessages(req *transRequest) ([]*openAIOutMessage, error) {
	ret := make([]*openAIOutMessage, 0, len(req.messages)+1)

	for _, cur := range req.system {
		if cur == "" {
			continue
		}
		content, err := marshalRaw(cur)
		if err != nil {
			return nil, err
		}
		ret = append(ret, &openAIOutMessage{
			Role:    roleSystem,
			Content: content,
		})
	}

	for _, msg := range req.messages {
		for _, block := range msg.blocks {
			if block.kind != transBlockToolResult {
				continue
			}
			content, err := marshalRaw(block.toolResult)
			if err != nil {
				return nil, err
			}
			ret = append(ret, &openAIOutMessage{
				Role:       "tool",
				Content:    content,
				ToolCallID: block.toolCallID,
			})
		}

		out, err := c.encodeMessage(msg)
		if err != nil {
			return nil, err
		}
		if out != nil {
			ret = append(ret, out)
		}
	}

	return ret, nil
}

func (c *openAIChatCodec) encodeMessage(msg *transMessage) (*openAIOutMessage, error) {
	ret := &openAIOutMessage{Role: msg.role}

	var hasImage bool
	for _, block := range msg.blocks {
		if block.kind == transBlockImage {
			hasImage = true
		}
	}

	var parts []any
	var texts []string

	for _, block := range msg.blocks {
		switch block.kind {
		case transBlockText:
			if block.text == "" {
				continue
			}
			texts = append(texts, block.text)
			parts = append(parts, map[string]any{
				"type": "text",
				"text": block.text,
			})
		case transBlockImage:
			parts = append(parts, map[string]any{
				"type": "image_url",
				"image_url": map[string]any{
					"url": encodeOpenAIImageURL(block.image),
				},
			})
		case transBlockToolCall:
			call, err := marshalRaw(map[string]any{
				"id":   block.toolCallID,
				"type": functionToolKind,
				"function": map[string]any{
					"name":      block.toolName,
					"arguments": string(block.toolInput),
				},
			})
			if err != nil {
				return nil, err
			}
			ret.ToolCalls = append(ret.ToolCalls, call)
		}
	}

	switch {
	case hasImage:
		content, err := marshalRaw(parts)
		if err != nil {
			return nil, err
		}
		ret.Content = content
	case len(texts) > 0:
		content, err := marshalRaw(transBlocksText(msg.blocks))
		if err != nil {
			return nil, err
		}
		ret.Content = content
	}

	if len(ret.Content) == 0 && len(ret.ToolCalls) == 0 {
		return nil, nil
	}

	return ret, nil
}

func encodeOpenAIImageURL(arg *transImage) string {
	if arg.url != "" {
		return arg.url
	}
	return fmt.Sprintf("data:%s;base64,%s", arg.mediaType, arg.data)
}

func (c *openAIChatCodec) encodeTools(tools []*transTool) ([]any, error) {
	ret := make([]any, 0, len(tools))

	for _, tool := range tools {
		fn := map[string]any{"name": tool.name}
		if tool.description != "" {
			fn["description"] = tool.description
		}
		if len(tool.schema) > 0 {
			fn["parameters"] = tool.schema
		}

		ret = append(ret, map[string]any{
			"type":     functionToolKind,
			"function": fn,
		})
	}

	return ret, nil
}

func (c *openAIChatCodec) encodeToolChoice(root map[string]json.RawMessage,
	choice *transToolChoice) error {

	if choice == nil {
		return nil
	}

	if choice.disableParallel {
		if err := setRawField(root, "parallel_tool_calls", false); err != nil {
			return err
		}
	}

	switch choice.kind {
	case transToolChoiceAuto:
		return setRawField(root, "tool_choice", "auto")
	case transToolChoiceNone:
		return setRawField(root, "tool_choice", "none")
	case transToolChoiceRequired:
		return setRawField(root, "tool_choice", "required")
	case transToolChoiceNamed:
		return setRawField(root, "tool_choice", map[string]any{
			"type": functionToolKind,
			"function": map[string]any{
				"name": choice.name,
			},
		})
	default:
		return nil
	}
}

type openAIResponseEnvelope struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content   json.RawMessage `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`

	Usage *openAIUsage `json:"usage"`
}

type openAIUsage struct {
	PromptTokens     uint64 `json:"prompt_tokens"`
	CompletionTokens uint64 `json:"completion_tokens"`

	PromptTokensDetails *struct {
		CachedTokens uint64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`

	CompletionTokensDetails *struct {
		ReasoningTokens uint64 `json:"reasoning_tokens"`
	} `json:"completion_tokens_details"`
}

func (u *openAIUsage) toTransUsage() transUsage {
	ret := transUsage{
		inputTokens:  u.PromptTokens,
		outputTokens: u.CompletionTokens,
		isSet:        true,
	}

	if u.PromptTokensDetails != nil {
		ret.cacheReadTokens = u.PromptTokensDetails.CachedTokens
	}
	if u.CompletionTokensDetails != nil {
		ret.reasoningTokens = u.CompletionTokensDetails.ReasoningTokens
	}

	return ret
}

func (c *openAIChatCodec) decodeResponse(body []byte) (*transResponse, error) {
	env := &openAIResponseEnvelope{}
	if err := json.Unmarshal(body, env); err != nil {
		return nil, transInvalidResponse("the upstream response is not a valid OpenAI response")
	}

	if len(env.Choices) == 0 {
		return nil, transInvalidResponse("the upstream response carries no choices")
	}

	ret := &transResponse{
		id:           env.ID,
		model:        env.Model,
		finishReason: openAIFinishReason(env.Choices[0].FinishReason),
	}

	if env.Usage != nil {
		ret.usage = env.Usage.toTransUsage()
	}

	msg := env.Choices[0].Message

	blocks, err := c.decodeContent(msg.Content)
	if err != nil {
		return nil, transInvalidResponse(
			"the inference upstream sent content that cannot be translated")
	}

	if text := transBlocksText(blocks); text != "" {
		ret.blocks = append(ret.blocks, &transBlock{kind: transBlockText, text: text})
	}

	for _, call := range msg.ToolCalls {
		input, err := transToolArguments(call.Function.Arguments)
		if err != nil {
			return nil, transInvalidResponse(
				"the upstream response carries a tool call whose arguments are not a JSON object")
		}
		ret.blocks = append(ret.blocks, &transBlock{
			kind:       transBlockToolCall,
			toolCallID: call.ID,
			toolName:   call.Function.Name,
			toolInput:  input,
		})
	}

	return ret, nil
}

func openAIFinishReason(arg string) transFinishReason {
	switch arg {
	case "stop":
		return transFinishStop
	case "length":
		return transFinishLength
	case "tool_calls", "function_call":
		return transFinishToolCall
	case "content_filter":
		return transFinishContentFilter
	default:
		return transFinishUnset
	}
}

func toOpenAIFinishReason(arg transFinishReason) string {
	switch arg {
	case transFinishStop, transFinishStopSequence:
		return "stop"
	case transFinishLength:
		return "length"
	case transFinishToolCall:
		return "tool_calls"
	case transFinishContentFilter:
		return "content_filter"
	default:
		return ""
	}
}

func (c *openAIChatCodec) encodeResponse(resp *transResponse,
	o *transEncodeOpts) ([]byte, error) {

	msg := map[string]any{"role": roleAssistant}

	text := transBlocksText(resp.blocks)
	if text != "" {
		msg["content"] = text
	} else {
		msg["content"] = nil
	}

	var calls []any
	for _, block := range resp.blocks {
		if block.kind != transBlockToolCall {
			continue
		}
		calls = append(calls, map[string]any{
			"id":   block.toolCallID,
			"type": functionToolKind,
			"function": map[string]any{
				"name":      block.toolName,
				"arguments": string(block.toolInput),
			},
		})
	}
	if len(calls) > 0 {
		msg["tool_calls"] = calls
	}

	choice := map[string]any{
		"index":         0,
		"message":       msg,
		"finish_reason": toOpenAIFinishReason(resp.finishReason),
	}

	ret := map[string]any{
		"id":      newOpenAIResponseID(),
		"object":  openAIObjectCompletion,
		"created": time.Now().Unix(),
		"model":   resp.model,
		"choices": []any{choice},
	}

	if resp.usage.isSet {
		ret["usage"] = encodeOpenAIUsage(resp.usage)
	}

	return json.Marshal(ret)
}

func encodeOpenAIUsage(usage transUsage) map[string]any {
	ret := map[string]any{
		"prompt_tokens":     usage.inputTokens,
		"completion_tokens": usage.outputTokens,
		"total_tokens":      usage.inputTokens + usage.outputTokens,
	}

	if usage.cacheReadTokens > 0 {
		ret["prompt_tokens_details"] = map[string]any{
			"cached_tokens": usage.cacheReadTokens,
		}
	}

	if usage.reasoningTokens > 0 {
		ret["completion_tokens_details"] = map[string]any{
			"reasoning_tokens": usage.reasoningTokens,
		}
	}

	return ret
}

func newOpenAIResponseID() string {
	return fmt.Sprintf("chatcmpl_%s", utilrand.GetRandomStringLowercase(24))
}

func (c *openAIChatCodec) newStreamDecoder() transStreamDecoder {
	return &openAIStreamDecoder{}
}

func (c *openAIChatCodec) newStreamEncoder(o *transEncodeOpts) transStreamEncoder {
	return &openAIStreamEncoder{
		id:          newOpenAIResponseID(),
		created:     time.Now().Unix(),
		streamUsage: o.streamUsage,
	}
}

type openAIChunkEnvelope struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Delta struct {
			Content   json.RawMessage `json:"content"`
			ToolCalls []struct {
				Index    *int   `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`

	Usage *openAIUsage `json:"usage"`
}

type openAIStreamDecoder struct {
	isStarted  bool
	isFinished bool

	id    string
	model string

	finishReason transFinishReason
	usage        transUsage

	seenTools map[int]struct{}
}

func (d *openAIStreamDecoder) decode(data []byte) ([]*transEvent, error) {
	if httputils.IsLLMStreamDone(data) {
		return nil, nil
	}

	env := &openAIChunkEnvelope{}
	if err := json.Unmarshal(data, env); err != nil {
		return nil, nil
	}

	var ret []*transEvent

	if !d.isStarted {
		d.isStarted = true
		d.id = env.ID
		d.model = env.Model
		ret = append(ret, &transEvent{
			kind:  transEventStart,
			id:    env.ID,
			model: env.Model,
		})
	}

	if env.Usage != nil {
		d.usage.merge(env.Usage.toTransUsage())
	}

	for _, choice := range env.Choices {
		if choice.FinishReason != "" {
			d.finishReason = openAIFinishReason(choice.FinishReason)
		}

		if text, err := transString(choice.Delta.Content, "content"); err == nil && text != "" {
			ret = append(ret, &transEvent{kind: transEventTextDelta, text: text})
		}

		for _, call := range choice.Delta.ToolCalls {
			index := 0
			if call.Index != nil {
				index = *call.Index
			}

			if _, ok := d.seenTools[index]; !ok &&
				(call.ID != "" || call.Function.Name != "") {
				if d.seenTools == nil {
					d.seenTools = make(map[int]struct{})
				}
				d.seenTools[index] = struct{}{}
				ret = append(ret, &transEvent{
					kind:       transEventToolCallStart,
					index:      index,
					toolCallID: call.ID,
					toolName:   call.Function.Name,
				})
			}

			if call.Function.Arguments != "" {
				ret = append(ret, &transEvent{
					kind:  transEventToolCallDelta,
					index: index,
					text:  call.Function.Arguments,
				})
			}
		}
	}

	return ret, nil
}

func (d *openAIStreamDecoder) finish() []*transEvent {
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

type openAIStreamEncoder struct {
	id      string
	created int64
	model   string

	streamUsage bool
}

func (e *openAIStreamEncoder) chunk(choices []any, usage map[string]any) ([]byte, error) {
	ret := map[string]any{
		"id":      e.id,
		"object":  openAIObjectChunk,
		"created": e.created,
		"model":   e.model,
		"choices": choices,
	}

	if usage != nil {
		ret["usage"] = usage
	}

	return sseEventOf("", ret)
}

func (e *openAIStreamEncoder) deltaChunk(delta map[string]any,
	finishReason string) ([]byte, error) {

	choice := map[string]any{
		"index": 0,
		"delta": delta,
	}
	if finishReason != "" {
		choice["finish_reason"] = finishReason
	} else {
		choice["finish_reason"] = nil
	}

	return e.chunk([]any{choice}, nil)
}

func (e *openAIStreamEncoder) encode(ev *transEvent) ([]byte, error) {
	switch ev.kind {
	case transEventStart:
		e.model = ev.model
		return e.deltaChunk(map[string]any{
			"role":    roleAssistant,
			"content": "",
		}, "")
	case transEventTextDelta:
		return e.deltaChunk(map[string]any{"content": ev.text}, "")
	case transEventToolCallStart:
		return e.deltaChunk(map[string]any{
			"tool_calls": []any{
				map[string]any{
					"index": ev.index,
					"id":    ev.toolCallID,
					"type":  functionToolKind,
					"function": map[string]any{
						"name":      ev.toolName,
						"arguments": "",
					},
				},
			},
		}, "")
	case transEventToolCallDelta:
		return e.deltaChunk(map[string]any{
			"tool_calls": []any{
				map[string]any{
					"index": ev.index,
					"function": map[string]any{
						"arguments": ev.text,
					},
				},
			},
		}, "")
	case transEventFinish:
		return e.encodeFinish(ev)
	default:
		return nil, nil
	}
}

func (e *openAIStreamEncoder) encodeFinish(ev *transEvent) ([]byte, error) {
	finishReason := toOpenAIFinishReason(ev.finishReason)
	if finishReason == "" {
		finishReason = "stop"
	}

	ret, err := e.deltaChunk(map[string]any{}, finishReason)
	if err != nil {
		return nil, err
	}

	if e.streamUsage && ev.usage.isSet {
		usage, err := e.chunk([]any{}, encodeOpenAIUsage(ev.usage))
		if err != nil {
			return nil, err
		}
		ret = append(ret, usage...)
	}

	return append(ret, sseEvent("", []byte("[DONE]"))...), nil
}

func (e *openAIStreamEncoder) encodeError(message string) []byte {
	ret, err := sseEventOf("", &openAIErrorResponse{
		Error: &openAIError{
			Message: message,
			Type:    ErrTypeAPI,
			Code:    ErrCodeTranslation,
		},
	})
	if err != nil {
		return nil
	}

	return ret
}
