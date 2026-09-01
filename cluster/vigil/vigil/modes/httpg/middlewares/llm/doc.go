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
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/pkg/errors"
)

const (
	roleSystem    = "system"
	roleDeveloper = "developer"
	roleUser      = "user"
	roleAssistant = "assistant"
)

const functionToolKind = "function"

type doc struct {
	protocol  corev1.Service_Spec_Config_LLM_Protocol
	operation corev1.RequestContext_Request_LLM_Operation

	root    map[string]json.RawMessage
	changed bool
}

func newDoc(protocol corev1.Service_Spec_Config_LLM_Protocol,
	operation corev1.RequestContext_Request_LLM_Operation, body []byte) (*doc, error) {
	root := make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, errors.Errorf("Could not parse the inference request body")
	}

	return &doc{
		protocol:  protocol,
		operation: operation,
		root:      root,
	}, nil
}

func (d *doc) isChanged() bool {
	return d.changed
}

func (d *doc) bytes() ([]byte, error) {
	return json.Marshal(d.root)
}

func (d *doc) instructionsKey() string {
	switch d.protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return "system"
	default:
		switch d.operation {
		case corev1.RequestContext_Request_LLM_RESPONSES:
			return "instructions"
		default:
			return ""
		}
	}
}

func (d *doc) messagesKey() string {
	switch d.operation {
	case corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
		corev1.RequestContext_Request_LLM_MESSAGES,
		corev1.RequestContext_Request_LLM_COUNT_TOKENS:
		return "messages"
	case corev1.RequestContext_Request_LLM_RESPONSES:
		return "input"
	default:
		return ""
	}
}

func (d *doc) hasInstructionsCarrier() bool {
	if d.instructionsKey() != "" {
		return true
	}
	return d.operation == corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS
}

func (d *doc) hasMessagesCarrier() bool {
	return d.messagesKey() != ""
}

func (d *doc) hasToolsCarrier() bool {
	switch d.operation {
	case corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
		corev1.RequestContext_Request_LLM_RESPONSES,
		corev1.RequestContext_Request_LLM_MESSAGES,
		corev1.RequestContext_Request_LLM_COUNT_TOKENS:
		return true
	default:
		return false
	}
}

func (d *doc) promptKey() string {
	switch d.operation {
	case corev1.RequestContext_Request_LLM_COMPLETIONS:
		return "prompt"
	case corev1.RequestContext_Request_LLM_EMBEDDINGS,
		corev1.RequestContext_Request_LLM_MODERATIONS:
		return "input"
	default:
		return ""
	}
}

func (d *doc) hasInstructionMessages() bool {
	switch d.operation {
	case corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
		corev1.RequestContext_Request_LLM_RESPONSES:
		return true
	default:
		return false
	}
}

type message struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`

	rest map[string]json.RawMessage
}

func (m *message) UnmarshalJSON(data []byte) error {
	rest := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &rest); err != nil {
		return err
	}

	if raw, ok := rest["role"]; ok {
		if err := json.Unmarshal(raw, &m.Role); err != nil {
			return err
		}
		delete(rest, "role")
	}
	if raw, ok := rest["content"]; ok {
		m.Content = raw
		delete(rest, "content")
	}

	m.rest = rest
	return nil
}

func (m *message) MarshalJSON() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(m.rest)+2)
	for k, v := range m.rest {
		out[k] = v
	}

	if m.Role != "" {
		role, err := json.Marshal(m.Role)
		if err != nil {
			return nil, err
		}
		out["role"] = role
	}

	if len(m.Content) > 0 {
		out["content"] = m.Content
	}

	return json.Marshal(out)
}

func (m *message) isItem() bool {
	if m.Role != "" {
		return false
	}
	_, ok := m.rest["type"]
	return ok
}

func (m *message) itemType() string {
	raw, ok := m.rest["type"]
	if !ok {
		return ""
	}
	var ret string
	if err := json.Unmarshal(raw, &ret); err != nil {
		return ""
	}
	return ret
}

func (d *doc) messages() ([]*message, error) {
	key := d.messagesKey()
	if key == "" {
		return nil, nil
	}

	raw, ok := d.root[key]
	if !ok || len(raw) == 0 {
		return nil, nil
	}

	if raw[0] == '"' {
		var arg string
		if err := json.Unmarshal(raw, &arg); err != nil {
			return nil, errors.Errorf("Could not parse the request input")
		}
		content, err := json.Marshal(arg)
		if err != nil {
			return nil, err
		}
		return []*message{{Role: roleUser, Content: content}}, nil
	}

	var ret []*message
	if err := json.Unmarshal(raw, &ret); err != nil {
		return nil, errors.Errorf("Could not parse the request messages")
	}

	return ret, nil
}

func (d *doc) setMessages(msgs []*message) error {
	key := d.messagesKey()
	if key == "" {
		return errors.Errorf("This operation carries no conversation messages")
	}

	raw, err := json.Marshal(msgs)
	if err != nil {
		return err
	}

	d.root[key] = raw
	d.changed = true
	return nil
}

func (d *doc) textBlockType(role string) string {
	if d.operation != corev1.RequestContext_Request_LLM_RESPONSES {
		return "text"
	}
	if role == roleAssistant {
		return "output_text"
	}
	return "input_text"
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func newTextContent(text string) (json.RawMessage, error) {
	return json.Marshal(text)
}

func (d *doc) insertIntoContent(role string, content json.RawMessage,
	text string, isPrepend bool) (json.RawMessage, bool, error) {
	if len(content) == 0 {
		ret, err := newTextContent(text)
		return ret, err == nil, err
	}

	switch content[0] {
	case '"':
		var cur string
		if err := json.Unmarshal(content, &cur); err != nil {
			return content, false, nil
		}
		var ret string
		if isPrepend {
			ret = text + "\n\n" + cur
		} else {
			ret = cur + "\n\n" + text
		}
		raw, err := json.Marshal(ret)
		if err != nil {
			return content, false, err
		}
		return raw, true, nil
	case '[':
		var blocks []json.RawMessage
		if err := json.Unmarshal(content, &blocks); err != nil {
			return content, false, nil
		}
		block, err := json.Marshal(&contentBlock{
			Type: d.textBlockType(role),
			Text: text,
		})
		if err != nil {
			return content, false, err
		}
		if isPrepend {
			blocks = append([]json.RawMessage{block}, blocks...)
		} else {
			blocks = append(blocks, block)
		}
		raw, err := json.Marshal(blocks)
		if err != nil {
			return content, false, err
		}
		return raw, true, nil
	default:
		return content, false, nil
	}
}

func contentText(content json.RawMessage) string {
	if len(content) == 0 {
		return ""
	}

	switch content[0] {
	case '"':
		var ret string
		if err := json.Unmarshal(content, &ret); err != nil {
			return ""
		}
		return ret
	case '[':
		var blocks []map[string]any
		if err := json.Unmarshal(content, &blocks); err != nil {
			return ""
		}
		var ret string
		for _, block := range blocks {
			for _, key := range []string{"text", "input_text", "output_text"} {
				if val, ok := block[key].(string); ok {
					if ret != "" {
						ret = ret + "\n"
					}
					ret = ret + val
				}
			}
		}
		return ret
	default:
		return ""
	}
}

func isInstructionRole(role string) bool {
	return role == roleSystem || role == roleDeveloper
}

func (d *doc) instructions() (string, error) {
	var ret string

	if key := d.instructionsKey(); key != "" {
		ret = contentText(d.root[key])
	}

	if !d.hasInstructionMessages() {
		return ret, nil
	}

	msgs, err := d.messages()
	if err != nil {
		return "", err
	}

	for _, msg := range msgs {
		if !isInstructionRole(msg.Role) {
			continue
		}
		if ret != "" {
			ret = ret + "\n\n"
		}
		ret = ret + contentText(msg.Content)
	}

	return ret, nil
}

func (d *doc) replaceInstructions(text string) error {
	key := d.instructionsKey()

	if key != "" {
		if text == "" {
			if _, ok := d.root[key]; ok {
				delete(d.root, key)
				d.changed = true
			}
		} else {
			raw, err := json.Marshal(text)
			if err != nil {
				return err
			}
			d.root[key] = raw
			d.changed = true
		}
	}

	if !d.hasInstructionMessages() {
		if key == "" {
			return errors.Errorf("This operation carries no system instructions")
		}
		return nil
	}

	msgs, err := d.messages()
	if err != nil {
		return err
	}

	ret := make([]*message, 0, len(msgs)+1)
	if key == "" && text != "" {
		content, err := json.Marshal(text)
		if err != nil {
			return err
		}
		ret = append(ret, &message{Role: roleSystem, Content: content})
	}

	var isStripped bool
	for _, msg := range msgs {
		if isInstructionRole(msg.Role) {
			isStripped = true
			continue
		}
		ret = append(ret, msg)
	}

	if !isStripped && (key != "" || text == "") {
		return nil
	}

	return d.setMessages(ret)
}

func (d *doc) insertInstructions(text string, isPrepend bool) error {
	if text == "" {
		return nil
	}

	if key := d.instructionsKey(); key != "" {
		raw, ok, err := d.insertIntoContent(roleSystem, d.root[key], text, isPrepend)
		if err != nil {
			return err
		}
		if !ok {
			return errors.Errorf("Could not insert into the request instructions")
		}
		d.root[key] = raw
		d.changed = true
		return nil
	}

	if !d.hasInstructionMessages() {
		return errors.Errorf("This operation carries no system instructions")
	}

	msgs, err := d.messages()
	if err != nil {
		return err
	}

	content, err := json.Marshal(text)
	if err != nil {
		return err
	}
	inserted := &message{Role: roleSystem, Content: content}

	idx := 0
	if !isPrepend {
		for i, msg := range msgs {
			if isInstructionRole(msg.Role) {
				idx = i + 1
			}
		}
	}

	ret := make([]*message, 0, len(msgs)+1)
	ret = append(ret, msgs[:idx]...)
	ret = append(ret, inserted)
	ret = append(ret, msgs[idx:]...)

	return d.setMessages(ret)
}

func (d *doc) toolsRaw() json.RawMessage {
	return d.root["tools"]
}

func (d *doc) setToolsRaw(raw json.RawMessage) {
	if len(raw) == 0 {
		delete(d.root, "tools")
	} else {
		d.root["tools"] = raw
	}
	d.changed = true
}

type tool struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Function *struct {
		Name string `json:"name"`
	} `json:"function"`
}

func (t *tool) name() string {
	if t.Function != nil && t.Function.Name != "" {
		return t.Function.Name
	}
	return t.Name
}

func (t *tool) kind() string {
	if t.Type == "" {
		return functionToolKind
	}
	return t.Type
}

func (t *tool) label() string {
	if name := t.name(); name != "" {
		return name
	}
	return t.kind()
}

func (d *doc) tools() ([]*tool, []json.RawMessage, error) {
	raw := d.toolsRaw()
	if len(raw) == 0 {
		return nil, nil, nil
	}

	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, nil, errors.Errorf("Could not parse the declared tools")
	}

	ret := make([]*tool, 0, len(entries))
	for _, entry := range entries {
		t := &tool{}
		if err := json.Unmarshal(entry, t); err != nil {
			return nil, nil, errors.Errorf("Could not parse a declared tool")
		}
		ret = append(ret, t)
	}

	return ret, entries, nil
}

func (d *doc) toolChoice() json.RawMessage {
	return d.root["tool_choice"]
}

func (d *doc) setToolChoice(raw json.RawMessage) {
	if len(raw) == 0 {
		delete(d.root, "tool_choice")
	} else {
		d.root["tool_choice"] = raw
	}
	d.changed = true
}

func isBodyParsedOperation(operation corev1.RequestContext_Request_LLM_Operation) bool {
	return httputils.IsLLMOperationBodyParsed(operation)
}

type textPart struct {
	scope corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope
	text  string
	set   func(string) error
}

func hasScope(scopes []corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope,
	arg corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope) bool {
	if len(scopes) == 0 {
		return arg == corev1.Service_Spec_Config_LLM_Plugin_Guardrail_CONTENT
	}
	for _, scope := range scopes {
		if scope == corev1.Service_Spec_Config_LLM_Plugin_Guardrail_ALL || scope == arg {
			return true
		}
	}
	return false
}

func (d *doc) textParts(
	scopes []corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope) ([]*textPart, error) {
	var ret []*textPart

	if hasScope(scopes, corev1.Service_Spec_Config_LLM_Plugin_Guardrail_INSTRUCTIONS) {
		if key := d.instructionsKey(); key != "" {
			if raw, ok := d.root[key]; ok {
				ret = append(ret, d.contentParts(
					corev1.Service_Spec_Config_LLM_Plugin_Guardrail_INSTRUCTIONS,
					roleSystem, raw, func(updated json.RawMessage) error {
						d.root[key] = updated
						d.changed = true
						return nil
					})...)
			}
		}
	}

	if d.hasMessagesCarrier() {
		msgs, err := d.messages()
		if err != nil {
			return nil, err
		}

		for i := range msgs {
			msg := msgs[i]
			apply := func(updated json.RawMessage) error {
				msg.Content = updated
				return d.setMessages(msgs)
			}

			if scope := d.scopeOfMessage(msg); scope != scopeNone {
				if !hasScope(scopes, scope) {
					continue
				}
				ret = append(ret, d.contentParts(scope, msg.Role, msg.Content, apply)...)
				ret = append(ret, d.itemParts(scope, msg, msgs)...)
				continue
			}

			ret = append(ret, d.blockParts(scopes, msg, apply)...)
		}
	}

	if hasScope(scopes, corev1.Service_Spec_Config_LLM_Plugin_Guardrail_CONTENT) {
		if key := d.promptKey(); key != "" {
			if raw, ok := d.root[key]; ok {
				ret = append(ret, d.promptParts(key, raw)...)
			}
		}
	}

	if hasScope(scopes, corev1.Service_Spec_Config_LLM_Plugin_Guardrail_TOOL_DEFINITIONS) {
		if raw := d.toolsRaw(); len(raw) > 0 {
			ret = append(ret, &textPart{
				scope: corev1.Service_Spec_Config_LLM_Plugin_Guardrail_TOOL_DEFINITIONS,
				text:  string(raw),
			})
		}
	}

	return ret, nil
}

const scopeNone = corev1.Service_Spec_Config_LLM_Plugin_Guardrail_SCOPE_UNSET

func (d *doc) promptParts(key string, raw json.RawMessage) []*textPart {
	scope := corev1.Service_Spec_Config_LLM_Plugin_Guardrail_CONTENT

	apply := func(updated json.RawMessage) error {
		d.root[key] = updated
		d.changed = true
		return nil
	}

	if len(raw) > 0 && raw[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil
		}

		var ret []*textPart
		for i := range items {
			idx := i
			if len(items[idx]) == 0 || items[idx][0] != '"' {
				ret = append(ret, &textPart{scope: scope, text: string(items[idx])})
				continue
			}

			var cur string
			if err := json.Unmarshal(items[idx], &cur); err != nil {
				continue
			}

			ret = append(ret, &textPart{
				scope: scope,
				text:  cur,
				set: func(updated string) error {
					val, err := json.Marshal(updated)
					if err != nil {
						return err
					}
					items[idx] = val
					out, err := json.Marshal(items)
					if err != nil {
						return err
					}
					return apply(out)
				},
			})
		}
		return ret
	}

	return d.contentParts(scope, roleUser, raw, apply)
}

func (d *doc) scopeOfMessage(
	msg *message) corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope {
	if msg.isItem() {
		switch msg.itemType() {
		case "function_call_output", "computer_call_output", "local_shell_call_output",
			"custom_tool_call_output", "mcp_call", "web_search_call", "file_search_call":
			return corev1.Service_Spec_Config_LLM_Plugin_Guardrail_TOOL_RESULTS
		default:
			return corev1.Service_Spec_Config_LLM_Plugin_Guardrail_CONTENT
		}
	}

	switch {
	case msg.Role == "tool" || msg.Role == "function":
		return corev1.Service_Spec_Config_LLM_Plugin_Guardrail_TOOL_RESULTS
	case d.hasInstructionMessages() && isInstructionRole(msg.Role):
		return corev1.Service_Spec_Config_LLM_Plugin_Guardrail_INSTRUCTIONS
	default:
		return scopeNone
	}
}

func (d *doc) itemParts(scope corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope,
	msg *message, msgs []*message) []*textPart {
	if !msg.isItem() {
		return nil
	}

	var ret []*textPart
	for _, key := range []string{"output", "text"} {
		raw, ok := msg.rest[key]
		if !ok || len(raw) == 0 {
			continue
		}

		itemKey := key
		apply := func(updated json.RawMessage) error {
			msg.rest[itemKey] = updated
			return d.setMessages(msgs)
		}

		if raw[0] == '[' {
			ret = append(ret, d.nestedBlockParts(scope, raw, apply)...)
			continue
		}

		var cur string
		if err := json.Unmarshal(raw, &cur); err != nil {
			ret = append(ret, &textPart{scope: scope, text: string(raw)})
			continue
		}

		ret = append(ret, &textPart{
			scope: scope,
			text:  cur,
			set: func(updated string) error {
				val, err := json.Marshal(updated)
				if err != nil {
					return err
				}
				return apply(val)
			},
		})
	}

	return ret
}

func (d *doc) blockParts(scopes []corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope,
	msg *message, apply func(json.RawMessage) error) []*textPart {

	content := msg.Content
	if len(content) == 0 || content[0] != '[' {
		scope := corev1.Service_Spec_Config_LLM_Plugin_Guardrail_CONTENT
		if !hasScope(scopes, scope) {
			return nil
		}
		return d.contentParts(scope, msg.Role, content, apply)
	}

	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(content, &blocks); err != nil {
		return nil
	}

	var ret []*textPart
	for i := range blocks {
		idx := i
		scope := scopeOfBlock(blocks[idx])
		if !hasScope(scopes, scope) {
			continue
		}

		ret = append(ret, d.blockTextParts(scope, msg.Role, blocks, idx, apply)...)
	}

	return ret
}

func scopeOfBlock(
	block map[string]json.RawMessage) corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope {
	raw, ok := block["type"]
	if !ok {
		return corev1.Service_Spec_Config_LLM_Plugin_Guardrail_CONTENT
	}

	var typ string
	if err := json.Unmarshal(raw, &typ); err != nil {
		return corev1.Service_Spec_Config_LLM_Plugin_Guardrail_CONTENT
	}

	switch {
	case typ == "tool_result" || typ == "function_call_output" ||
		typ == "search_result" || strings.HasSuffix(typ, "_tool_result"):
		return corev1.Service_Spec_Config_LLM_Plugin_Guardrail_TOOL_RESULTS
	default:
		return corev1.Service_Spec_Config_LLM_Plugin_Guardrail_CONTENT
	}
}

func (d *doc) blockTextParts(scope corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope,
	role string, blocks []map[string]json.RawMessage, idx int,
	apply func(json.RawMessage) error) []*textPart {

	commit := func() error {
		out, err := json.Marshal(blocks)
		if err != nil {
			return err
		}
		return apply(out)
	}

	var ret []*textPart
	for _, key := range []string{"text", "input_text", "output_text", "output", "content"} {
		raw, ok := blocks[idx][key]
		if !ok || len(raw) == 0 {
			continue
		}

		if raw[0] == '[' {
			ret = append(ret, d.nestedBlockParts(scope, raw, func(
				updated json.RawMessage) error {
				blocks[idx][key] = updated
				return commit()
			})...)
			continue
		}

		var cur string
		if err := json.Unmarshal(raw, &cur); err != nil {
			continue
		}

		blockKey := key
		ret = append(ret, &textPart{
			scope: scope,
			text:  cur,
			set: func(updated string) error {
				val, err := json.Marshal(updated)
				if err != nil {
					return err
				}
				blocks[idx][blockKey] = val
				return commit()
			},
		})
	}

	if len(ret) == 0 {
		raw, err := json.Marshal(blocks[idx])
		if err != nil {
			return nil
		}
		return []*textPart{{scope: scope, text: string(raw)}}
	}

	return ret
}

func (d *doc) nestedBlockParts(scope corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope,
	content json.RawMessage, apply func(json.RawMessage) error) []*textPart {

	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(content, &blocks); err != nil {
		return nil
	}

	var ret []*textPart
	for i := range blocks {
		ret = append(ret, d.blockTextParts(scope, "", blocks, i, apply)...)
	}

	return ret
}

func (d *doc) contentParts(scope corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Scope,
	role string, content json.RawMessage, apply func(json.RawMessage) error) []*textPart {
	if len(content) == 0 {
		return nil
	}

	switch content[0] {
	case '"':
		var cur string
		if err := json.Unmarshal(content, &cur); err != nil {
			return nil
		}
		return []*textPart{{
			scope: scope,
			text:  cur,
			set: func(updated string) error {
				raw, err := json.Marshal(updated)
				if err != nil {
					return err
				}
				return apply(raw)
			},
		}}
	case '[':
		var blocks []map[string]json.RawMessage
		if err := json.Unmarshal(content, &blocks); err != nil {
			return nil
		}

		var ret []*textPart
		for i := range blocks {
			ret = append(ret, d.blockTextParts(scope, role, blocks, i, apply)...)
		}

		if len(ret) == 0 {
			return []*textPart{{scope: scope, text: string(content)}}
		}

		return ret
	default:
		return []*textPart{{scope: scope, text: string(content)}}
	}
}
