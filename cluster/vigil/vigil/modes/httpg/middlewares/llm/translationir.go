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
)

type transBlockKind int

const (
	transBlockText transBlockKind = iota
	transBlockImage
	transBlockToolCall
	transBlockToolResult
)

type transImage struct {
	url       string
	mediaType string
	data      string
}

type transBlock struct {
	kind transBlockKind

	text string

	image *transImage

	toolCallID string
	toolName   string
	toolInput  json.RawMessage

	toolSignature string

	toolResult  json.RawMessage
	isToolError bool
}

type transMessage struct {
	role   string
	blocks []*transBlock
}

func (m *transMessage) hasKind(kind transBlockKind) bool {
	for _, block := range m.blocks {
		if block.kind == kind {
			return true
		}
	}
	return false
}

type transTool struct {
	name        string
	description string
	schema      json.RawMessage
}

type transToolChoiceKind int

const (
	transToolChoiceUnset transToolChoiceKind = iota
	transToolChoiceAuto
	transToolChoiceNone
	transToolChoiceRequired
	transToolChoiceNamed
)

type transToolChoice struct {
	kind            transToolChoiceKind
	name            string
	disableParallel bool
}

type transRequest struct {
	model  string
	stream bool

	streamUsage bool

	maxOutputTokens uint64
	stopSequences   []string

	temperature *float64
	topP        *float64

	userID string

	system   []string
	messages []*transMessage

	tools      []*transTool
	toolChoice *transToolChoice

	reasoningTarget *reasoningTarget

	reasoning       *reasoningValue
	reasoningFormat reasoningFormat
}

type transFinishReason int

const (
	transFinishUnset transFinishReason = iota
	transFinishStop
	transFinishStopSequence
	transFinishLength
	transFinishToolCall
	transFinishContentFilter
)

type transUsage struct {
	inputTokens  uint64
	outputTokens uint64

	totalTokens uint64

	cacheReadTokens     uint64
	cacheCreationTokens uint64

	reasoningTokens uint64

	isSet bool
}

func (u transUsage) total() uint64 {
	if u.totalTokens > 0 {
		return u.totalTokens
	}
	return u.inputTokens + u.outputTokens
}

func (u *transUsage) merge(arg transUsage) {
	if !arg.isSet {
		return
	}

	if arg.inputTokens > 0 {
		u.inputTokens = arg.inputTokens
	}
	if arg.outputTokens > 0 {
		u.outputTokens = arg.outputTokens
	}
	if arg.cacheReadTokens > 0 {
		u.cacheReadTokens = arg.cacheReadTokens
	}
	if arg.cacheCreationTokens > 0 {
		u.cacheCreationTokens = arg.cacheCreationTokens
	}
	if arg.reasoningTokens > 0 {
		u.reasoningTokens = arg.reasoningTokens
	}
	if arg.totalTokens > 0 {
		u.totalTokens = arg.totalTokens
	}

	u.isSet = true
}

func (u transUsage) uncachedInputTokens() uint64 {
	ret := u.inputTokens
	for _, cur := range []uint64{u.cacheReadTokens, u.cacheCreationTokens} {
		if ret < cur {
			return 0
		}
		ret = ret - cur
	}
	return ret
}

type transResponse struct {
	id    string
	model string

	blocks []*transBlock

	finishReason transFinishReason
	stopSequence string

	usage transUsage
}

type transEventKind int

const (
	transEventStart transEventKind = iota
	transEventTextDelta
	transEventToolCallStart
	transEventToolCallDelta
	transEventFinish
)

type transEvent struct {
	kind transEventKind

	id    string
	model string

	text string

	index         int
	toolCallID    string
	toolName      string
	toolSignature string

	finishReason transFinishReason
	stopSequence string

	usage transUsage
}

type transEncodeOpts struct {
	model string

	defaultMaxOutputTokens uint64

	streamUsage bool
}

type transCodec interface {
	protocol() corev1.Service_Spec_Config_LLM_Protocol
	route() corev1.RequestContext_Request_LLM_Route

	decodeRequest(body []byte) (*transRequest, error)
	encodeRequest(req *transRequest, o *transEncodeOpts) (map[string]json.RawMessage, error)

	decodeResponse(body []byte) (*transResponse, error)
	encodeResponse(resp *transResponse, o *transEncodeOpts) ([]byte, error)

	newStreamDecoder() transStreamDecoder
	newStreamEncoder(o *transEncodeOpts) transStreamEncoder

	streamMediaType() string
}

type transStreamDecoder interface {
	decode(eventType string, data []byte) ([]*transEvent, error)
	finish() []*transEvent
}

type transStreamEncoder interface {
	encode(ev *transEvent) ([]byte, error)
	encodeError(message string) []byte
}

func getTransCodec(protocol corev1.Service_Spec_Config_LLM_Protocol,
	route corev1.RequestContext_Request_LLM_Route) transCodec {

	if route != getTransRoute(protocol, corev1.Service_Spec_Config_LLM_GENERATE) {
		return nil
	}

	switch protocol {
	case corev1.Service_Spec_Config_LLM_OPENAI:
		return &openAIChatCodec{}
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return &anthropicMessagesCodec{}
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return &geminiContentCodec{}
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return &bedrockConverseCodec{}
	default:
		return nil
	}
}

func getTransRoute(protocol corev1.Service_Spec_Config_LLM_Protocol,
	operation corev1.Service_Spec_Config_LLM_Operation) corev1.RequestContext_Request_LLM_Route {

	if operation != corev1.Service_Spec_Config_LLM_GENERATE {
		return corev1.RequestContext_Request_LLM_ROUTE_UNSET
	}

	switch protocol {
	case corev1.Service_Spec_Config_LLM_OPENAI:
		return corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return corev1.RequestContext_Request_LLM_MESSAGES
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return corev1.RequestContext_Request_LLM_GENERATE_CONTENT
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		return corev1.RequestContext_Request_LLM_CONVERSE
	default:
		return corev1.RequestContext_Request_LLM_ROUTE_UNSET
	}
}
