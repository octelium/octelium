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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	MCPHeaderProtocolVersion = "MCP-Protocol-Version"
	MCPHeaderMethod          = "Mcp-Method"
	MCPHeaderName            = "Mcp-Name"
	MCPHeaderSessionID       = "Mcp-Session-Id"
)

const (
	mcpMetaProtocolVersion = "io.modelcontextprotocol/protocolVersion"
	mcpMetaClientInfo      = "io.modelcontextprotocol/clientInfo"
	mcpMetaClientCaps      = "io.modelcontextprotocol/clientCapabilities"
)

const (
	mcpBase64Prefix = "=?base64?"
	mcpBase64Suffix = "?="
)

const maxMCPCaps = 64

const mcpCapsExtensions = "extensions"

type MCPClientInfo struct {
	Name    string
	Version string
	Title   string
}

type MCPRequest struct {
	IsJSONRPC bool
	IsBatch   bool

	JSONRPCVersion string
	Method         string
	Name           string
	RequestID      string
	RequestIDRaw   json.RawMessage
	IsNotification bool

	HasInvalidRequestID bool

	ProtocolVersion       string
	BodyProtocolVersion   string
	HeaderProtocolVersion string

	HeaderMethod  string
	HeaderName    string
	HasHeaderName bool

	HasInvalidHeaderName bool

	Client       *MCPClientInfo
	Capabilities []string
	SessionID    string
}

func (r *MCPRequest) GetRequestID() string {
	if r == nil {
		return ""
	}
	return r.RequestID
}

func (r *MCPRequest) GetRequestIDRaw() json.RawMessage {
	if r == nil {
		return nil
	}
	return r.RequestIDRaw
}

func (r *MCPRequest) GetMethod() string {
	if r == nil {
		return ""
	}
	return r.Method
}

func (r *MCPRequest) GetName() string {
	if r == nil {
		return ""
	}
	return r.Name
}

func (r *MCPRequest) GetProtocolVersion() string {
	if r == nil {
		return ""
	}
	return r.ProtocolVersion
}

func (r *MCPRequest) GetSessionID() string {
	if r == nil {
		return ""
	}
	return r.SessionID
}

func (r *MCPRequest) GetIsNotification() bool {
	if r == nil {
		return false
	}
	return r.IsNotification
}

func (r *MCPRequest) GetCapabilities() []string {
	if r == nil {
		return nil
	}
	return r.Capabilities
}

func (r *MCPRequest) GetClient() *MCPClientInfo {
	if r == nil {
		return nil
	}
	return r.Client
}

func (c *MCPClientInfo) GetName() string {
	if c == nil {
		return ""
	}
	return c.Name
}

func (c *MCPClientInfo) GetVersion() string {
	if c == nil {
		return ""
	}
	return c.Version
}

func (c *MCPClientInfo) GetTitle() string {
	if c == nil {
		return ""
	}
	return c.Title
}

type mcpEnvelope struct {
	JSONRPC json.RawMessage `json:"jsonrpc"`
	Method  json.RawMessage `json:"method"`
	ID      json.RawMessage `json:"id"`
	Params  json.RawMessage `json:"params"`
}

type mcpClientInfoJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Title   string `json:"title"`
}

type mcpParams struct {
	Name string `json:"name"`
	URI  string `json:"uri"`

	Ref *struct {
		Name string `json:"name"`
		URI  string `json:"uri"`
	} `json:"ref"`

	Meta map[string]json.RawMessage `json:"_meta"`

	ProtocolVersion string                     `json:"protocolVersion"`
	ClientInfo      *mcpClientInfoJSON         `json:"clientInfo"`
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
}

func ParseMCPRequest(req *http.Request, body []byte) *MCPRequest {
	ret := &MCPRequest{}

	if req != nil {
		ret.SessionID = req.Header.Get(MCPHeaderSessionID)
		ret.HeaderProtocolVersion = req.Header.Get(MCPHeaderProtocolVersion)
		ret.HeaderMethod = req.Header.Get(MCPHeaderMethod)

		if vals, ok := req.Header[http.CanonicalHeaderKey(MCPHeaderName)]; ok && len(vals) > 0 {
			ret.HasHeaderName = true
			var isValid bool
			ret.HeaderName, isValid = DecodeMCPHeaderValue(vals[0])
			ret.HasInvalidHeaderName = !isValid
		}
	}

	ret.ProtocolVersion = ret.HeaderProtocolVersion

	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return ret
	}

	if trimmed[0] == '[' {
		ret.IsBatch = true
		return ret
	}

	env := &mcpEnvelope{}
	if err := json.Unmarshal(body, env); err != nil {
		return ret
	}

	ret.IsJSONRPC = true

	if len(env.JSONRPC) > 0 {
		var v string
		if err := json.Unmarshal(env.JSONRPC, &v); err == nil {
			ret.JSONRPCVersion = v
		}
	}

	if len(env.Method) > 0 {
		var v string
		if err := json.Unmarshal(env.Method, &v); err == nil {
			ret.Method = v
		}
	}

	var isValidRequestID bool
	ret.RequestID, ret.RequestIDRaw, ret.IsNotification, isValidRequestID = parseMCPRequestID(env.ID)
	ret.HasInvalidRequestID = !isValidRequestID

	if len(env.Params) == 0 {
		return ret
	}

	params := &mcpParams{}
	if err := json.Unmarshal(env.Params, params); err != nil {
		return ret
	}

	ret.Name = deriveMCPName(ret.Method, params)

	if bodyVersion := getMCPMetaString(params.Meta, mcpMetaProtocolVersion); bodyVersion != "" {
		ret.BodyProtocolVersion = bodyVersion
	} else if params.ProtocolVersion != "" && ret.Method == "initialize" {
		ret.BodyProtocolVersion = params.ProtocolVersion
	}

	if ret.BodyProtocolVersion != "" {
		ret.ProtocolVersion = ret.BodyProtocolVersion
	}

	if raw, ok := params.Meta[mcpMetaClientInfo]; ok {
		info := &mcpClientInfoJSON{}
		if err := json.Unmarshal(raw, info); err == nil {
			ret.Client = &MCPClientInfo{
				Name:    info.Name,
				Version: info.Version,
				Title:   info.Title,
			}
		}
	} else if params.ClientInfo != nil {
		ret.Client = &MCPClientInfo{
			Name:    params.ClientInfo.Name,
			Version: params.ClientInfo.Version,
			Title:   params.ClientInfo.Title,
		}
	}

	if raw, ok := params.Meta[mcpMetaClientCaps]; ok {
		ret.Capabilities = getMCPObjectKeys(raw)
	} else if len(params.Capabilities) > 0 {
		ret.Capabilities = getMCPMapKeys(params.Capabilities)
	}

	return ret
}

func parseMCPRequestID(raw json.RawMessage) (string, json.RawMessage, bool, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", nil, true, true
	}

	if bytes.Equal(trimmed, []byte("null")) {
		return "", nil, false, false
	}

	var str string
	if err := json.Unmarshal(trimmed, &str); err == nil {
		return str, trimmed, false, true
	}

	var num json.Number
	if err := json.Unmarshal(trimmed, &num); err == nil {
		return num.String(), trimmed, false, true
	}

	return string(trimmed), nil, false, false
}

func deriveMCPName(method string, params *mcpParams) string {
	if params == nil {
		return ""
	}

	switch method {
	case "tools/call", "prompts/get":
		return params.Name
	case "resources/read", "resources/subscribe", "resources/unsubscribe":
		return params.URI
	case "completion/complete":
		if params.Ref == nil {
			return ""
		}
		if params.Ref.Name != "" {
			return params.Ref.Name
		}
		return params.Ref.URI
	default:
		return ""
	}
}

func getMCPMetaString(meta map[string]json.RawMessage, key string) string {
	if meta == nil {
		return ""
	}
	raw, ok := meta[key]
	if !ok {
		return ""
	}
	var ret string
	if err := json.Unmarshal(raw, &ret); err != nil {
		return ""
	}
	return ret
}

func getMCPObjectKeys(raw json.RawMessage) []string {
	obj := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	return getMCPMapKeys(obj)
}

func getMCPMapKeys(obj map[string]json.RawMessage) []string {
	if len(obj) == 0 {
		return nil
	}

	ret := make([]string, 0, len(obj))
	for k, v := range obj {
		if k != mcpCapsExtensions {
			ret = append(ret, k)
			continue
		}

		extensions := make(map[string]json.RawMessage)
		if err := json.Unmarshal(v, &extensions); err != nil {
			continue
		}
		for id := range extensions {
			ret = append(ret, id)
		}
	}

	sort.Strings(ret)
	if len(ret) > maxMCPCaps {
		ret = ret[:maxMCPCaps]
	}
	return ret
}

func DecodeMCPHeaderValue(arg string) (string, bool) {
	if len(arg) < len(mcpBase64Prefix)+len(mcpBase64Suffix) ||
		!strings.HasPrefix(arg, mcpBase64Prefix) || !strings.HasSuffix(arg, mcpBase64Suffix) {
		return arg, true
	}

	encoded := arg[len(mcpBase64Prefix) : len(arg)-len(mcpBase64Suffix)]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return arg, false
	}
	if !utf8.Valid(decoded) {
		return arg, false
	}

	return string(decoded), true
}

type MCPResponse struct {
	IsJSONRPC bool

	IsNotification bool
	Method         string

	RequestID string

	ResultType string
	TTLMs      uint64
	CacheScope string

	IsError      bool
	ErrorCode    int32
	ErrorMessage string

	IsToolError bool
}

type mcpResponseEnvelope struct {
	JSONRPC json.RawMessage `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  json.RawMessage `json:"method"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int32  `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type mcpResult struct {
	ResultType string `json:"resultType"`
	TTLMs      uint64 `json:"ttlMs"`
	CacheScope string `json:"cacheScope"`
	IsError    bool   `json:"isError"`
}

func ParseMCPResponse(body []byte) *MCPResponse {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}

	env := &mcpResponseEnvelope{}
	if err := json.Unmarshal(body, env); err != nil {
		return nil
	}

	ret := &MCPResponse{
		IsJSONRPC: true,
	}

	if len(env.Method) > 0 {
		var v string
		if err := json.Unmarshal(env.Method, &v); err == nil {
			ret.Method = v
		}
	}

	var hasNoID bool
	ret.RequestID, _, hasNoID, _ = parseMCPRequestID(env.ID)
	ret.IsNotification = hasNoID && ret.Method != ""

	if env.Error != nil {
		ret.IsError = true
		ret.ErrorCode = env.Error.Code
		ret.ErrorMessage = env.Error.Message
		return ret
	}

	if len(env.Result) > 0 {
		result := &mcpResult{}
		if err := json.Unmarshal(env.Result, result); err == nil {
			ret.ResultType = result.ResultType
			ret.TTLMs = result.TTLMs
			ret.CacheScope = result.CacheScope
			ret.IsToolError = result.IsError
		}
	}

	return ret
}

func GetSSEEventData(event []byte) []byte {
	var ret []byte

	for _, line := range bytes.Split(event, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 || line[0] == ':' {
			continue
		}
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}

		val := line[len("data:"):]
		val = bytes.TrimPrefix(val, []byte(" "))

		if ret != nil {
			ret = append(ret, '\n')
		}
		ret = append(ret, val...)
	}

	return ret
}

func IsMCPMethodKnown(method string) bool {
	_, ok := mcpKnownMethods[method]
	return ok
}

var mcpKnownMethods = map[string]struct{}{
	"server/discover": {},
	"initialize":      {},
	"ping":            {},

	"tools/list":               {},
	"tools/call":               {},
	"prompts/list":             {},
	"prompts/get":              {},
	"resources/list":           {},
	"resources/read":           {},
	"resources/templates/list": {},
	"resources/subscribe":      {},
	"resources/unsubscribe":    {},
	"completion/complete":      {},

	"subscriptions/listen": {},

	"elicitation/create":     {},
	"roots/list":             {},
	"sampling/createMessage": {},
	"logging/setLevel":       {},

	"tasks/get":    {},
	"tasks/update": {},
	"tasks/cancel": {},

	"notifications/initialized":                {},
	"notifications/cancelled":                  {},
	"notifications/progress":                   {},
	"notifications/message":                    {},
	"notifications/roots/list_changed":         {},
	"notifications/tools/list_changed":         {},
	"notifications/prompts/list_changed":       {},
	"notifications/resources/list_changed":     {},
	"notifications/resources/updated":          {},
	"notifications/subscriptions/acknowledged": {},
	"notifications/tasks":                      {},
}
