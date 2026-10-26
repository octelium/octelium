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

	"github.com/go-json-experiment/json/jsontext"
	"github.com/pkg/errors"
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

var (
	mcpEnvelopeMembers = []string{"jsonrpc", "id", "method", "params"}
	mcpParamsMembers   = []string{
		"name", "uri", "ref", "arguments", "_meta", "protocolVersion", "clientInfo", "capabilities",
	}
	mcpRefMembers        = []string{"name", "uri"}
	mcpClientInfoMembers = []string{"name", "version", "title"}
)

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
	HasInvalidMembers   bool

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

	env := make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &env); err != nil {
		return ret
	}

	ret.IsJSONRPC = true

	if !jsontext.Value(body).IsValid() || hasMCPMemberAlias(env, mcpEnvelopeMembers) {
		ret.HasInvalidMembers = true
		return ret
	}

	ret.JSONRPCVersion, _ = getMCPString(env, "jsonrpc")
	ret.Method, _ = getMCPString(env, "method")

	var isValidRequestID bool
	ret.RequestID, ret.RequestIDRaw, ret.IsNotification, isValidRequestID = parseMCPRequestID(env["id"])
	ret.HasInvalidRequestID = !isValidRequestID

	params, err := getMCPObject(env["params"], mcpParamsMembers)
	if err != nil {
		ret.HasInvalidMembers = true
		return ret
	}

	if params == nil {
		return ret
	}

	if err := setMCPParams(ret, params); err != nil {
		ret.HasInvalidMembers = true
	}

	return ret
}

func setMCPParams(ret *MCPRequest, params map[string]json.RawMessage) error {
	var err error

	ret.Name, err = deriveMCPName(ret.Method, params)
	if err != nil {
		return err
	}

	meta, err := getMCPObject(params["_meta"], nil)
	if err != nil {
		return err
	}

	ret.BodyProtocolVersion, err = getMCPString(meta, mcpMetaProtocolVersion)
	if err != nil {
		return err
	}

	if ret.BodyProtocolVersion == "" && ret.Method == "initialize" {
		ret.BodyProtocolVersion, err = getMCPString(params, "protocolVersion")
		if err != nil {
			return err
		}
	}

	if ret.BodyProtocolVersion != "" {
		ret.ProtocolVersion = ret.BodyProtocolVersion
	}

	if raw, ok := meta[mcpMetaClientInfo]; ok {
		ret.Client, err = getMCPClientInfo(raw)
	} else {
		ret.Client, err = getMCPClientInfo(params["clientInfo"])
	}
	if err != nil {
		return err
	}

	if raw, ok := meta[mcpMetaClientCaps]; ok {
		ret.Capabilities, err = getMCPObjectKeys(raw)
	} else {
		ret.Capabilities, err = getMCPObjectKeys(params["capabilities"])
	}

	return err
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

func deriveMCPName(method string, params map[string]json.RawMessage) (string, error) {
	switch method {
	case "tools/call", "prompts/get":
		return getMCPString(params, "name")
	case "resources/read", "resources/subscribe", "resources/unsubscribe":
		return getMCPString(params, "uri")
	case "completion/complete":
		ref, err := getMCPObject(params["ref"], mcpRefMembers)
		if err != nil {
			return "", err
		}
		name, err := getMCPString(ref, "name")
		if err != nil {
			return "", err
		}
		uri, err := getMCPString(ref, "uri")
		if err != nil {
			return "", err
		}
		if name != "" && uri != "" {
			return "", errors.Errorf("Ambiguous MCP completion reference")
		}
		if name != "" {
			return name, nil
		}
		return uri, nil
	default:
		return "", nil
	}
}

func getMCPClientInfo(raw json.RawMessage) (*MCPClientInfo, error) {
	obj, err := getMCPObject(raw, mcpClientInfoMembers)
	if err != nil || obj == nil {
		return nil, err
	}

	ret := &MCPClientInfo{}

	if ret.Name, err = getMCPString(obj, "name"); err != nil {
		return nil, err
	}
	if ret.Version, err = getMCPString(obj, "version"); err != nil {
		return nil, err
	}
	if ret.Title, err = getMCPString(obj, "title"); err != nil {
		return nil, err
	}

	return ret, nil
}

func getMCPObject(raw json.RawMessage, members []string) (map[string]json.RawMessage, error) {
	if isMCPNull(raw) {
		return nil, nil
	}

	ret := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &ret); err != nil {
		return nil, err
	}

	if hasMCPMemberAlias(ret, members) {
		return nil, errors.Errorf("Ambiguous MCP member")
	}

	return ret, nil
}

func hasMCPMemberAlias(obj map[string]json.RawMessage, members []string) bool {
	for k := range obj {
		for _, member := range members {
			if k != member && strings.EqualFold(k, member) {
				return true
			}
		}
	}

	return false
}

func getMCPString(obj map[string]json.RawMessage, key string) (string, error) {
	raw, ok := obj[key]
	if !ok || isMCPNull(raw) {
		return "", nil
	}

	var ret string
	if err := json.Unmarshal(raw, &ret); err != nil {
		return "", err
	}

	return ret, nil
}

func isMCPNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

func getMCPObjectKeys(raw json.RawMessage) ([]string, error) {
	obj, err := getMCPObject(raw, nil)
	if err != nil {
		return nil, err
	}
	return getMCPMapKeys(obj), nil
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

func GetSSEEventName(event []byte) string {
	for _, line := range bytes.Split(event, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if !bytes.HasPrefix(line, []byte("event:")) {
			continue
		}

		return string(bytes.TrimPrefix(bytes.TrimPrefix(line, []byte("event:")), []byte(" ")))
	}

	return ""
}
