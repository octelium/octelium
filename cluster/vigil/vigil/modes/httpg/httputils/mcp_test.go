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
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newMCPRequest(body string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://localhost/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestParseMCPRequest(t *testing.T) {

	{
		body := `{
			"jsonrpc": "2.0",
			"id": 1,
			"method": "tools/call",
			"params": {
				"name": "get_weather",
				"arguments": {"location": "Seattle, WA"},
				"_meta": {
					"io.modelcontextprotocol/protocolVersion": "2026-07-28",
					"io.modelcontextprotocol/clientInfo": {"name": "ExampleClient", "version": "1.0.0"},
					"io.modelcontextprotocol/clientCapabilities": {"elicitation": {}}
				}
			}
		}`

		req := newMCPRequest(body, map[string]string{
			MCPHeaderProtocolVersion: "2026-07-28",
			MCPHeaderMethod:          "tools/call",
			MCPHeaderName:            "get_weather",
		})

		ret := ParseMCPRequest(req, []byte(body))

		assert.True(t, ret.IsJSONRPC)
		assert.False(t, ret.IsBatch)
		assert.Equal(t, "2.0", ret.JSONRPCVersion)
		assert.Equal(t, "tools/call", ret.Method)
		assert.Equal(t, "get_weather", ret.Name)
		assert.Equal(t, "1", ret.RequestID)
		assert.False(t, ret.IsNotification)

		assert.Equal(t, "2026-07-28", ret.ProtocolVersion)
		assert.Equal(t, "2026-07-28", ret.BodyProtocolVersion)
		assert.Equal(t, "2026-07-28", ret.HeaderProtocolVersion)

		assert.Equal(t, "tools/call", ret.HeaderMethod)
		assert.True(t, ret.HasHeaderName)
		assert.Equal(t, "get_weather", ret.HeaderName)

		assert.Equal(t, "ExampleClient", ret.Client.GetName())
		assert.Equal(t, "1.0.0", ret.Client.GetVersion())
		assert.Equal(t, []string{"elicitation"}, ret.Capabilities)
	}

	{
		body := `{
			"jsonrpc": "2.0",
			"id": "abc",
			"method": "initialize",
			"params": {
				"protocolVersion": "2025-06-18",
				"clientInfo": {"name": "legacy-client", "version": "0.9"},
				"capabilities": {"roots": {}, "sampling": {}}
			}
		}`

		ret := ParseMCPRequest(newMCPRequest(body, map[string]string{
			MCPHeaderSessionID: "sess-123",
		}), []byte(body))

		assert.Equal(t, "initialize", ret.Method)
		assert.Equal(t, "abc", ret.RequestID)
		assert.Equal(t, "2025-06-18", ret.ProtocolVersion)
		assert.Equal(t, "sess-123", ret.SessionID)
		assert.Equal(t, "", ret.Name)
		assert.Equal(t, "legacy-client", ret.Client.GetName())
		assert.Equal(t, []string{"roots", "sampling"}, ret.Capabilities)
	}

	{
		body := `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///ünïcode"}}`

		ret := ParseMCPRequest(newMCPRequest(body, map[string]string{
			MCPHeaderName: "=?base64?ZmlsZTovLy/DvG7Dr2NvZGU=?=",
		}), []byte(body))

		assert.True(t, ret.HasHeaderName)
		assert.Equal(t, "file:///ünïcode", ret.HeaderName)
		assert.Equal(t, ret.Name, ret.HeaderName)
	}

	{
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"add",
			"_meta":{"io.modelcontextprotocol/clientCapabilities":{"roots":{},
			"extensions":{"io.modelcontextprotocol/tasks":{},
			"io.modelcontextprotocol/ui":{"mimeTypes":["text/html"]}}}}}}`

		ret := ParseMCPRequest(newMCPRequest(body, nil), []byte(body))

		assert.Equal(t, []string{
			"io.modelcontextprotocol/tasks",
			"io.modelcontextprotocol/ui",
			"roots",
		}, ret.Capabilities)
	}

	{
		ret := ParseMCPRequest(nil, nil)
		assert.False(t, ret.IsJSONRPC)

		var nilReq *MCPRequest
		assert.Equal(t, "", nilReq.GetMethod())
		assert.Equal(t, "", nilReq.GetName())
		assert.Equal(t, "", nilReq.GetRequestID())
		assert.Nil(t, nilReq.GetRequestIDRaw())
		assert.Equal(t, "", nilReq.GetProtocolVersion())
		assert.Equal(t, "", nilReq.GetSessionID())
		assert.False(t, nilReq.GetIsNotification())
		assert.Nil(t, nilReq.GetCapabilities())
		assert.Nil(t, nilReq.GetClient())
		assert.Equal(t, "", nilReq.GetClient().GetName())
	}
}

func TestParseMCPRequestName(t *testing.T) {

	tsts := []struct {
		method string
		params string
		name   string
	}{
		{"tools/call", `{"name": "add"}`, "add"},
		{"prompts/get", `{"name": "review"}`, "review"},
		{"resources/read", `{"uri": "file:///a/b.json"}`, "file:///a/b.json"},
		{"resources/subscribe", `{"uri": "file:///a"}`, "file:///a"},
		{"resources/unsubscribe", `{"uri": "file:///a"}`, "file:///a"},
		{"completion/complete", `{"ref": {"name": "p1"}}`, "p1"},
		{"completion/complete", `{"ref": {"uri": "res://x"}}`, "res://x"},
		{"tools/list", `{}`, ""},
		{"server/discover", `{}`, ""},
		{"acme/doThing", `{"name": "ignored"}`, ""},
	}

	for _, tst := range tsts {
		body := `{"jsonrpc":"2.0","id":1,"method":"` + tst.method + `","params":` + tst.params + `}`
		ret := ParseMCPRequest(newMCPRequest(body, nil), []byte(body))

		assert.Equal(t, tst.method, ret.Method)
		assert.Equal(t, tst.name, ret.Name, tst.method)
	}
}

func TestParseMCPRequestID(t *testing.T) {

	tsts := []struct {
		id             string
		requestID      string
		requestIDRaw   string
		isNotification bool
		isInvalid      bool
	}{
		{`1`, "1", `1`, false, false},
		{`9007199254740993`, "9007199254740993", `9007199254740993`, false, false},
		{`"req-1"`, "req-1", `"req-1"`, false, false},
		{`"42"`, "42", `"42"`, false, false},
		{`"1e5"`, "1e5", `"1e5"`, false, false},

		{`null`, "", ``, false, true},
		{`true`, "true", ``, false, true},
		{`{"a":1}`, `{"a":1}`, ``, false, true},
		{`[1]`, `[1]`, ``, false, true},
	}

	for _, tst := range tsts {
		body := `{"jsonrpc":"2.0","id":` + tst.id + `,"method":"tools/list"}`
		ret := ParseMCPRequest(newMCPRequest(body, nil), []byte(body))

		assert.Equal(t, tst.requestID, ret.RequestID, tst.id)
		assert.Equal(t, tst.requestIDRaw, string(ret.RequestIDRaw), tst.id)
		assert.Equal(t, tst.isNotification, ret.IsNotification, tst.id)
		assert.Equal(t, tst.isInvalid, ret.HasInvalidRequestID, tst.id)
	}

	{
		body := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
		ret := ParseMCPRequest(newMCPRequest(body, nil), []byte(body))

		assert.True(t, ret.IsNotification)
		assert.False(t, ret.HasInvalidRequestID)
		assert.Equal(t, "", ret.RequestID)
	}

	{
		ret := ParseMCPResponse([]byte(
			`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}`))

		assert.True(t, ret.IsError)
		assert.False(t, ret.IsNotification)
		assert.Equal(t, "", ret.RequestID)
	}
}

func TestParseMCPRequestMalformed(t *testing.T) {

	for _, body := range []string{
		``,
		"  \n\t ",
		`not json at all`,
		`{"jsonrpc":"2.0","method":`,
		`42`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"a string"}`,
	} {
		ret := ParseMCPRequest(newMCPRequest(body, nil), []byte(body))
		assert.NotNil(t, ret, body)
	}

	{
		body := `[{"jsonrpc":"2.0","method":"tools/list","id":1}]`
		ret := ParseMCPRequest(newMCPRequest(body, nil), []byte(body))

		assert.True(t, ret.IsBatch)
		assert.False(t, ret.IsJSONRPC)
	}

	{
		body := `{"jsonrpc":"2.0","id":1,"method":42}`
		ret := ParseMCPRequest(newMCPRequest(body, nil), []byte(body))

		assert.True(t, ret.IsJSONRPC)
		assert.Equal(t, "", ret.Method)
	}
}

func TestDecodeMCPHeaderValue(t *testing.T) {

	tsts := []struct {
		in      string
		out     string
		isValid bool
	}{
		{"us-west1", "us-west1", true},
		{"=?base64?SGVsbG8sIOS4lueVjA==?=", "Hello, 世界", true},
		{"=?base64?IHBhZGRlZCA=?=", " padded ", true},
		{"=?base64?bGluZTEKbGluZTI=?=", "line1\nline2", true},
		{"=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=", "=?base64?literal?=", true},

		{"=?base64?!!!notbase64!!!?=", "=?base64?!!!notbase64!!!?=", false},
		{"=?base64?" + base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe}) + "?=",
			"=?base64?//4=?=", false},

		{"=?base64?abc", "=?base64?abc", true},
		{"=?base64??=", "", true},
		{"", "", true},
	}

	for _, tst := range tsts {
		out, isValid := DecodeMCPHeaderValue(tst.in)
		assert.Equal(t, tst.out, out, tst.in)
		assert.Equal(t, tst.isValid, isValid, tst.in)
	}
}

func TestParseMCPResponse(t *testing.T) {

	{
		ret := ParseMCPResponse([]byte(
			`{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","ttlMs":300000,"cacheScope":"public"}}`))

		assert.Equal(t, "complete", ret.ResultType)
		assert.Equal(t, uint64(300000), ret.TTLMs)
		assert.Equal(t, "public", ret.CacheScope)
		assert.False(t, ret.IsError)
		assert.False(t, ret.IsNotification)
	}

	{
		ret := ParseMCPResponse([]byte(
			`{"jsonrpc":"2.0","id":3,"result":{"resultType":"complete","isError":true,"content":[]}}`))

		assert.True(t, ret.IsToolError)
		assert.False(t, ret.IsError)
	}

	{
		ret := ParseMCPResponse([]byte(
			`{"jsonrpc":"2.0","id":4,"error":{"code":-32020,"message":"Header mismatch"}}`))

		assert.True(t, ret.IsError)
		assert.Equal(t, int32(-32020), ret.ErrorCode)
		assert.Equal(t, "Header mismatch", ret.ErrorMessage)
		assert.False(t, ret.IsToolError)
	}

	{
		ret := ParseMCPResponse([]byte(
			`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":0.5}}`))

		assert.True(t, ret.IsNotification)
		assert.Equal(t, "notifications/progress", ret.Method)
	}

	for _, body := range []string{`[1,2,3]`, ``, `plain text`} {
		assert.Nil(t, ParseMCPResponse([]byte(body)), body)
	}
}

func TestGetSSEEventData(t *testing.T) {

	tsts := []struct {
		event string
		data  string
	}{
		{"data: {\"a\":1}", `{"a":1}`},
		{"event: message\ndata: {\"a\":1}", `{"a":1}`},
		{"data: {\"a\":\ndata: 1}", "{\"a\":\n1}"},
		{": keep-alive", ""},
		{"data:{\"a\":1}", `{"a":1}`},
		{"event: message\r\ndata: {\"a\":1}\r", `{"a":1}`},
		{"id: 5\ndata: {\"a\":1}", `{"a":1}`},
		{"", ""},
	}

	for _, tst := range tsts {
		assert.Equal(t, tst.data, string(GetSSEEventData([]byte(tst.event))), tst.event)
	}
}

func TestIsMCPMethodKnown(t *testing.T) {

	for _, method := range []string{
		"server/discover",
		"tools/list",
		"tools/call",
		"prompts/list",
		"prompts/get",
		"resources/list",
		"resources/read",
		"resources/templates/list",
		"completion/complete",
		"subscriptions/listen",
		"initialize",
		"notifications/initialized",
		"tasks/get",
		"tasks/update",
		"tasks/cancel",
		"notifications/tasks",
	} {
		assert.True(t, IsMCPMethodKnown(method), method)
	}

	for _, method := range []string{
		"", "acme/custom", "tools/", "TOOLS/CALL",
		"tasks/list", "tasks/result", "notifications/tasks/status",
	} {
		assert.False(t, IsMCPMethodKnown(method), method)
	}
}

func FuzzParseMCPRequest(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}}`)
	f.Add(`[{"jsonrpc":"2.0"}]`)
	f.Add(`{"params":{"_meta":{"io.modelcontextprotocol/clientInfo":{}}}}`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, body string) {
		ParseMCPRequest(newMCPRequest(body, nil), []byte(body))
		ParseMCPResponse([]byte(body))
		GetSSEEventData([]byte(body))
		_, _ = DecodeMCPHeaderValue(body)
	})
}
