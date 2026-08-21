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

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
)

const testDomain = "example.com"

const toolsCallBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
	`"params":{"name":"add","arguments":{"a":1,"b":2},` +
	`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`

func newService() *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "my-mcp.default",
			Uid:  "d3d0d2a2-0000-0000-0000-000000000001",
		},
		Spec: &corev1.Service_Spec{
			Mode:     corev1.Service_Spec_MCP,
			IsPublic: true,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "default"},
		},
	}
}

type guardResult struct {
	isNext      bool
	code        int
	errCode     int
	body        string
	errBodyID   any
	errBodyData map[string]any
	hasBodyID   bool
}

func serveGuard(t *testing.T, method, path, body string,
	headers map[string]string, cfg *corev1.Service_Spec_Config_MCP) *guardResult {

	hdr := http.Header{}
	for k, v := range headers {
		if v == "" {
			continue
		}
		hdr.Set(k, v)
	}

	var deleted []string
	for k, v := range headers {
		if v == "" {
			deleted = append(deleted, k)
		}
	}

	return serveGuardHeader(t, method, path, body, hdr, deleted, cfg)
}

func serveGuardHeader(t *testing.T, method, path, body string,
	headers http.Header, deleted []string,
	cfg *corev1.Service_Spec_Config_MCP) *guardResult {

	ctx := context.Background()
	ret := &guardResult{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ret.isNext = true
	})

	mdlwr, err := NewGuard(ctx, next, testDomain)
	assert.Nil(t, err)

	req := httptest.NewRequest(method, "http://my-mcp.example.com"+path, strings.NewReader(body))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vals := range headers {
		req.Header.Del(k)
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	for _, k := range deleted {
		req.Header.Del(k)
	}

	req = req.WithContext(context.WithValue(ctx,
		middlewares.CtxRequestContext,
		&middlewares.RequestContext{
			CreatedAt: time.Now(),
			Service:   newService(),
			ServiceConfig: &corev1.Service_Spec_Config{
				Type: &corev1.Service_Spec_Config_Mcp{Mcp: cfg},
			},
			Body: []byte(body),
			MCP:  httputils.ParseMCPRequest(req, []byte(body)),
		}))

	rw := httptest.NewRecorder()
	mdlwr.ServeHTTP(rw, req)

	ret.code = rw.Code
	ret.body = rw.Body.String()

	if !ret.isNext && rw.Body.Len() > 0 {
		parsed := map[string]any{}
		if err := json.Unmarshal(rw.Body.Bytes(), &parsed); err == nil {
			ret.errBodyID, ret.hasBodyID = parsed["id"]
			if e, ok := parsed["error"].(map[string]any); ok {
				if c, ok := e["code"].(float64); ok {
					ret.errCode = int(c)
				}
				ret.errBodyData, _ = e["data"].(map[string]any)
			}
		}
	}

	return ret
}

func TestGuard(t *testing.T) {

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			httputils.MCPHeaderProtocolVersion: "2026-07-28",
			httputils.MCPHeaderMethod:          "tools/call",
			httputils.MCPHeaderName:            "add",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/", toolsCallBody, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp",
			`{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}

	{
		ctx := context.Background()
		var isNext bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isNext = true
		})

		mdlwr, err := NewGuard(ctx, next, testDomain)
		assert.Nil(t, err)

		svc := newService()
		svc.Spec.Mode = corev1.Service_Spec_HTTP

		req := httptest.NewRequest(http.MethodGet, "http://localhost/anything", nil)
		req = req.WithContext(context.WithValue(ctx, middlewares.CtxRequestContext,
			&middlewares.RequestContext{CreatedAt: time.Now(), Service: svc}))

		mdlwr.ServeHTTP(httptest.NewRecorder(), req)

		assert.True(t, isNext)
	}
}

func TestGuardTransport(t *testing.T) {

	{
		ret := serveGuard(t, http.MethodGet, "/mcp", "", nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusMethodNotAllowed, ret.code)
	}

	{
		ret := serveGuard(t, http.MethodDelete, "/mcp", "", nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusMethodNotAllowed, ret.code)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody,
			map[string]string{"Content-Type": ""}, &corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusUnsupportedMediaType, ret.code)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody,
			map[string]string{"Content-Type": "text/plain"}, &corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusUnsupportedMediaType, ret.code)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody,
			map[string]string{"Content-Type": "application/json; charset=utf-8"},
			&corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}
}

func TestGuardEndpoint(t *testing.T) {

	cfg := &corev1.Service_Spec_Config_MCP{
		Endpoint: "/mcp",
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, nil, cfg)
		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/other", toolsCallBody, nil, cfg)

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusNotFound, ret.code)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/other", toolsCallBody, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}
}

func TestGuardEnvelope(t *testing.T) {

	tsts := []struct {
		body    string
		code    int
		errCode int
	}{
		{`{not json`, http.StatusBadRequest, ErrCodeParse},
		{``, http.StatusBadRequest, ErrCodeParse},
		{`{"jsonrpc":"1.0","id":1,"method":"tools/list"}`, http.StatusBadRequest, ErrCodeInvalidRequest},
		{`{"id":1,"method":"tools/list"}`, http.StatusBadRequest, ErrCodeInvalidRequest},
		{`{"jsonrpc":"2.0","id":1}`, http.StatusBadRequest, ErrCodeInvalidRequest},
		{`{"jsonrpc":"2.0","id":1,"method":""}`, http.StatusBadRequest, ErrCodeInvalidRequest},
		{`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, http.StatusBadRequest, ErrCodeInvalidRequest},
	}

	for _, tst := range tsts {
		ret := serveGuard(t, http.MethodPost, "/mcp", tst.body, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext, tst.body)
		assert.Equal(t, tst.code, ret.code, tst.body)
		assert.Equal(t, tst.errCode, ret.errCode, tst.body)
	}
}

func TestGuardErrorRequestID(t *testing.T) {

	{
		ret := serveGuard(t, http.MethodPost, "/mcp",
			`{"jsonrpc":"1.0","id":42,"method":"tools/list"}`, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.Equal(t, float64(42), ret.errBodyID)
		assert.Contains(t, ret.body, `"jsonrpc":"2.0"`)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp",
			`{"jsonrpc":"1.0","id":"abc","method":"tools/list"}`, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.Equal(t, "abc", ret.errBodyID)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp",
			`{"jsonrpc":"1.0","id":"42","method":"tools/list"}`, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.Equal(t, "42", ret.errBodyID)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp",
			`{"jsonrpc":"1.0","id":"1e5","method":"tools/list"}`, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.Equal(t, "1e5", ret.errBodyID)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", `{not json`, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.hasBodyID)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp",
			`{"jsonrpc":"1.0","id":null,"method":"tools/list"}`, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.hasBodyID)
	}
}

func TestGuardProtocolVersion(t *testing.T) {

	for _, version := range []string{"2026-07-28", "2025-06-18", "2099-01-01"} {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":` +
			`{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + version + `"}}}`

		ret := serveGuard(t, http.MethodPost, "/mcp", body, map[string]string{
			httputils.MCPHeaderProtocolVersion: version,
		}, &corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext, version)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp",
			`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp",
			`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil,
			&corev1.Service_Spec_Config_MCP{
				Protocol: &corev1.Service_Spec_Config_MCP_Protocol{RequireVersion: true},
			})

		assert.False(t, ret.isNext)
		assert.Equal(t, ErrCodeHeaderMismatch, ret.errCode)
		assert.Equal(t, http.StatusBadRequest, ret.code)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, nil,
			&corev1.Service_Spec_Config_MCP{
				Protocol: &corev1.Service_Spec_Config_MCP_Protocol{
					Versions: []string{"2026-07-28"},
				},
			})

		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, nil,
			&corev1.Service_Spec_Config_MCP{
				Protocol: &corev1.Service_Spec_Config_MCP_Protocol{
					Versions: []string{"2025-06-18"},
				},
			})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusBadRequest, ret.code)
		assert.Equal(t, ErrCodeUnsupportedVer, ret.errCode)
		assert.Equal(t, "2026-07-28", ret.errBodyData["requested"])
		assert.Equal(t, []any{"2025-06-18"}, ret.errBodyData["supported"])
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			httputils.MCPHeaderProtocolVersion: "2025-06-18",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusBadRequest, ret.code)
		assert.Equal(t, ErrCodeHeaderMismatch, ret.errCode)
	}
}

func TestGuardMirroredHeaders(t *testing.T) {

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			httputils.MCPHeaderMethod: "tools/list",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusBadRequest, ret.code)
		assert.Equal(t, ErrCodeHeaderMismatch, ret.errCode)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			httputils.MCPHeaderName: "subtract",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, ErrCodeHeaderMismatch, ret.errCode)
	}

	{
		body := `{"jsonrpc":"2.0","id":1,"method":"resources/read",` +
			`"params":{"uri":"file:///ünïcode"}}`

		ret := serveGuard(t, http.MethodPost, "/mcp", body, map[string]string{
			httputils.MCPHeaderName: "=?base64?ZmlsZTovLy/DvG7Dr2NvZGU=?=",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}
}

func TestGuardUnknownMethod(t *testing.T) {

	body := `{"jsonrpc":"2.0","id":1,"method":"acme/customThing","params":{}}`

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", body, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", body, nil,
			&corev1.Service_Spec_Config_MCP{
				Protocol: &corev1.Service_Spec_Config_MCP_Protocol{
					RejectUnknownMethods: true,
				},
			})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusNotFound, ret.code)
		assert.Equal(t, ErrCodeMethodNotFound, ret.errCode)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp",
			`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}`, nil,
			&corev1.Service_Spec_Config_MCP{
				Protocol: &corev1.Service_Spec_Config_MCP_Protocol{
					RejectUnknownMethods: true,
				},
			})

		assert.True(t, ret.isNext)
	}
}

func TestGuardProtectedResourceMetadata(t *testing.T) {

	ret := serveGuard(t, http.MethodGet, PathProtectedResourceMetadata, "", nil,
		&corev1.Service_Spec_Config_MCP{})

	assert.False(t, ret.isNext)
	assert.Equal(t, http.StatusOK, ret.code)

	parsed := map[string]any{}
	assert.Nil(t, json.Unmarshal([]byte(ret.body), &parsed))
	assert.Equal(t, "https://my-mcp.example.com/", parsed["resource"])
	assert.Equal(t, []any{"https://example.com"}, parsed["authorization_servers"])
}

func TestGuardOrigin(t *testing.T) {

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}

	for _, origin := range []string{
		"https://my-mcp.example.com",
		"https://my-mcp.example.com:443",
		"http://my-mcp.example.com",
		"HTTPS://MY-MCP.EXAMPLE.COM",
	} {
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": origin,
		}, &corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext, origin)
	}

	for _, origin := range []string{
		"https://evil.com",
		"https://my-mcp.example.com.evil.com",
		"https://my-mcp.example.com:8443",
		"null",
		"",
		"https://user:pass@my-mcp.example.com",
		"https://my-mcp.example.com/path",
	} {
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": origin,
		}, &corev1.Service_Spec_Config_MCP{})

		if origin == "" {
			assert.True(t, ret.isNext, origin)
			continue
		}

		assert.False(t, ret.isNext, origin)
		assert.Equal(t, http.StatusForbidden, ret.code, origin)
		assert.Equal(t, ErrCodeOriginRejected, ret.errCode, origin)

		assert.False(t, ret.hasBodyID, origin)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": "https://console.example.com",
		}, &corev1.Service_Spec_Config_MCP{
			Cors: &corev1.Service_Spec_Config_HTTP_CORS{
				AllowOriginStringMatch: []string{"https://console.example.com:443"},
			},
		})

		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": "https://evil.com",
		}, &corev1.Service_Spec_Config_MCP{
			DisableOriginCheck: true,
		})

		assert.True(t, ret.isNext)
	}

	{
		hdr := http.Header{}
		hdr.Add("Origin", "https://my-mcp.example.com")
		hdr.Add("Origin", "https://evil.com")

		ret := serveGuardHeader(t, http.MethodPost, "/mcp", toolsCallBody, hdr, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusForbidden, ret.code)
	}

	{
		ret := serveGuard(t, http.MethodGet, "/mcp", "", map[string]string{
			"Origin": "https://evil.com",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusForbidden, ret.code)
	}
}

func TestGuardSingletonHeaders(t *testing.T) {

	for _, hdrName := range []string{
		httputils.MCPHeaderProtocolVersion,
		httputils.MCPHeaderMethod,
		httputils.MCPHeaderName,
		httputils.MCPHeaderSessionID,
	} {
		hdr := http.Header{}
		hdr.Add(hdrName, "2026-07-28")
		hdr.Add(hdrName, "tools/call")

		ret := serveGuardHeader(t, http.MethodPost, "/mcp", toolsCallBody, hdr, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext, hdrName)
		assert.Equal(t, http.StatusBadRequest, ret.code, hdrName)
		assert.Equal(t, ErrCodeHeaderMismatch, ret.errCode, hdrName)
	}
}

func TestGuardInvalidRequestID(t *testing.T) {

	for _, id := range []string{`null`, `true`, `{"a":1}`, `[1]`} {
		body := `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/list"}`

		ret := serveGuard(t, http.MethodPost, "/mcp", body, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext, id)
		assert.Equal(t, http.StatusBadRequest, ret.code, id)
		assert.Equal(t, ErrCodeInvalidRequest, ret.errCode, id)
		assert.False(t, ret.hasBodyID, id)
	}

	for _, id := range []string{`1`, `"req-1"`, `"42"`} {
		body := `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/list"}`

		ret := serveGuard(t, http.MethodPost, "/mcp", body, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext, id)
	}
}

func TestGuardInvalidHeaderName(t *testing.T) {

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			httputils.MCPHeaderName: "=?base64?!!!notbase64!!!?=",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusBadRequest, ret.code)
		assert.Equal(t, ErrCodeHeaderMismatch, ret.errCode)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			httputils.MCPHeaderName: "=?base64?YWRk?=",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}
}

func TestGuardOriginCors(t *testing.T) {
	ctx := context.Background()

	serve := func(cfg *corev1.Service_Spec_Config_MCP, origin string) int {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		mdlwr, err := NewGuard(ctx, next, "example.com")
		assert.Nil(t, err)

		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
		req := httptest.NewRequest(http.MethodPost,
			"http://my-mcp.example.com/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Origin", origin)

		req = req.WithContext(context.WithValue(ctx,
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service: &corev1.Service{
					Metadata: &metav1.Metadata{Name: "my-mcp.default"},
					Spec: &corev1.Service_Spec{
						Mode:     corev1.Service_Spec_MCP,
						IsPublic: true,
					},
					Status: &corev1.Service_Status{
						NamespaceRef: &metav1.ObjectReference{Name: "default"},
					},
				},
				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Mcp{Mcp: cfg},
				},
				MCP: httputils.ParseMCPRequest(req, []byte(body)),
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		return rw.Result().StatusCode
	}

	{
		cfg := &corev1.Service_Spec_Config_MCP{}
		assert.Equal(t, http.StatusForbidden,
			serve(cfg, "https://console.example.com"))
	}

	{
		cfg := &corev1.Service_Spec_Config_MCP{
			Cors: &corev1.Service_Spec_Config_HTTP_CORS{
				AllowOriginStringMatch: []string{"https://console.example.com"},
			},
		}
		assert.Equal(t, http.StatusOK, serve(cfg, "https://console.example.com"))
	}

	{
		cfg := &corev1.Service_Spec_Config_MCP{
			Cors: &corev1.Service_Spec_Config_HTTP_CORS{
				AllowOriginStringMatch: []string{"https://console.example.com"},
			},
		}
		assert.Equal(t, http.StatusForbidden,
			serve(cfg, "https://evil.example.com"))
	}
}

func TestGuardOriginClusterServices(t *testing.T) {

	for _, origin := range []string{
		"https://console.octelium.example.com",
		"https://another-svc.example.com",
		"https://example.com",
	} {
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": origin,
		}, &corev1.Service_Spec_Config_MCP{
			Cors: &corev1.Service_Spec_Config_HTTP_CORS{
				AllowClusterServices: true,
			},
		})

		assert.True(t, ret.isNext, origin)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": "https://notexample.com",
		}, &corev1.Service_Spec_Config_MCP{
			Cors: &corev1.Service_Spec_Config_HTTP_CORS{
				AllowClusterServices: true,
			},
		})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusForbidden, ret.code)
		assert.Equal(t, ErrCodeOriginRejected, ret.errCode)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": "https://console.octelium.example.com",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusForbidden, ret.code)
	}
}
