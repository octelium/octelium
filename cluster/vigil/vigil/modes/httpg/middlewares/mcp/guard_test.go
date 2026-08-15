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
	isNext    bool
	code      int
	errCode   int
	body      string
	errBodyID any
}

func serveGuard(t *testing.T, method, path, body string,
	headers map[string]string, cfg *corev1.Service_Spec_Config_MCP) *guardResult {

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
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
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
			ret.errBodyID = parsed["id"]
			if e, ok := parsed["error"].(map[string]any); ok {
				if c, ok := e["code"].(float64); ok {
					ret.errCode = int(c)
				}
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
		Endpoint: &corev1.Service_Spec_Config_MCP_Endpoint{
			Path:   "/mcp",
			Strict: true,
		},
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
			&corev1.Service_Spec_Config_MCP{
				Endpoint: &corev1.Service_Spec_Config_MCP_Endpoint{Path: "/mcp"},
			})

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

	{
		ret := serveGuard(t, http.MethodPost, "/mcp",
			`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, nil,
			&corev1.Service_Spec_Config_MCP{
				Protocol: &corev1.Service_Spec_Config_MCP_Protocol{AllowBatch: true},
			})

		assert.False(t, ret.isNext)
		assert.Equal(t, ErrCodeParse, ret.errCode)
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
		ret := serveGuard(t, http.MethodPost, "/mcp", `{not json`, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.Nil(t, ret.errBodyID)
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
		assert.Equal(t, ErrCodeUnsupportedVer, ret.errCode)
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

func TestGuardOrigin(t *testing.T) {

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, nil,
			&corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": "https://my-mcp.example.com",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": "https://evil.example.net",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusForbidden, ret.code)
		assert.Equal(t, ErrCodeOriginRejected, ret.errCode)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": "null",
		}, &corev1.Service_Spec_Config_MCP{})

		assert.False(t, ret.isNext)
		assert.Equal(t, http.StatusForbidden, ret.code)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": "https://app.example.net",
		}, &corev1.Service_Spec_Config_MCP{
			Origin: &corev1.Service_Spec_Config_MCP_Origin{
				Allowed: []string{"https://app.example.net"},
			},
		})

		assert.True(t, ret.isNext)
	}

	{
		ret := serveGuard(t, http.MethodPost, "/mcp", toolsCallBody, map[string]string{
			"Origin": "https://evil.example.net",
		}, &corev1.Service_Spec_Config_MCP{
			Origin: &corev1.Service_Spec_Config_MCP_Origin{Disable: true},
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
