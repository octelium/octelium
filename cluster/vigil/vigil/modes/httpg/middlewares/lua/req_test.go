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

package lua

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
)

func newReqTestRequest(t *testing.T, script string,
	body io.Reader, reqCtx *middlewares.RequestContext) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "http://localhost/v1", body)

	reqCtx.CreatedAt = time.Now()
	reqCtx.ReqCtxMap = map[string]any{}
	reqCtx.ServiceConfig.GetHttp().Plugins =
		[]*corev1.Service_Spec_Config_HTTP_Plugin{
			{
				Name: "tst",
				Condition: &corev1.Condition{
					Type: &corev1.Condition_MatchAny{MatchAny: true},
				},
				Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
					Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
						Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
							Inline: script,
						},
					},
				},
			},
		}

	return req.WithContext(context.WithValue(context.Background(),
		middlewares.CtxRequestContext, reqCtx))
}

func newReqTestCtx(maxRequestSize uint32) *middlewares.RequestContext {
	return &middlewares.RequestContext{
		ServiceConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					Body: &corev1.Service_Spec_Config_HTTP_Body{
						MaxRequestSize: maxRequestSize,
					},
				},
			},
		},
	}
}

func TestSetPath(t *testing.T) {
	for _, e := range []struct {
		arg      string
		expected string
	}{
		{"/a/b", "/a/b"},
		{"/a/../b", "/b"},
		{"/../../../etc/passwd", "/etc/passwd"},
		{"/a/./b", "/a/b"},

		{"relative/path", "/v1"},
		{"", "/v1"},
		{"/a/..\\../b", "/v1"},
		{"/a\x00/b", "/v1"},
	} {
		var gotPath string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
		})

		m := newTestMiddleware(t, next, false)

		req := newReqTestRequest(t, `
function onRequest(ctx)
  octelium.req.setPath(`+quoteLua(e.arg)+`)
end`, nil, newReqTestCtx(0))

		m.ServeHTTP(httptest.NewRecorder(), req)

		assert.Equal(t, e.expected, gotPath, "%q", e.arg)
	}
}

func TestSetRequestHeaderRejectsReserved(t *testing.T) {
	for _, e := range []struct {
		name  string
		isSet bool
	}{
		{"X-Custom", true},
		{"X-Octelium-Auth", false},
		{"x-octelium-client-address", false},
		{"X-OCTELIUM-Session-Uid", false},
		{"Transfer-Encoding", false},
		{"connection", false},
		{"Upgrade", false},
		{"Host", false},
	} {
		var gotHeader string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotHeader = r.Header.Get(e.name)
		})

		m := newTestMiddleware(t, next, false)

		req := newReqTestRequest(t, `
function onRequest(ctx)
  octelium.req.setRequestHeader(`+quoteLua(e.name)+`, "octelium")
end`, nil, newReqTestCtx(0))

		m.ServeHTTP(httptest.NewRecorder(), req)

		if e.isSet {
			assert.Equal(t, "octelium", gotHeader, e.name)
		} else {
			assert.Equal(t, "", gotHeader, e.name)
		}
	}
}

func TestGetRequestBodyIsBounded(t *testing.T) {

	script := `
function onRequest(ctx)
  local body, err = octelium.req.getRequestBody()
  if err ~= nil then
    octelium.req.setResponseHeader("X-Tst-Err", err)
  else
    octelium.req.setResponseHeader("X-Tst-Len", tostring(#body))
  end
end`

	{
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		m := newTestMiddleware(t, next, false)

		req := newReqTestRequest(t, script,
			strings.NewReader(strings.Repeat("a", 16)), newReqTestCtx(64))

		rw := httptest.NewRecorder()
		m.ServeHTTP(rw, req)

		assert.Equal(t, "16", rw.Result().Header.Get("X-Tst-Len"))
	}

	{
		var upstreamBody []byte
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamBody, _ = io.ReadAll(r.Body)
		})
		m := newTestMiddleware(t, next, false)

		req := newReqTestRequest(t, script,
			strings.NewReader(strings.Repeat("a", 256)), newReqTestCtx(64))

		rw := httptest.NewRecorder()
		m.ServeHTTP(rw, req)

		assert.Equal(t, "The request body is too large",
			rw.Result().Header.Get("X-Tst-Err"))
		assert.Equal(t, strings.Repeat("a", 256), string(upstreamBody))
	}

	{
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
		m := newTestMiddleware(t, next, false)

		reqCtx := newReqTestCtx(64)
		reqCtx.Body = []byte(strings.Repeat("a", 256))

		req := newReqTestRequest(t, script, nil, reqCtx)

		rw := httptest.NewRecorder()
		m.ServeHTTP(rw, req)

		assert.Equal(t, "256", rw.Result().Header.Get("X-Tst-Len"))
	}
}

func quoteLua(arg string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for i := range len(arg) {
		switch c := arg[i]; c {
		case '"', '\\':
			sb.WriteByte('\\')
			sb.WriteByte(c)
		default:
			if c < 0x20 || c == 0x7f {
				sb.WriteString(fmt.Sprintf("\\%d", c))
			} else {
				sb.WriteByte(c)
			}
		}
	}
	sb.WriteByte('"')

	return sb.String()
}
