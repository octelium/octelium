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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	lua "github.com/yuin/gopher-lua"
)

func newTestRequest(t *testing.T, script string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)

	return req.WithContext(context.WithValue(context.Background(),
		middlewares.CtxRequestContext,
		&middlewares.RequestContext{
			CreatedAt: time.Now(),
			ReqCtxMap: map[string]any{},
			ServiceConfig: &corev1.Service_Spec_Config{
				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
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
						},
					},
				},
			},
		}))
}

func newTestMiddleware(t *testing.T, next http.Handler, failOpen bool) *middleware {
	t.Helper()

	celEngine, err := celengine.New(context.Background(), &celengine.Opts{})
	require.Nil(t, err)

	return &middleware{
		next:      next,
		cMap:      make(map[string]*lua.FunctionProto),
		phase:     corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH,
		celEngine: celEngine,
		failOpen:  failOpen,
	}
}

func TestPhaseDeadlineStopsRunawayScript(t *testing.T) {
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	m := newTestMiddleware(t, next, false)

	req := newTestRequest(t, `
function onRequest(ctx)
  while true do end
end`)

	rw := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.ServeHTTP(rw, req)
	}()

	select {
	case <-done:
	case <-time.After(defaultPhaseTimeout + 10*time.Second):
		t.Fatal("the script was never interrupted")
	}

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusInternalServerError, rw.Result().StatusCode)
}

func TestDeadlineNotEscapableViaPCall(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	m := newTestMiddleware(t, next, false)

	req := newTestRequest(t, `
function onRequest(ctx)
  while true do
    pcall(function() while true do end end)
  end
end`)

	rw := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.ServeHTTP(rw, req)
	}()

	select {
	case <-done:
	case <-time.After(defaultPhaseTimeout + 10*time.Second):
		t.Fatal("pcall let the script outlive its deadline")
	}
}

func TestScriptErrorFailsClosed(t *testing.T) {
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	m := newTestMiddleware(t, next, false)

	req := newTestRequest(t, `
function onRequest(ctx)
  local x = nil
  return x.missing.field
end`)

	rw := httptest.NewRecorder()
	m.ServeHTTP(rw, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusInternalServerError, rw.Result().StatusCode)
}

func TestScriptErrorFailOpenStillProxies(t *testing.T) {
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.Write([]byte("upstream"))
	})

	m := newTestMiddleware(t, next, true)

	req := newTestRequest(t, `
function onRequest(ctx)
  local x = nil
  return x.missing.field
end`)

	rw := httptest.NewRecorder()
	m.ServeHTTP(rw, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
	assert.Equal(t, "upstream", rw.Body.String())
}

func TestMissingHooksAreNotFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
	}{
		{"empty", ``},
		{"onRequestOnly", "function onRequest(ctx)\n  octelium.req.setRequestHeader(\"X-A\", \"b\")\nend"},
		{"onResponseOnly", "function onResponse(ctx)\nend"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var nextCalled bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.Write([]byte("ok"))
			})

			m := newTestMiddleware(t, next, false)
			rw := httptest.NewRecorder()
			m.ServeHTTP(rw, newTestRequest(t, tc.script))

			assert.True(t, nextCalled)
			assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
			assert.Equal(t, "ok", rw.Body.String())
		})
	}
}

func TestOnRequestOnlyPluginStreams(t *testing.T) {
	release := make(chan struct{})
	wrote := make(chan struct{})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("first"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(wrote)
		<-release
		w.Write([]byte("second"))
	})

	m := newTestMiddleware(t, next, false)

	req := newTestRequest(t, `
function onRequest(ctx)
  octelium.req.setResponseHeader("X-Plugin", "on")
end`)

	rw := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.ServeHTTP(rw, req)
	}()

	<-wrote
	assert.Equal(t, "first", rw.Body.String())

	close(release)
	<-done

	assert.Equal(t, "firstsecond", rw.Body.String())
	assert.Equal(t, "on", rw.Header().Get("X-Plugin"))
}

func TestStreamingContentTypeDisablesBuffering(t *testing.T) {
	wrote := make(chan struct{})
	release := make(chan struct{})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data: one\n\n"))
		close(wrote)
		<-release
	})

	m := newTestMiddleware(t, next, false)

	req := newTestRequest(t, `
function onResponse(ctx)
  octelium.req.setResponseBody("rewritten")
end`)

	rw := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.ServeHTTP(rw, req)
	}()

	<-wrote
	assert.Equal(t, "data: one\n\n", rw.Body.String())

	close(release)
	<-done

	assert.Equal(t, "data: one\n\n", rw.Body.String())
}

func TestResponseOverflowFailsClosed(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := strings.Repeat("a", 64*1024)
		for i := 0; i < (maxBufferedResponseBytes/len(chunk))+2; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	})

	m := newTestMiddleware(t, next, false)

	req := newTestRequest(t, `
function onResponse(ctx)
  octelium.req.setResponseHeader("X-Seen", "yes")
end`)

	rw := httptest.NewRecorder()
	m.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusInternalServerError, rw.Result().StatusCode)
	assert.Empty(t, rw.Header().Get("X-Seen"))
}

func TestResponseOverflowFailOpenStreamsThrough(t *testing.T) {
	chunk := strings.Repeat("a", 64*1024)
	total := (maxBufferedResponseBytes/len(chunk) + 2) * len(chunk)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < (maxBufferedResponseBytes/len(chunk))+2; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	})

	m := newTestMiddleware(t, next, true)

	req := newTestRequest(t, `
function onResponse(ctx)
end`)

	rw := httptest.NewRecorder()
	m.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
	assert.Equal(t, total, rw.Body.Len())
}

func TestNoContentStatusGetsNoContentLength(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	m := newTestMiddleware(t, next, false)

	req := newTestRequest(t, `
function onResponse(ctx)
end`)

	rw := httptest.NewRecorder()
	m.ServeHTTP(rw, req)

	assert.Equal(t, http.StatusNoContent, rw.Result().StatusCode)
	assert.Empty(t, rw.Header().Get("Content-Length"))
	assert.Equal(t, 0, rw.Body.Len())
}

func TestBufferedResponseSetsContentLengthOnce(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "8")
		w.Write([]byte("upstream"))
	})

	m := newTestMiddleware(t, next, false)

	req := newTestRequest(t, `
function onResponse(ctx)
  octelium.req.setResponseBody("rewritten-and-longer")
end`)

	rw := httptest.NewRecorder()
	m.ServeHTTP(rw, req)

	assert.Equal(t, "rewritten-and-longer", rw.Body.String())
	assert.Equal(t, []string{"20"}, rw.Header().Values("Content-Length"))
}

func TestRequestContextIsolatedPerPlugin(t *testing.T) {
	reqCtxMap := map[string]any{
		"user": map[string]any{"name": "original"},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
	req = req.WithContext(context.WithValue(context.Background(),
		middlewares.CtxRequestContext,
		&middlewares.RequestContext{CreatedAt: time.Now()}))

	m := &middleware{cMap: make(map[string]*lua.FunctionProto)}

	mutator, err := m.doGetAndSetLuaFnProto(`
function onRequest(ctx)
  ctx.user.name = "tampered"
end`)
	require.Nil(t, err)

	reader, err := m.doGetAndSetLuaFnProto(`
function onRequest(ctx)
  octelium.req.setRequestHeader("X-Observed", ctx.user.name)
end`)
	require.Nil(t, err)

	rw := newResponseWriter(httptest.NewRecorder())

	first, err := newCtx(&newCtxOpts{req: req, rw: rw, fnProto: mutator, reqCtxMap: reqCtxMap})
	require.Nil(t, err)
	defer first.close()

	second, err := newCtx(&newCtxOpts{req: req, rw: rw, fnProto: reader, reqCtxMap: reqCtxMap})
	require.Nil(t, err)
	defer second.close()

	require.Nil(t, first.callOnRequest())
	require.Nil(t, second.callOnRequest())

	assert.Equal(t, "original", req.Header.Get("X-Observed"))
	assert.Equal(t, "original", reqCtxMap["user"].(map[string]any)["name"])
}

func TestHookDetection(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
	req = req.WithContext(context.WithValue(context.Background(),
		middlewares.CtxRequestContext,
		&middlewares.RequestContext{CreatedAt: time.Now()}))

	m := &middleware{cMap: make(map[string]*lua.FunctionProto)}

	for _, tc := range []struct {
		name       string
		script     string
		onRequest  bool
		onResponse bool
	}{
		{"none", ``, false, false},
		{"request", "function onRequest(ctx) end", true, false},
		{"response", "function onResponse(ctx) end", false, true},
		{"both", "function onRequest(ctx) end\nfunction onResponse(ctx) end", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fnProto, err := m.doGetAndSetLuaFnProto(tc.script)
			require.Nil(t, err)

			c, err := newCtx(&newCtxOpts{
				req:     req,
				rw:      newResponseWriter(httptest.NewRecorder()),
				fnProto: fnProto,
			})
			require.Nil(t, err)
			defer c.close()

			assert.Equal(t, tc.onRequest, c.hasOnRequest)
			assert.Equal(t, tc.onResponse, c.hasOnResponse)
		})
	}
}
