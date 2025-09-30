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
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/yuin/gopher-lua/parse"
	"go.uber.org/zap"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
	"github.com/octelium/octelium/pkg/common/pbutils"
	lua "github.com/yuin/gopher-lua"
)

type middleware struct {
	next http.Handler
	sync.RWMutex
	cMap      map[string]*lua.FunctionProto
	phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
	celEngine *celengine.CELEngine
}

func New(ctx context.Context, next http.Handler, celEngine *celengine.CELEngine, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) (http.Handler, error) {
	return &middleware{
		next:      next,
		cMap:      make(map[string]*lua.FunctionProto),
		phase:     phase,
		celEngine: celEngine,
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)
	cfg := reqCtx.ServiceConfig

	if cfg == nil || cfg.GetHttp() == nil || len(cfg.GetHttp().Plugins) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	var luaContexts []*luaCtx
	crw := newResponseWriter(rw)
	reqCtxVal := m.getRequestContextLValue(reqCtx.DownstreamInfo)

	doAfterResponse := func() {

		/*
			if len(crw.headers) > 0 {
				for k, v := range crw.headers {
					if len(v) < 1 {
						continue
					}

					crw.ResponseWriter.Header().Set(k, v[0])
				}
			}
		*/

		{
			crw.ResponseWriter.Header().Set("Content-Length", fmt.Sprintf("%d", len(crw.body.Bytes())))
			crw.ResponseWriter.WriteHeader(crw.statusCode)

			if _, err := crw.ResponseWriter.Write(crw.body.Bytes()); err != nil {
				zap.L().Warn("Could not write to lua crw", zap.Error(err))
			}
		}

		for _, luaCtx := range luaContexts {
			luaCtx.close()
		}
	}

	for _, plugin := range cfg.GetHttp().Plugins {

		switch plugin.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_Lua_:
			if !commonplugin.ShouldEnforcePlugin(ctx, &commonplugin.ShouldEnforcePluginOpts{
				Plugin:    plugin,
				CELEngine: m.celEngine,
				Phase:     m.phase,
			}) {
				continue
			}

			fnProto, err := m.getLuaFnProto(plugin.GetLua())
			if err != nil {
				continue
			}
			luaCtx, err := newCtx(&newCtxOpts{
				req:          req,
				rw:           crw,
				fnProto:      fnProto,
				reqCtxLValue: reqCtxVal,
			})
			if err != nil {
				continue
			}
			luaContexts = append(luaContexts, luaCtx)
		}
	}

	if len(luaContexts) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	for _, luaCtx := range luaContexts {
		if err := luaCtx.callOnRequest(); err != nil {
			zap.L().Debug("Could not callOnRequest", zap.Error(err))
		} else {
			if luaCtx.isExit {
				doAfterResponse()
				return
			}
		}
	}

	m.next.ServeHTTP(crw, req)

	for _, luaCtx := range luaContexts {
		if err := luaCtx.callOnResponse(); err != nil {
			zap.L().Debug("Could not callOnResponse", zap.Error(err))
		}
	}

	doAfterResponse()
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	// headers    http.Header
	body  *bytes.Buffer
	isSet bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		// headers:        make(http.Header),
		body:       new(bytes.Buffer),
		statusCode: 200,
	}
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func (w *responseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}

	return hj.Hijack()
}

func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := p.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (m *middleware) compileLua(luaContent string) (*lua.FunctionProto, error) {
	filePath := m.getKey(luaContent)
	chunk, err := parse.Parse(strings.NewReader(luaContent), filePath)
	if err != nil {
		return nil, err
	}
	proto, err := lua.Compile(chunk, filePath)
	if err != nil {
		return nil, err
	}
	return proto, nil
}

func (m *middleware) getLuaFnProto(plugin *corev1.Service_Spec_Config_HTTP_Plugin_Lua) (*lua.FunctionProto, error) {
	switch plugin.Type.(type) {
	case *corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline:
		return m.doGetAndSetLuaFnProto(plugin.GetInline())
	default:
		return nil, errors.Errorf("Only inline mode is supported")
	}
}

func (m *middleware) doGetAndSetLuaFnProto(content string) (*lua.FunctionProto, error) {
	if ret, err := m.doGetLuaFnProto(content); err == nil {
		return ret, nil
	}

	m.Lock()
	defer m.Unlock()

	fnProto, err := m.compileLua(content)
	if err != nil {
		return nil, err
	}

	m.cMap[m.getKey(content)] = fnProto

	return fnProto, nil
}

func (m *middleware) doGetLuaFnProto(content string) (*lua.FunctionProto, error) {
	m.RLock()
	defer m.RUnlock()
	ret, ok := m.cMap[m.getKey(content)]
	if !ok {
		return nil, errors.Errorf("fnProto not found")
	}

	return ret, nil
}

func (m *middleware) getKey(content string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
}

func (m *middleware) getRequestContextLValue(reqCtx *corev1.RequestContext) lua.LValue {
	state := lua.NewState(lua.Options{
		SkipOpenLibs: true,
	})

	return toLuaValue(state, pbutils.MustConvertToMap(reqCtx))
}
