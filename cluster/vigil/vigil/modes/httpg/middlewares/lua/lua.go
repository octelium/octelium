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
	"net/http"
	"os"
	"sync"

	"github.com/pkg/errors"
	"github.com/yuin/gopher-lua/parse"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	lua "github.com/yuin/gopher-lua"
)

type middleware struct {
	next http.Handler
	sync.RWMutex
	cMap map[string]*lua.FunctionProto
}

func New(ctx context.Context, next http.Handler) (http.Handler, error) {
	return &middleware{
		next: next,
		cMap: make(map[string]*lua.FunctionProto),
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqCtx := middlewares.GetCtxRequestContext(req.Context())
	cfg := reqCtx.ServiceConfig

	if cfg == nil || cfg.GetHttp() == nil || len(cfg.GetHttp().Plugins) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	var luaContexts []*luaCtx
	crw := newResponseWriter(rw)

	for _, plugin := range cfg.GetHttp().Plugins {
		switch plugin.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_Lua_:
			fnProto, err := m.getLuaFnProto(plugin.GetLua())
			if err != nil {
				continue
			}
			luaCtx, err := newCtx(&newCtxOpts{
				req:     req,
				rw:      crw,
				fnProto: fnProto,
			})
			if err != nil {
				continue
			}
			luaContexts = append(luaContexts, luaCtx)
		}
	}

	for _, luaCtx := range luaContexts {
		luaCtx.callOnRequest()
	}

	m.next.ServeHTTP(crw, req)

	for _, luaCtx := range luaContexts {
		luaCtx.callOnRequest()
	}

	for _, luaCtx := range luaContexts {
		luaCtx.close()
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	headers    http.Header
	body       *bytes.Buffer
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		headers:        make(http.Header),
		body:           new(bytes.Buffer),
	}
}

func (rw *responseWriter) Header() http.Header {
	return rw.headers
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	return rw.body.Write(b)
}

func (m *middleware) compileLua(luaContent string) (*lua.FunctionProto, error) {
	file, err := os.CreateTemp("/tmp", "octelium-lua")
	if err != nil {
		return nil, err
	}
	filePath := file.Name()
	defer os.Remove(filePath)

	if _, err := file.WriteString(luaContent); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(file)
	chunk, err := parse.Parse(reader, filePath)
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
		return nil, errors.Errorf("Only lua inline is supported")
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
