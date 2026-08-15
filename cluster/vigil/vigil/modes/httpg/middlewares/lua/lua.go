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
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/yuin/gopher-lua/parse"
	"go.uber.org/zap"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	lua "github.com/yuin/gopher-lua"
)

const (
	maxBufferedResponseBytes = 4 * 1024 * 1024

	maxCachedFnProtos = 1024
)

const defaultFailOpen = false

var errResponseTooLarge = errors.Errorf(
	"upstream response exceeded the %d byte Lua buffering limit", maxBufferedResponseBytes)

type middleware struct {
	next http.Handler
	sync.RWMutex
	cMap      map[string]*lua.FunctionProto
	phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
	celEngine *celengine.CELEngine
	failOpen  bool
}

func New(ctx context.Context, next http.Handler, celEngine *celengine.CELEngine, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) (http.Handler, error) {
	return &middleware{
		next:      next,
		cMap:      make(map[string]*lua.FunctionProto),
		phase:     phase,
		celEngine: celEngine,
		failOpen:  defaultFailOpen,
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)
	cfg := reqCtx.ServiceConfig

	plugins := ucorev1.ToServiceConfig(cfg).GetHTTPPlugins()
	if len(plugins) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	var luaContexts []*luaCtx
	defer func() {
		for _, luaCtx := range luaContexts {
			luaCtx.close()
		}
	}()

	crw := newResponseWriter(rw)
	crw.failOpen = m.failOpen
	isHead := req.Method == http.MethodHead

	if reqCtx.ReqCtxMap == nil && reqCtx.DownstreamInfo != nil {
		reqCtx.ReqCtxMap = pbutils.MustConvertToMap(reqCtx.DownstreamInfo)
	}
	reqCtxMap := reqCtx.ReqCtxMap

	for _, plugin := range plugins {

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
				if m.isRejected(rw, plugin.Name, "compile", err) {
					return
				}
				continue
			}

			luaCtx, err := newCtx(&newCtxOpts{
				req:        req,
				rw:         crw,
				fnProto:    fnProto,
				reqCtxMap:  reqCtxMap,
				pluginName: plugin.Name,
			})
			if err != nil {
				if m.isRejected(rw, plugin.Name, "load", err) {
					return
				}
				continue
			}
			luaContexts = append(luaContexts, luaCtx)
		}
	}

	if len(luaContexts) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	crw.buffering = false
	for _, luaCtx := range luaContexts {
		if luaCtx.hasOnResponse {
			crw.buffering = true
			break
		}
	}

	for _, luaCtx := range luaContexts {
		if err := luaCtx.callOnRequest(); err != nil {
			if m.isRejected(rw, luaCtx.pluginName, "onRequest", err) {
				return
			}
			continue
		}

		if luaCtx.isExit {
			crw.buffering = true
			crw.finish(isHead)
			return
		}
	}

	m.next.ServeHTTP(crw, req)

	if crw.overflowed {
		if m.isRejected(rw, "", "responseBuffer", errResponseTooLarge) {
			return
		}
	} else {
		for _, luaCtx := range luaContexts {
			if err := luaCtx.callOnResponse(); err != nil {
				if m.isRejected(rw, luaCtx.pluginName, "onResponse", err) {
					return
				}
			}
		}
	}

	crw.finish(isHead)
}

func (m *middleware) isRejected(rw http.ResponseWriter, pluginName, stage string, err error) bool {
	fields := []zap.Field{
		zap.String("plugin", pluginName),
		zap.String("stage", stage),
		zap.Error(err),
	}

	if m.failOpen {
		zap.L().Warn("Lua plugin failed. Continuing since the plugin fails open", fields...)
		return false
	}

	zap.L().Warn("Lua plugin failed. Rejecting the request", fields...)

	rw.Header().Set("Server", "octelium")
	rw.WriteHeader(http.StatusInternalServerError)

	return true
}

type responseWriter struct {
	http.ResponseWriter
	statusCode  int
	headers     http.Header
	body        *bytes.Buffer
	wroteHeader bool

	buffering   bool
	maxBodySize int
	failOpen    bool

	headersSent bool
	overflowed  bool
	hijacked    bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		headers:        make(http.Header),
		body:           new(bytes.Buffer),
		statusCode:     http.StatusOK,
		buffering:      true,
		maxBodySize:    maxBufferedResponseBytes,
	}
}

func (w *responseWriter) Header() http.Header {
	return w.headers
}

func (w *responseWriter) sendHeaders() {
	if w.headersSent || w.hijacked {
		return
	}
	w.headersSent = true

	dst := w.ResponseWriter.Header()
	for k, vv := range w.headers {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}

	w.ResponseWriter.WriteHeader(w.statusCode)
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.statusCode = statusCode
	w.wroteHeader = true

	if w.buffering && isStreamingResponse(w.headers) {
		w.buffering = false
	}

	if !w.buffering {
		w.sendHeaders()
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	if w.hijacked {
		return 0, http.ErrHijacked
	}

	if !w.buffering {
		w.sendHeaders()
		return w.ResponseWriter.Write(b)
	}

	if w.body.Len()+len(b) > w.maxBodySize {
		w.overflowed = true

		if !w.failOpen {
			return 0, errResponseTooLarge
		}

		w.buffering = false
		w.sendHeaders()
		if w.body.Len() > 0 {
			if _, err := w.ResponseWriter.Write(w.body.Bytes()); err != nil {
				return 0, err
			}
			w.body.Reset()
		}
		return w.ResponseWriter.Write(b)
	}

	return w.body.Write(b)
}

func (w *responseWriter) finish(isHead bool) {
	if w.hijacked {
		return
	}

	if !w.buffering {
		w.sendHeaders()
		return
	}

	hasBody := bodyAllowedForStatus(w.statusCode) && !isHead
	if hasBody {
		w.headers.Set("Content-Length", strconv.Itoa(w.body.Len()))
	} else {
		w.headers.Del("Content-Length")
	}

	w.sendHeaders()

	if hasBody && w.body.Len() > 0 {
		if _, err := w.ResponseWriter.Write(w.body.Bytes()); err != nil {
			zap.L().Debug("Could not write response", zap.Error(err))
		}
	}
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}

	conn, brw, err := hj.Hijack()
	if err == nil {
		w.hijacked = true
	}

	return conn, brw, err
}

func (w *responseWriter) Flush() {
	if w.hijacked || w.buffering {
		return
	}

	w.sendHeaders()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func isStreamingResponse(h http.Header) bool {
	ct := strings.ToLower(strings.TrimSpace(h.Get("Content-Type")))

	return strings.HasPrefix(ct, "text/event-stream") ||
		strings.HasPrefix(ct, "application/grpc") ||
		strings.HasPrefix(ct, "multipart/x-mixed-replace")
}

func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent, status == http.StatusNotModified:
		return false
	default:
		return true
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

	if len(m.cMap) >= maxCachedFnProtos {
		m.cMap = make(map[string]*lua.FunctionProto)
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
