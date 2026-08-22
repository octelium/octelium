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

package accesslog

import (
	"net/http"
	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
)

const defaultMaxMCPStreamEventBytes = 256 * 1024

type mcpObserver struct {
	mu sync.Mutex

	eventCount        uint64
	notificationCount uint64

	resultType string
	ttlMs      uint64
	cacheScope string

	isProtocolError bool
	errorCode       int32
	errorMessage    string
	isToolError     bool
}

func (o *mcpObserver) onSSEEvent(event []byte) {
	data := httputils.GetSSEEventData(event)

	o.mu.Lock()
	defer o.mu.Unlock()

	o.eventCount++

	if len(data) == 0 {
		return
	}

	msg := httputils.ParseMCPResponse(data)
	if msg == nil {
		return
	}

	if msg.IsNotification {
		o.notificationCount++
		return
	}

	o.setResult(msg)
}

func (o *mcpObserver) onFinalBody(body []byte) {
	msg := httputils.ParseMCPResponse(body)
	if msg == nil {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if msg.IsNotification {
		o.notificationCount++
		return
	}

	o.setResult(msg)
}

func (o *mcpObserver) setResult(msg *httputils.MCPResponse) {
	o.resultType = msg.ResultType
	o.ttlMs = msg.TTLMs
	o.cacheScope = msg.CacheScope
	o.isProtocolError = msg.IsError
	o.errorCode = msg.ErrorCode
	o.errorMessage = msg.ErrorMessage
	o.isToolError = msg.IsToolError
}

func (m *middleware) serveMCP(w http.ResponseWriter, req *http.Request,
	reqCtx *middlewares.RequestContext) {

	obs := &mcpObserver{}

	connID := vutils.GenerateLogID()

	crw := newResponseWriter(w, streamKindMCP)
	crw.maxSSEEvent = getMaxMCPStreamEventBytes(reqCtx)
	crw.onSSEEvent = obs.onSSEEvent

	crw.onFirstByte = func() {
		if reqCtx.DownstreamInfo == nil || !crw.isSSE {
			return
		}
		otelutils.EmitAccessLog(
			m.getMCPAccessLog(req, crw, reqCtx, obs, logPhaseStreamOpen, connID, 0))
	}

	m.next.ServeHTTP(crw, req)

	if reqCtx.DownstreamInfo == nil {
		obs.setRequestContext(reqCtx)
		return
	}

	if !crw.isSSE {
		obs.onFinalBody(crw.body.Bytes())
		obs.setRequestContext(reqCtx)
		otelutils.EmitAccessLog(
			m.getMCPAccessLog(req, crw, reqCtx, obs, logPhaseComplete, "", 0))
		return
	}

	obs.setRequestContext(reqCtx)
	otelutils.EmitAccessLog(
		m.getMCPAccessLog(req, crw, reqCtx, obs, logPhaseStreamClose, connID, 1))
}

func (o *mcpObserver) setRequestContext(reqCtx *middlewares.RequestContext) {
	o.mu.Lock()
	defer o.mu.Unlock()

	reqCtx.MCPResponse = &middlewares.MCPResponseInfo{
		IsProtocolError: o.isProtocolError,
		IsToolError:     o.isToolError,
		ErrorCode:       o.errorCode,
		EventCount:      o.eventCount,
	}
}

func (m *middleware) getMCPAccessLog(
	req *http.Request,
	crw *responseWriter,
	reqCtx *middlewares.RequestContext,
	obs *mcpObserver,
	phase logPhase,
	connID string,
	eventSeq int64) *corev1.AccessLog {

	logE := m.getAccessLog(req, crw, reqCtx, phase, connID, eventSeq)
	if logE == nil {
		return nil
	}

	mcpC := logE.Entry.Info.GetMcp()
	if mcpC == nil {
		return logE
	}

	mcpC.Type = func() corev1.AccessLog_Entry_Info_MCP_Type {
		switch phase {
		case logPhaseStreamOpen:
			return corev1.AccessLog_Entry_Info_MCP_STREAM_START
		case logPhaseStreamClose:
			return corev1.AccessLog_Entry_Info_MCP_STREAM_END
		default:
			return corev1.AccessLog_Entry_Info_MCP_COMPLETE
		}
	}()

	if phase == logPhaseStreamOpen {
		return logE
	}

	obs.mu.Lock()
	defer obs.mu.Unlock()

	mcpC.EventCount = obs.eventCount
	mcpC.NotificationCount = obs.notificationCount
	mcpC.ResultType = obs.resultType
	mcpC.TtlMs = obs.ttlMs
	mcpC.CacheScope = obs.cacheScope
	mcpC.IsProtocolError = obs.isProtocolError
	mcpC.ErrorCode = obs.errorCode
	mcpC.IsToolError = obs.isToolError

	if isResponseBodyVisible(reqCtx) {
		mcpC.ErrorMessage = obs.errorMessage
	}

	return logE
}

func isResponseBodyVisible(reqCtx *middlewares.RequestContext) bool {
	visibility := getVisibilityConfig(reqCtx)
	if visibility == nil {
		return false
	}
	return visibility.EnableResponseBody || visibility.EnableResponseBodyMap
}

func getMaxMCPStreamEventBytes(reqCtx *middlewares.RequestContext) int {
	cfg := reqCtx.ServiceConfig
	if cfg == nil {
		return defaultMaxMCPStreamEventBytes
	}

	configured := cfg.GetMcp().GetLimits().GetMaxStreamEventBytes()
	if configured == 0 || int(configured) > maxMCPStreamEventBytes {
		return defaultMaxMCPStreamEventBytes
	}

	return int(configured)
}

const maxMCPStreamEventBytes = 4 * 1024 * 1024
