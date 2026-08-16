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
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"
	"google.golang.org/protobuf/types/known/structpb"
)

type middleware struct {
	next http.Handler
}

func New(ctx context.Context, next http.Handler) (http.Handler, error) {
	return &middleware{
		next: next,
	}, nil
}

type streamKind int

const (
	streamKindNone streamKind = iota
	streamKindSSE
	// streamKindGRPC
	streamKindWS
	streamKindK8sExec
	streamKindK8sLog
	streamKindGeneric
	streamKindMCP
)

const (
	maxBodyLen     = 32 * 1024
	maxSSEEventLog = 10
	sseLogInterval = 30 * time.Second
)

func (m *middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	kind := detectStreamKind(req, reqCtx)

	switch kind {
	case streamKindNone:
		m.serveNonStreaming(w, req, reqCtx)
	case streamKindMCP:
		m.serveMCP(w, req, reqCtx)
	default:
		m.serveStreaming(w, req, reqCtx, kind)
	}
}

func detectStreamKind(req *http.Request, reqCtx *middlewares.RequestContext) streamKind {
	svc := reqCtx.Service

	if isWebSocketUpgrade(req) {
		return streamKindWS
	}

	if ucorev1.ToService(svc).IsMCP() {
		return streamKindMCP
	}

	/*
		if ucorev1.ToService(svc).IsGRPC() {
			return streamKindGRPC
		}
		ct := req.Header.Get("Content-Type")
		if strings.HasPrefix(ct, "application/grpc") {
			return streamKindGRPC
		}
	*/

	if ucorev1.ToService(svc).IsKubernetes() {
		path := req.URL.Path
		q := req.URL.Query()

		if strings.HasSuffix(path, "/exec") || strings.HasSuffix(path, "/attach") {
			return streamKindK8sExec
		}
		if strings.HasSuffix(path, "/log") {
			return streamKindK8sLog
		}
		if strings.HasSuffix(path, "/portforward") ||
			q.Get("follow") == "true" || q.Get("follow") == "1" {
			return streamKindGeneric
		}
	}

	accept := req.Header.Get("Accept")
	if strings.Contains(accept, "text/event-stream") {
		return streamKindSSE
	}

	if req.Header.Get("X-Accel-Buffering") == "no" {
		return streamKindGeneric
	}

	return streamKindNone
}

func (m *middleware) serveNonStreaming(w http.ResponseWriter, req *http.Request,
	reqCtx *middlewares.RequestContext) {
	crw := newResponseWriter(w, streamKindNone)
	m.next.ServeHTTP(crw, req)

	if reqCtx.DownstreamInfo == nil {
		return
	}

	otelutils.EmitAccessLog(m.getAccessLog(req, crw, reqCtx, logPhaseComplete, "", 0))
}

func (m *middleware) serveStreaming(w http.ResponseWriter,
	req *http.Request,
	reqCtx *middlewares.RequestContext,
	kind streamKind) {
	crw := newResponseWriter(w, kind)
	connID := vutils.GenerateLogID()

	crw.onFirstByte = func() {
		if reqCtx.DownstreamInfo == nil {
			return
		}
		otelutils.EmitAccessLog(m.getAccessLog(req, crw, reqCtx, logPhaseStreamOpen, connID, 0))
	}

	if kind == streamKindSSE {
		var eventCount int64
		var mu sync.Mutex
		lastLog := time.Now()

		crw.onSSEEvent = func(event []byte) {
			n := atomic.AddInt64(&eventCount, 1)

			mu.Lock()
			shouldLog := n <= maxSSEEventLog || time.Since(lastLog) >= sseLogInterval
			if shouldLog {
				lastLog = time.Now()
			}
			mu.Unlock()

			if !shouldLog {
				return
			}
			if reqCtx.DownstreamInfo == nil {
				return
			}
			log := m.getAccessLog(req, crw, reqCtx, logPhaseSSEEvent, connID, n)

			if visibilityCfg := getVisibilityConfig(reqCtx); visibilityCfg != nil {
				if visibilityCfg.EnableResponseBody {
					log.Entry.Info.GetHttp().Response.Body = event
				}

				if visibilityCfg.EnableResponseBodyMap {
					bm := &structpb.Struct{}

					if err := pbutils.UnmarshalJSON(event, bm); err != nil {
						zap.L().Debug("Could not unmarshalJSON respBody", zap.Error(err))
					} else {
						log.Entry.Info.GetHttp().Response.BodyMap = bm
					}
				}
			}

			otelutils.EmitAccessLog(log)
		}
	}

	m.next.ServeHTTP(crw, req)

	if reqCtx.DownstreamInfo == nil {
		return
	}

	otelutils.EmitAccessLog(m.getAccessLog(req, crw, reqCtx, logPhaseStreamClose, connID, crw.eventCount()))
}

type logPhase int

const (
	logPhaseComplete logPhase = iota
	logPhaseStreamOpen
	logPhaseStreamClose
	logPhaseSSEEvent
)

func getVisibilityConfig(reqCtx *middlewares.RequestContext) *corev1.Service_Spec_Config_HTTP_Visibility {
	if ucorev1.ToService(reqCtx.Service).IsMCP() {
		return ucorev1.ToServiceConfig(reqCtx.ServiceConfig).GetMCPVisibility()
	}
	return ucorev1.ToServiceConfig(reqCtx.ServiceConfig).GetHTTPVisibility()
}

func (m *middleware) getAccessLog(
	req *http.Request,
	crw *responseWriter,
	reqCtx *middlewares.RequestContext,
	phase logPhase,
	connID string,
	eventSeq int64) *corev1.AccessLog {

	svcCfg := reqCtx.ServiceConfig
	visibilityCfg := getVisibilityConfig(reqCtx)

	var reqBody []byte
	var reqBodyMap *structpb.Struct
	var respBody []byte
	var respBodyMap *structpb.Struct
	var reqHeaders map[string]string
	var respHeaders map[string]string

	if visibilityCfg != nil {
		if len(reqCtx.Body) <= maxBodyLen {
			if visibilityCfg.EnableRequestBody {
				reqBody = reqCtx.Body
			}
			if visibilityCfg.EnableRequestBodyMap {
				ret := &structpb.Struct{}
				if err := pbutils.UnmarshalJSON(reqCtx.Body, ret); err != nil {
					zap.L().Debug("Could not unmarshalJSON reqBody", zap.Error(err))
				} else {
					reqBodyMap = ret
				}
			}
		}

		if phase == logPhaseComplete || phase == logPhaseStreamClose {
			if crw.body.Len() <= maxBodyLen {
				if visibilityCfg.EnableResponseBody {
					b := make([]byte, crw.body.Len())
					copy(b, crw.body.Bytes())
					respBody = b
				}
				if visibilityCfg.EnableResponseBodyMap && crw.body.Len() > 0 {
					ret := &structpb.Struct{}

					body := respBody
					if body == nil {
						body = make([]byte, crw.body.Len())
						copy(body, crw.body.Bytes())
					}

					if err := pbutils.UnmarshalJSON(body, ret); err != nil {
						zap.L().Debug("Could not unmarshalJSON respBody", zap.Error(err))
					} else {
						respBodyMap = ret
					}
				}
			}
		}

		var customAuthHeader string
		if ucorev1.ToServiceConfig(svcCfg).GetHTTPAuth().GetCustom() != nil {
			customAuthHeader = ucorev1.ToServiceConfig(svcCfg).GetHTTPAuth().GetCustom().Header
		}

		reqHeaders = getRequestHeaderMap(req, visibilityCfg, customAuthHeader)
		respHeaders = getResponseHeaderMap(crw, visibilityCfg)
	}

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       reqCtx.CreatedAt,
		IsAuthenticated: reqCtx.IsAuthenticated,
		IsAuthorized:    reqCtx.IsAuthorized,
		ReqCtx:          reqCtx.DownstreamInfo,
		Reason:          reqCtx.DecisionReason,
		ConnectionID:    connID,
		Sequence:        eventSeq,
	})

	crwHeader := crw.Header()

	httpC := &corev1.AccessLog_Entry_Info_HTTP{
		Request: &corev1.AccessLog_Entry_Info_HTTP_Request{
			Uri:       getLogURI(req),
			Path:      req.URL.Path,
			UserAgent: req.Header.Get("User-Agent"),
			Method:    req.Method,
			Referer:   getLogReferer(req),
			Scheme:    req.URL.Scheme,
			BodyBytes: func() uint64 {
				if req.ContentLength < 0 {
					return 0
				}
				return uint64(req.ContentLength)
			}(),
			ForwardedHost: func() string {
				svc := reqCtx.Service
				if svc != nil && ucorev1.ToService(svc).IsManagedService() &&
					svc.Status.ManagedService != nil &&
					svc.Status.ManagedService.ForwardHost {
					return req.Header.Get("X-Forwarded-Host")
				}
				return ""
			}(),
			Body:    reqBody,
			BodyMap: reqBodyMap,
			Origin:  req.Header.Get("Origin"),
			Headers: reqHeaders,
		},
		Response: &corev1.AccessLog_Entry_Info_HTTP_Response{
			Code:        uint32(crw.statusCode),
			BodyBytes:   uint64(atomic.LoadInt64(&crw.bytesWritten)),
			Body:        respBody,
			BodyMap:     respBodyMap,
			ContentType: crwHeader.Get("Content-Type"),
			Headers:     respHeaders,
		},
		HttpVersion: func() corev1.AccessLog_Entry_Info_HTTP_HTTPVersion {

			switch {
			case req.ProtoMajor == 2:
				return corev1.AccessLog_Entry_Info_HTTP_HTTP2
			case req.ProtoMajor == 1 && req.ProtoMinor == 1:
				return corev1.AccessLog_Entry_Info_HTTP_HTTP11
			default:
				return corev1.AccessLog_Entry_Info_HTTP_HTTP_VERSION_UNKNOWN
			}
		}(),
	}

	svc := reqCtx.Service

	switch {
	case ucorev1.ToService(svc).IsKubernetes():
		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Kubernetes_{
			Kubernetes: &corev1.AccessLog_Entry_Info_Kubernetes{
				Http: httpC,
			},
		}
		k8sI := reqCtx.DownstreamInfo.Request.GetKubernetes()
		if k8sI != nil {
			k8sC := logE.Entry.Info.GetKubernetes()
			k8sC.Verb = k8sI.Verb
			k8sC.ApiGroup = k8sI.ApiGroup
			k8sC.ApiPrefix = k8sI.ApiPrefix
			k8sC.ApiVersion = k8sI.ApiVersion
			k8sC.Namespace = k8sI.Namespace
			k8sC.Resource = k8sI.Resource
			k8sC.Subresource = k8sI.Subresource
			k8sC.Name = k8sI.Name
		}
	case ucorev1.ToService(svc).IsMCP():
		mcpC := &corev1.AccessLog_Entry_Info_MCP{
			Http: httpC,
		}
		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Mcp{
			Mcp: mcpC,
		}

		if mcpI := reqCtx.DownstreamInfo.Request.GetMcp(); mcpI != nil {
			mcpC.ProtocolVersion = mcpI.ProtocolVersion
			mcpC.Method = mcpI.Method
			mcpC.Name = mcpI.Name
			mcpC.RequestID = mcpI.RequestID
			mcpC.IsNotification = mcpI.IsNotification
			mcpC.SessionID = mcpI.SessionID

			if mcpI.Client != nil {
				mcpC.Client = &corev1.AccessLog_Entry_Info_MCP_Client{
					Name:    mcpI.Client.Name,
					Version: mcpI.Client.Version,
					Title:   mcpI.Client.Title,
				}
			}
		}
	case ucorev1.ToService(svc).IsGRPC():
		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Grpc{
			Grpc: &corev1.AccessLog_Entry_Info_GRPC{
				Http: httpC,
			},
		}
		grpcI := reqCtx.DownstreamInfo.Request.GetGrpc()
		if grpcI != nil {
			grpcC := logE.Entry.Info.GetGrpc()
			grpcC.Method = grpcI.Method
			grpcC.Package = grpcI.Package
			grpcC.Service = grpcI.Service
			grpcC.ServiceFullName = grpcI.ServiceFullName
			grpcC.Message = crwHeader.Get("Grpc-Message")
			status, _ := strconv.ParseInt(crwHeader.Get("Grpc-Status"), 10, 32)
			grpcC.Status = int32(status)
		}
	default:
		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Http{
			Http: httpC,
		}
	}

	return logE
}

var sensitiveRequestHeaders = []string{
	"Authorization",
	"Cookie",
	"Cookie2",
	"Grpc-Metadata-Authorization",
	"Proxy-Authorization",
	"Referer",
	"Sec-Websocket-Protocol",
	"X-Api-Key",
	"X-Auth-Token",
	"X-Octelium-Auth",
	"X-Octelium-Refresh-Token",
	"X-Octelium-Session-Ref",
	"X-Octelium-Session-Uid",
}

var sensitiveResponseHeaders = []string{
	"Authentication-Info",
	"Authorization",
	"Location",
	"Proxy-Authentication-Info",
	"Refresh",
	"Sec-Websocket-Protocol",
	"Set-Cookie",
	"Set-Cookie2",
	"X-Auth-Token",
	"X-Octelium-Auth",
	"X-Octelium-Refresh-Token",
	"X-Octelium-Session-Ref",
	"X-Octelium-Session-Uid",
}

func getRequestHeaderMap(req *http.Request, cfg *corev1.Service_Spec_Config_HTTP_Visibility,
	customAuthHeader string) map[string]string {
	if cfg == nil {
		return nil
	}

	var ret map[string]string

	if cfg.IncludeAllRequestHeaders {
		ret = httputils.GetHeaders(req.Header)
	} else if len(cfg.IncludeRequestHeaders) > 0 {
		ret = make(map[string]string)
		for _, hdr := range cfg.IncludeRequestHeaders {
			hdr = http.CanonicalHeaderKey(hdr)
			if val := req.Header.Get(hdr); val != "" {
				ret[hdr] = val
			}
		}
	}

	if len(cfg.ExcludeRequestHeaders) > 0 && len(ret) > 0 {
		deleteHeaderMap(ret, cfg.ExcludeRequestHeaders...)
	}

	if ret != nil {
		deleteHeaderMap(ret, sensitiveRequestHeaders...)
		deleteHeaderMap(ret, customAuthHeader)
	}

	return ret
}

func getResponseHeaderMap(rw http.ResponseWriter, cfg *corev1.Service_Spec_Config_HTTP_Visibility) map[string]string {
	if cfg == nil {
		return nil
	}

	var ret map[string]string

	if cfg.IncludeAllResponseHeaders {
		ret = httputils.GetHeaders(rw.Header())
	} else if len(cfg.IncludeResponseHeaders) > 0 {
		ret = make(map[string]string)
		for _, hdr := range cfg.IncludeResponseHeaders {
			hdr = http.CanonicalHeaderKey(hdr)
			if val := rw.Header().Get(hdr); val != "" {
				ret[hdr] = val
			}
		}
	}

	if len(cfg.ExcludeResponseHeaders) > 0 && len(ret) > 0 {
		deleteHeaderMap(ret, cfg.ExcludeResponseHeaders...)
	}

	if ret != nil {
		deleteHeaderMap(ret, sensitiveResponseHeaders...)
	}

	return ret
}

func deleteHeaderMap(headers map[string]string, names ...string) {
	for key := range headers {
		for _, name := range names {
			if strings.EqualFold(key, name) {
				delete(headers, key)
				break
			}
		}
	}
}

func getLogURI(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}

	u := *req.URL
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.RequestURI()
}

func getLogReferer(req *http.Request) string {
	if req == nil {
		return ""
	}

	u, err := url.Parse(req.Referer())
	if err != nil {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String()
}

type responseWriter struct {
	http.ResponseWriter

	body *bytes.Buffer

	statusCode   int
	bytesWritten int64

	firstByteAt time.Time

	kind    streamKind
	writeMu sync.Mutex

	onFirstByte func()
	onSSEEvent  func([]byte)
	sseLineBuf  []byte
	sseMu       sync.Mutex
	sseEventCnt atomic.Int64

	mcpResolved bool
	mcpIsSSE    bool
	maxSSEEvent int
}

func (rw *responseWriter) resolveMCPKind() {
	if rw.mcpResolved {
		return
	}
	rw.mcpResolved = true

	ct := rw.Header().Get("Content-Type")
	mediaType := strings.TrimSpace(strings.Split(ct, ";")[0])
	rw.mcpIsSSE = strings.EqualFold(mediaType, "text/event-stream")
}

func newResponseWriter(w http.ResponseWriter, kind streamKind) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
		kind:           kind,
	}
}

func (rw *responseWriter) eventCount() int64 {
	return rw.sseEventCnt.Load()
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.writeMu.Lock()
	defer rw.writeMu.Unlock()

	var isFirstByte bool
	if rw.firstByteAt.IsZero() && len(b) > 0 {
		rw.firstByteAt = time.Now()
		isFirstByte = true
	}

	n, err := rw.ResponseWriter.Write(b)
	if n > 0 {
		atomic.AddInt64(&rw.bytesWritten, int64(n))

		switch rw.kind {
		case streamKindNone:
			rw.bufferBody(b[:n])
		case streamKindSSE:
			rw.parseSSEEvents(b[:n])
		case streamKindMCP:
			rw.resolveMCPKind()
			if rw.mcpIsSSE {
				rw.parseSSEEvents(b[:n])
			} else {
				rw.bufferBody(b[:n])
			}
		}

		if isFirstByte && rw.onFirstByte != nil {
			rw.onFirstByte()
		}
	}
	return n, err
}

func (rw *responseWriter) bufferBody(p []byte) {
	if rw.body.Len() >= maxBodyLen {
		return
	}

	remaining := maxBodyLen - rw.body.Len()
	if len(p) <= remaining {
		rw.body.Write(p)
	} else {
		rw.body.Write(p[:remaining])
	}
}

func (rw *responseWriter) parseSSEEvents(p []byte) {
	if rw.onSSEEvent == nil {
		return
	}

	rw.sseMu.Lock()
	defer rw.sseMu.Unlock()

	rw.sseLineBuf = append(rw.sseLineBuf, p...)

	for {
		idx := bytes.Index(rw.sseLineBuf, []byte("\n\n"))
		if idx == -1 {
			idx = bytes.Index(rw.sseLineBuf, []byte("\r\n\r\n"))
			if idx == -1 {
				break
			}
			event := make([]byte, idx)
			copy(event, rw.sseLineBuf[:idx])
			rw.sseLineBuf = rw.sseLineBuf[idx+4:]
			rw.sseEventCnt.Add(1)
			rw.onSSEEvent(event)
			continue
		}
		event := make([]byte, idx)
		copy(event, rw.sseLineBuf[:idx])
		rw.sseLineBuf = rw.sseLineBuf[idx+2:]
		rw.sseEventCnt.Add(1)
		rw.onSSEEvent(event)
	}

	maxSSELineBuf := defaultMaxSSELineBuf
	if rw.maxSSEEvent > 0 {
		maxSSELineBuf = rw.maxSSEEvent
	}
	if len(rw.sseLineBuf) > maxSSELineBuf {
		newBuf := make([]byte, maxSSELineBuf)
		copy(newBuf, rw.sseLineBuf[len(rw.sseLineBuf)-maxSSELineBuf:])
		rw.sseLineBuf = newBuf
	}
}

const defaultMaxSSELineBuf = 64 * 1024

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}
	return hj.Hijack()
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := rw.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func isWebSocketUpgrade(req *http.Request) bool {
	if !httpguts.HeaderValuesContainsToken(req.Header["Connection"], "Upgrade") {
		return false
	}

	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
}
