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
)

const (
	maxBodyLen     = 3 * 1024 * 1024
	maxSSEEventLog = 10
	sseLogInterval = 30 * time.Second
)

func (m *middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	kind := detectStreamKind(req, reqCtx)

	if kind == streamKindNone {
		m.serveNonStreaming(w, req, reqCtx)
		return
	}

	m.serveStreaming(w, req, reqCtx, kind)
}

func detectStreamKind(req *http.Request, reqCtx *middlewares.RequestContext) streamKind {
	svc := reqCtx.Service

	if isWebSocketUpgrade(req) {
		return streamKindWS
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

	if kind == streamKindSSE {
		var eventCount int64
		var mu sync.Mutex
		lastLog := time.Now()

		svcCfg := reqCtx.ServiceConfig
		var visibilityCfg *corev1.Service_Spec_Config_HTTP_Visibility
		if svcCfg != nil && svcCfg.GetHttp() != nil && svcCfg.GetHttp().Visibility != nil {
			visibilityCfg = svcCfg.GetHttp().Visibility
		}

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

			if visibilityCfg != nil {
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

	if crw.firstByteAt != (time.Time{}) {
		otelutils.EmitAccessLog(m.getAccessLog(req, crw, reqCtx, logPhaseStreamOpen, connID, 0))
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

func (m *middleware) getAccessLog(
	req *http.Request,
	crw *responseWriter,
	reqCtx *middlewares.RequestContext,
	phase logPhase,
	connID string,
	eventSeq int64) *corev1.AccessLog {

	svcCfg := reqCtx.ServiceConfig
	var visibilityCfg *corev1.Service_Spec_Config_HTTP_Visibility
	if svcCfg != nil && svcCfg.GetHttp() != nil && svcCfg.GetHttp().Visibility != nil {
		visibilityCfg = svcCfg.GetHttp().Visibility
	}

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

		reqHeaders = getRequestHeaderMap(req, visibilityCfg)
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
			Uri:       req.URL.RequestURI(),
			Path:      req.URL.Path,
			UserAgent: req.Header.Get("User-Agent"),
			Method:    req.Method,
			Referer:   req.Referer(),
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

func getRequestHeaderMap(req *http.Request, cfg *corev1.Service_Spec_Config_HTTP_Visibility) map[string]string {
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
		for _, hdr := range cfg.ExcludeRequestHeaders {
			delete(ret, http.CanonicalHeaderKey(hdr))
		}
	}

	if ret != nil {
		delete(ret, "Authorization")
		delete(ret, "Cookie")
		delete(ret, "X-Api-Key")
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
		for _, hdr := range cfg.ExcludeResponseHeaders {
			delete(ret, http.CanonicalHeaderKey(hdr))
		}
	}

	if ret != nil {
		delete(ret, "Set-Cookie")
	}

	return ret
}

type responseWriter struct {
	http.ResponseWriter

	body *bytes.Buffer

	statusCode   int
	bytesWritten int64

	firstByteAt time.Time

	kind    streamKind
	writeMu sync.Mutex

	onSSEEvent  func([]byte)
	sseLineBuf  []byte
	sseMu       sync.Mutex
	sseEventCnt atomic.Int64
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

	if rw.firstByteAt.IsZero() && len(b) > 0 {
		rw.firstByteAt = time.Now()
	}

	n, err := rw.ResponseWriter.Write(b)
	if n > 0 {
		atomic.AddInt64(&rw.bytesWritten, int64(n))

		switch rw.kind {
		case streamKindNone:
			if rw.body.Len() < maxBodyLen {
				remaining := maxBodyLen - rw.body.Len()
				if n <= remaining {
					rw.body.Write(b[:n])
				} else {
					rw.body.Write(b[:remaining])
				}
			}
		case streamKindSSE:
			rw.parseSSEEvents(b[:n])
		}
	}
	return n, err
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

	const maxSSELineBuf = 64 * 1024
	if len(rw.sseLineBuf) > maxSSELineBuf {
		newBuf := make([]byte, maxSSELineBuf)
		copy(newBuf, rw.sseLineBuf[len(rw.sseLineBuf)-maxSSELineBuf:])
		rw.sseLineBuf = newBuf
	}
}

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
