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
	"context"
	"net/http"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
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

const maxBodyLen = 3 * 1024 * 1024

func (m *middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()

	m.next.ServeHTTP(w, req)
	crw, ok := w.(*commonplugin.ResponseWriter)
	if !ok {
		zap.L().Warn("rw is not commonplugin.ResponseWriter in accessLog middleware")
		return
	}

	rwBody := crw.GetBody()
	lenRespBody := crw.GetBodySize()

	reqCtx := middlewares.GetCtxRequestContext(ctx)
	if reqCtx.DownstreamInfo == nil {
		zap.L().Debug("No downstreamInfo. Skipping setting the log entry", zap.Any("reqCtx", reqCtx))
		return
	}

	svcCfg := reqCtx.ServiceConfig
	var visibilityCfg *corev1.Service_Spec_Config_HTTP_Visibility
	if svcCfg != nil && svcCfg.GetHttp() != nil && svcCfg.GetHttp().Visibility != nil {
		visibilityCfg = svcCfg.GetHttp().Visibility
	}

	var reqBody []byte
	var reqBodyMap *structpb.Struct
	var respBody []byte
	var respBodyMap *structpb.Struct

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

		if lenRespBody <= maxBodyLen {
			if visibilityCfg.EnableResponseBody {
				respBody = rwBody
			}
			if visibilityCfg.EnableResponseBodyMap && lenRespBody > 0 {
				ret := &structpb.Struct{}
				if err := pbutils.UnmarshalJSON(rwBody, ret); err != nil {
					zap.L().Debug("Could not unmarshalJSON respBody", zap.Error(err))
				} else {
					respBodyMap = ret
				}
			}
		}
	}

	opts := &logentry.InitializeLogEntryOpts{
		StartTime:       reqCtx.CreatedAt,
		IsAuthenticated: reqCtx.IsAuthenticated,
		IsAuthorized:    reqCtx.IsAuthorized || httputils.IsAnonymousMode(req),
		ReqCtx:          reqCtx.DownstreamInfo,
		Reason:          reqCtx.DecisionReason,
	}

	logE := logentry.InitializeLogEntry(opts)

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
		},
		Response: &corev1.AccessLog_Entry_Info_HTTP_Response{
			Code:        uint32(crw.GetStatusCode()),
			BodyBytes:   uint64(lenRespBody),
			Body:        respBody,
			BodyMap:     respBodyMap,
			ContentType: crw.Header().Get("Content-Type"),
		},
		HttpVersion: func() corev1.AccessLog_Entry_Info_HTTP_HTTPVersion {
			switch req.Proto {
			case "HTTP/2.0":
				return corev1.AccessLog_Entry_Info_HTTP_HTTP2
			case "HTTP/1.1":
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
		}
	default:
		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Http{
			Http: httpC,
		}
	}

	otelutils.EmitAccessLog(logE)
}

/*
type responseWriter struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
		statusCode:     http.StatusOK,
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
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
*/
