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
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
)

type middleware struct {
	next http.Handler
}

func New(ctx context.Context, next http.Handler) (http.Handler, error) {
	return &middleware{
		next: next,
	}, nil
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	var crr *captureRequestReader
	ctx := req.Context()
	reqClone := req.Clone(ctx)
	if req.Body != nil {
		crr = &captureRequestReader{source: req.Body, count: 0}
		reqClone.Body = crr
	}

	crw := newCaptureResponseWriter(w)
	m.next.ServeHTTP(crw, reqClone)

	ctx = reqClone.Context()

	reqCtx := middlewares.GetCtxRequestContext(ctx)
	if reqCtx.DownstreamInfo == nil {
		return
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
			Path:      req.URL.RequestURI(),
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
		},
		Response: &corev1.AccessLog_Entry_Info_HTTP_Response{
			Code:      uint32(crw.Status()),
			BodyBytes: uint64(crw.Size()),
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
