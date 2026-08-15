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

package metrics

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"slices"

	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type middleware struct {
	next          http.Handler
	commonMetrics *metricutils.CommonMetrics
}

func New(ctx context.Context, next http.Handler, commonMetrics *metricutils.CommonMetrics) (http.Handler, error) {

	return &middleware{
		next:          next,
		commonMetrics: commonMetrics,
	}, nil
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	reqCtx := middlewares.GetCtxRequestContext(req.Context())

	m.commonMetrics.AtRequestStart()

	crw := &responseWriter{
		ResponseWriter: w,
		statusCode:     200,
	}
	m.next.ServeHTTP(crw, req)

	state := func() string {
		switch {
		case reqCtx.IsAuthorized:
			return "ALLOWED"
		default:
			return "DENIED"
		}
	}()

	attrs := []attribute.KeyValue{
		{
			Key:   "req.http.method",
			Value: attribute.StringValue(getMethod(req)),
		},
		{
			Key:   "req.http.status",
			Value: attribute.StringValue(getStatusState(crw.statusCode)),
		},
		{
			Key:   "state",
			Value: attribute.StringValue(state),
		},
	}

	if !reqCtx.IsAuthorized {
		attrs = append(attrs, attribute.KeyValue{
			Key:   "reason",
			Value: attribute.StringValue(reqCtx.DecisionReason.GetType().String()),
		})
	}

	if ucorev1.ToService(reqCtx.Service).IsMCP() {
		attrs = append(attrs,
			attribute.KeyValue{
				Key:   "req.mcp.method",
				Value: attribute.StringValue(getMCPMethod(reqCtx)),
			},
			attribute.KeyValue{
				Key:   "req.mcp.protocol_version",
				Value: attribute.StringValue(getMCPProtocolVersion(reqCtx)),
			},
		)
	}

	m.commonMetrics.AtRequestEnd(reqCtx.CreatedAt, metric.WithAttributeSet(attribute.NewSet(attrs...)))
}

func getMCPProtocolVersion(reqCtx *middlewares.RequestContext) string {
	version := reqCtx.MCP.GetProtocolVersion()
	switch {
	case version == "":
		return "UNSET"
	case slices.Contains(mcpProtocolVersions, version):
		return version
	case slices.Contains(
		reqCtx.ServiceConfig.GetMcp().GetProtocol().GetVersions(), version):
		return version
	default:
		return "OTHER"
	}
}

var mcpProtocolVersions = []string{
	"2024-11-05",
	"2025-03-26",
	"2025-06-18",
	"2025-11-25",
	"2026-07-28",
}

func getMCPMethod(reqCtx *middlewares.RequestContext) string {
	method := reqCtx.MCP.GetMethod()
	switch {
	case method == "":
		return "UNKNOWN"
	case httputils.IsMCPMethodKnown(method):
		return method
	default:
		return "OTHER"
	}
}

func getMethod(req *http.Request) string {
	switch req.Method {
	case "GET", "POST", "DELETE", "PUT", "OPTIONS", "CONNECT", "TRACE", "PATCH", "HEAD":
		return req.Method
	default:
		return "UNKNOWN"
	}
}

func getStatusState(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 500 && code < 600:
		return "5xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 100 && code < 200:
		return "1xx"
	default:
		return "UNKNOWN"
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseWriter) WriteHeader(status int) {
	r.ResponseWriter.WriteHeader(status)
	r.statusCode = status
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}

	return hj.Hijack()
}

func (r *responseWriter) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := p.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
