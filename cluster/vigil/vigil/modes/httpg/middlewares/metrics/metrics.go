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
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/net/http/httpguts"
)

const (
	maxMCPNameValues     = 128
	maxGRPCServiceValues = 128
	maxGRPCMethodValues  = 256
)

type middleware struct {
	next          http.Handler
	commonMetrics *metricutils.CommonMetrics
	llmMetrics    *metricutils.LLMMetrics
	mcpNames      *metricutils.BoundedValues
	grpcServices  *metricutils.BoundedValues
	grpcMethods   *metricutils.BoundedValues
}

func New(ctx context.Context, next http.Handler,
	commonMetrics *metricutils.CommonMetrics,
	llmMetrics *metricutils.LLMMetrics) (http.Handler, error) {

	return &middleware{
		next:          next,
		commonMetrics: commonMetrics,
		llmMetrics:    llmMetrics,
		mcpNames:      metricutils.NewBoundedValues(maxMCPNameValues),
		grpcServices:  metricutils.NewBoundedValues(maxGRPCServiceValues),
		grpcMethods:   metricutils.NewBoundedValues(maxGRPCMethodValues),
	}, nil
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	reqCtx := middlewares.GetCtxRequestContext(req.Context())

	streamKind := getStreamKind(req, reqCtx)

	crw := &responseWriter{
		ResponseWriter: w,
		statusCode:     200,
	}

	crb := &requestBody{ReadCloser: req.Body}
	if req.Body != nil {
		req.Body = crb
	}

	m.commonMetrics.AtRequestStart()

	if streamKind != streamKindNone {
		m.commonMetrics.AtSessionStart()
	} else {
		crw.onSSE = m.commonMetrics.AtSessionStart
	}

	defer func() {
		if crw.isSSE.Load() {
			streamKind = streamKindSSE
		}

		attrs := m.getAttributes(req, crw, reqCtx, streamKind)
		attrSet := metric.WithAttributeSet(attribute.NewSet(attrs...))

		transferAttrSet := metric.WithAttributeSet(attribute.NewSet(
			attribute.String("state", getState(reqCtx)),
			attribute.String("req.http.stream", streamKind.String()),
		))

		m.commonMetrics.AtRequestEnd(reqCtx.CreatedAt, attrSet)

		if streamKind != streamKindNone {
			m.commonMetrics.AtSessionEnd(reqCtx.CreatedAt, transferAttrSet)
		}

		m.commonMetrics.AddBytesTransferred(
			crw.bytesWritten.Load(), crb.bytesRead.Load(), transferAttrSet)

		if ttfb := crw.firstByteAt.Load(); ttfb != nil {
			m.commonMetrics.RequestTTFB.Record(context.Background(),
				float64(ttfb.Sub(reqCtx.CreatedAt).Nanoseconds())/1000000,
				metric.WithAttributeSet(m.commonMetrics.CommonAttributeSet),
				transferAttrSet)
		}

		if ucorev1.ToService(reqCtx.Service).IsLLM() {
			m.recordLLMUsage(reqCtx)
		}
	}()

	m.next.ServeHTTP(crw, req)
}

func getState(reqCtx *middlewares.RequestContext) string {
	if reqCtx.IsAuthorized {
		return "ALLOWED"
	}
	return "DENIED"
}

func (m *middleware) getAttributes(req *http.Request, crw *responseWriter,
	reqCtx *middlewares.RequestContext, streamKind streamKind) []attribute.KeyValue {

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
			Value: attribute.StringValue(getState(reqCtx)),
		},
		{
			Key:   "req.http.version",
			Value: attribute.StringValue(getHTTPVersion(req)),
		},
		{
			Key:   "req.http.stream",
			Value: attribute.StringValue(streamKind.String()),
		},
	}

	if !reqCtx.IsAuthorized {
		attrs = append(attrs,
			attribute.KeyValue{
				Key:   "reason",
				Value: attribute.StringValue(reqCtx.DecisionReason.GetType().String()),
			},
			attribute.KeyValue{
				Key:   "req.authenticated",
				Value: attribute.BoolValue(reqCtx.IsAuthenticated),
			},
		)
	}

	if reqCtx.Service == nil {
		return attrs
	}

	svc := ucorev1.ToService(reqCtx.Service)

	switch {
	case svc.IsGRPC():
		attrs = append(attrs, m.getGRPCAttributes(crw, reqCtx)...)
	case svc.IsKubernetes():
		attrs = append(attrs, getKubernetesAttributes(reqCtx)...)
	case svc.IsMCP():
		attrs = append(attrs, m.getMCPAttributes(reqCtx)...)
	case svc.IsLLM():
		attrs = append(attrs, m.getLLMAttributes(reqCtx)...)
	}

	return attrs
}

func (m *middleware) getGRPCAttributes(crw *responseWriter,
	reqCtx *middlewares.RequestContext) []attribute.KeyValue {

	code, hasCode := getGRPCStatusCode(crw.Header())

	statusName := metricutils.ValueUnset
	statusClass := metricutils.ValueUnset

	if hasCode {
		statusName = getGRPCStatusName(code)
		statusClass = getGRPCStatusClass(code)
	}

	grpcI := reqCtx.DownstreamInfo.GetRequest().GetGrpc()

	return []attribute.KeyValue{
		{
			Key:   "req.grpc.status",
			Value: attribute.StringValue(statusName),
		},
		{
			Key:   "req.grpc.status_class",
			Value: attribute.StringValue(statusClass),
		},
		{
			Key: "req.grpc.service_full_name",
			Value: attribute.StringValue(
				m.grpcServices.Get(grpcI.GetServiceFullName())),
		},
		{
			Key:   "req.grpc.method",
			Value: attribute.StringValue(m.grpcMethods.Get(grpcI.GetMethod())),
		},
	}
}

func getGRPCStatusCode(hdr http.Header) (int, bool) {
	raw := hdr.Get("Grpc-Status")
	if raw == "" {
		raw = hdr.Get(http.TrailerPrefix + "Grpc-Status")
	}
	if raw == "" {
		return 0, false
	}

	code, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, false
	}

	return code, true
}

var grpcStatusNames = []string{
	"OK",
	"CANCELLED",
	"UNKNOWN",
	"INVALID_ARGUMENT",
	"DEADLINE_EXCEEDED",
	"NOT_FOUND",
	"ALREADY_EXISTS",
	"PERMISSION_DENIED",
	"RESOURCE_EXHAUSTED",
	"FAILED_PRECONDITION",
	"ABORTED",
	"OUT_OF_RANGE",
	"UNIMPLEMENTED",
	"INTERNAL",
	"UNAVAILABLE",
	"DATA_LOSS",
	"UNAUTHENTICATED",
}

func getGRPCStatusName(code int) string {
	if code < 0 || code >= len(grpcStatusNames) {
		return metricutils.ValueOther
	}
	return grpcStatusNames[code]
}

func getGRPCStatusClass(code int) string {
	switch code {
	case 0:
		return "OK"
	case 1:
		return "CANCELLED"
	case 3, 5, 6, 7, 9, 11, 16:
		return "CLIENT_ERROR"
	case 2, 4, 8, 10, 12, 13, 14, 15:
		return "SERVER_ERROR"
	default:
		return metricutils.ValueOther
	}
}

func getKubernetesAttributes(reqCtx *middlewares.RequestContext) []attribute.KeyValue {
	k8sI := reqCtx.DownstreamInfo.GetRequest().GetKubernetes()

	return []attribute.KeyValue{
		{
			Key: "req.k8s.verb",
			Value: attribute.StringValue(
				metricutils.BoundedSlice(k8sI.GetVerb(), k8sVerbs)),
		},
		{
			Key: "req.k8s.resource",
			Value: attribute.StringValue(
				metricutils.BoundedSlice(k8sI.GetResource(), k8sResources)),
		},
		{
			Key: "req.k8s.subresource",
			Value: attribute.StringValue(
				metricutils.BoundedSlice(k8sI.GetSubresource(), k8sSubresources)),
		},
		{
			Key: "req.k8s.api_group",
			Value: attribute.StringValue(
				metricutils.BoundedSlice(k8sI.GetApiGroup(), k8sAPIGroups)),
		},
	}
}

var k8sVerbs = []string{
	"get", "list", "watch", "create", "update", "patch",
	"delete", "deletecollection", "proxy",
}

var k8sSubresources = []string{
	"exec", "attach", "portforward", "log", "status", "scale",
	"proxy", "binding", "eviction", "token", "finalize", "approval",
}

var k8sResources = []string{
	"pods", "services", "endpoints", "nodes", "namespaces", "events",
	"secrets", "configmaps", "serviceaccounts", "persistentvolumes",
	"persistentvolumeclaims", "replicationcontrollers", "resourcequotas",
	"limitranges", "deployments", "replicasets", "statefulsets", "daemonsets",
	"jobs", "cronjobs", "ingresses", "networkpolicies", "roles", "rolebindings",
	"clusterroles", "clusterrolebindings", "customresourcedefinitions",
	"horizontalpodautoscalers", "poddisruptionbudgets", "storageclasses",
	"volumeattachments", "leases", "endpointslices", "apiservices",
	"validatingwebhookconfigurations", "mutatingwebhookconfigurations",
	"controllerrevisions", "csidrivers", "csinodes", "priorityclasses",
}

var k8sAPIGroups = []string{
	"apps", "batch", "extensions", "networking.k8s.io", "rbac.authorization.k8s.io",
	"storage.k8s.io", "policy", "autoscaling", "apiextensions.k8s.io",
	"admissionregistration.k8s.io", "coordination.k8s.io", "discovery.k8s.io",
	"apiregistration.k8s.io", "authentication.k8s.io", "authorization.k8s.io",
	"certificates.k8s.io", "scheduling.k8s.io", "node.k8s.io", "events.k8s.io",
	"flowcontrol.apiserver.k8s.io",
}

func (m *middleware) getMCPAttributes(
	reqCtx *middlewares.RequestContext) []attribute.KeyValue {

	return []attribute.KeyValue{
		{
			Key:   "req.mcp.method",
			Value: attribute.StringValue(getMCPMethod(reqCtx)),
		},
		{
			Key:   "req.mcp.protocol_version",
			Value: attribute.StringValue(getMCPProtocolVersion(reqCtx)),
		},
		{
			Key:   "req.mcp.name",
			Value: attribute.StringValue(m.mcpNames.Get(reqCtx.MCP.GetName())),
		},
		{
			Key: "req.mcp.is_notification",
			Value: attribute.BoolValue(
				reqCtx.DownstreamInfo.GetRequest().GetMcp().GetIsNotification()),
		},
		{
			Key:   "req.mcp.error",
			Value: attribute.StringValue(getMCPError(reqCtx)),
		},
	}
}

func getMCPError(reqCtx *middlewares.RequestContext) string {
	resp := reqCtx.MCPResponse
	switch {
	case resp == nil:
		return metricutils.ValueUnset
	case resp.IsProtocolError:
		return "PROTOCOL"
	case resp.IsToolError:
		return "TOOL"
	default:
		return metricutils.ValueNone
	}
}

func (m *middleware) getLLMAttributes(
	reqCtx *middlewares.RequestContext) []attribute.KeyValue {

	return []attribute.KeyValue{
		{
			Key:   "req.llm.operation",
			Value: attribute.StringValue(reqCtx.LLM.GetOperation().String()),
		},
		{
			Key:   "req.llm.protocol",
			Value: attribute.StringValue(reqCtx.LLM.GetProtocol().String()),
		},
		{
			Key:   "req.llm.stream",
			Value: attribute.BoolValue(reqCtx.LLM.GetStream()),
		},
		{
			Key:   "req.llm.model",
			Value: attribute.StringValue(m.getLLMModel(reqCtx)),
		},
		{
			Key:   "req.llm.finish_reason",
			Value: attribute.StringValue(getLLMFinishReason(reqCtx)),
		},
	}
}

func (m *middleware) getLLMModel(reqCtx *middlewares.RequestContext) string {
	model := reqCtx.LLMResponse.GetModel()
	if model == "" {
		model = reqCtx.LLM.GetModel()
	}
	return m.llmMetrics.Models.Get(model)
}

var llmFinishReasons = []string{
	"stop", "length", "tool_calls", "content_filter", "function_call",
	"end_turn", "max_tokens", "stop_sequence", "tool_use", "pause_turn",
	"refusal", "completed", "incomplete", "failed", "cancelled",
}

func getLLMFinishReason(reqCtx *middlewares.RequestContext) string {
	return metricutils.BoundedSlice(
		reqCtx.LLMResponse.GetFinishReason(), llmFinishReasons)
}

func (m *middleware) recordLLMUsage(reqCtx *middlewares.RequestContext) {
	resp := reqCtx.LLMResponse
	if resp == nil {
		return
	}

	m.llmMetrics.AddUsage(&metricutils.LLMUsageOpts{
		InputTokens:      resp.Usage.InputTokens,
		OutputTokens:     resp.Usage.OutputTokens,
		CacheReadTokens:  resp.Usage.CacheReadInputTokens,
		CacheWriteTokens: resp.Usage.CacheCreationInputTokens,
		ReasoningTokens:  resp.Usage.ReasoningTokens,
		TotalTokens:      resp.Usage.TotalTokens,
		StreamEvents:     resp.EventCount,
		TimeToFirstToken: resp.TimeToFirstToken,
	}, metric.WithAttributes(
		attribute.String("req.llm.model", m.getLLMModel(reqCtx)),
		attribute.String("req.llm.operation", reqCtx.LLM.GetOperation().String()),
		attribute.String("req.llm.protocol", reqCtx.LLM.GetProtocol().String()),
		attribute.String("req.llm.usage_source", resp.UsageSource.String()),
	))
}

type streamKind int

const (
	streamKindNone streamKind = iota
	streamKindSSE
	streamKindWebSocket
	streamKindK8sExec
	streamKindK8sLog
	streamKindK8sPortForward
	streamKindK8sWatch
	streamKindGeneric
)

func (s streamKind) String() string {
	switch s {
	case streamKindSSE:
		return "SSE"
	case streamKindWebSocket:
		return "WEBSOCKET"
	case streamKindK8sExec:
		return "K8S_EXEC"
	case streamKindK8sLog:
		return "K8S_LOG"
	case streamKindK8sPortForward:
		return "K8S_PORTFORWARD"
	case streamKindK8sWatch:
		return "K8S_WATCH"
	case streamKindGeneric:
		return "GENERIC"
	default:
		return "NONE"
	}
}

func getStreamKind(req *http.Request, reqCtx *middlewares.RequestContext) streamKind {
	if reqCtx.Service != nil && ucorev1.ToService(reqCtx.Service).IsKubernetes() {
		path := req.URL.Path
		q := req.URL.Query()

		switch {
		case strings.HasSuffix(path, "/exec") || strings.HasSuffix(path, "/attach"):
			return streamKindK8sExec
		case strings.HasSuffix(path, "/portforward"):
			return streamKindK8sPortForward
		case strings.HasSuffix(path, "/log") && isTrueQueryValue(q.Get("follow")):
			return streamKindK8sLog
		case isTrueQueryValue(q.Get("watch")):
			return streamKindK8sWatch
		case isTrueQueryValue(q.Get("follow")):
			return streamKindGeneric
		}
	}

	if isWebSocketUpgrade(req) {
		return streamKindWebSocket
	}

	if strings.Contains(
		strings.ToLower(req.Header.Get("Accept")), "text/event-stream") {
		return streamKindSSE
	}

	return streamKindNone
}

func isTrueQueryValue(arg string) bool {
	switch arg {
	case "true", "1":
		return true
	default:
		return false
	}
}

func isWebSocketUpgrade(req *http.Request) bool {
	if !httpguts.HeaderValuesContainsToken(req.Header["Connection"], "Upgrade") {
		return false
	}

	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
}

func getHTTPVersion(req *http.Request) string {
	switch {
	case req.ProtoMajor == 2:
		return "HTTP2"
	case req.ProtoMajor == 1 && req.ProtoMinor == 1:
		return "HTTP11"
	case req.ProtoMajor == 1 && req.ProtoMinor == 0:
		return "HTTP10"
	default:
		return metricutils.ValueUnknown
	}
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

type requestBody struct {
	io.ReadCloser
	bytesRead atomic.Int64
}

func (r *requestBody) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.bytesRead.Add(int64(n))
	}
	return n, err
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int

	bytesWritten atomic.Int64
	firstByteAt  atomic.Pointer[time.Time]

	onSSE       func()
	isSSE       atomic.Bool
	sseResolved sync.Once
}

func (r *responseWriter) setFirstByteAt() {
	if r.firstByteAt.Load() != nil {
		return
	}
	now := time.Now()
	r.firstByteAt.CompareAndSwap(nil, &now)
}

func (r *responseWriter) resolveSSE() {
	if r.onSSE == nil {
		return
	}

	r.sseResolved.Do(func() {
		mediaType := strings.TrimSpace(
			strings.Split(r.Header().Get("Content-Type"), ";")[0])
		if !strings.EqualFold(mediaType, "text/event-stream") {
			return
		}

		r.isSSE.Store(true)
		r.onSSE()
	})
}

func (r *responseWriter) WriteHeader(status int) {
	r.setFirstByteAt()
	r.resolveSSE()
	r.ResponseWriter.WriteHeader(status)
	r.statusCode = status
}

func (r *responseWriter) Write(p []byte) (int, error) {
	r.setFirstByteAt()
	r.resolveSSE()
	n, err := r.ResponseWriter.Write(p)
	if n > 0 {
		r.bytesWritten.Add(int64(n))
	}
	return n, err
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
