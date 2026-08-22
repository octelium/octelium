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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func newTestSvc() *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "svc1",
		},
		Spec: &corev1.Service_Spec{},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "ns1"},
			RegionRef:    &metav1.ObjectReference{Name: "region1"},
		},
	}
}

func setTestMeterProvider(t *testing.T) *sdkmetric.ManualReader {
	prevProvider := otel.GetMeterProvider()
	t.Cleanup(func() {
		otel.SetMeterProvider(prevProvider)
	})

	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))

	return reader
}

func findSumDataPoints(t *testing.T, rm *metricdata.ResourceMetrics, name string) []metricdata.DataPoint[int64] {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			assert.True(t, ok, name)
			return sum.DataPoints
		}
	}
	t.Fatalf("metric %s not found", name)
	return nil
}

func findHistogramDataPoint(t *testing.T, rm *metricdata.ResourceMetrics, name string) metricdata.HistogramDataPoint[float64] {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			his, ok := m.Data.(metricdata.Histogram[float64])
			assert.True(t, ok, name)
			assert.Len(t, his.DataPoints, 1)
			return his.DataPoints[0]
		}
	}
	t.Fatalf("metric %s not found", name)
	return metricdata.HistogramDataPoint[float64]{}
}

func hasMetric(rm *metricdata.ResourceMetrics, name string) bool {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return true
			}
		}
	}
	return false
}

func newTestMiddleware(t *testing.T, svc *corev1.Service,
	next http.Handler) http.Handler {
	ctx := context.Background()

	commonMetrics, err := metricutils.NewCommonMetrics(ctx, svc)
	assert.Nil(t, err)

	llmMetrics, err := metricutils.NewLLMMetrics(ctx, svc)
	assert.Nil(t, err)

	mdlwr, err := New(ctx, next, commonMetrics, llmMetrics)
	assert.Nil(t, err)

	return mdlwr
}

func newTestReq(t *testing.T, method, target string,
	body io.Reader, reqCtx *middlewares.RequestContext) *http.Request {
	req := httptest.NewRequest(method, target, body)
	return req.WithContext(
		context.WithValue(req.Context(), middlewares.CtxRequestContext, reqCtx))
}

func findSumDataPoint(t *testing.T, rm *metricdata.ResourceMetrics, name string) metricdata.DataPoint[int64] {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			assert.True(t, ok, name)
			assert.Len(t, sum.DataPoints, 1)
			return sum.DataPoints[0]
		}
	}
	t.Fatalf("metric %s not found", name)
	return metricdata.DataPoint[int64]{}
}

func TestServeHTTPDeniedReason(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	commonMetrics, err := metricutils.NewCommonMetrics(ctx, newTestSvc())
	assert.Nil(t, err)

	llmMetrics, err := metricutils.NewLLMMetrics(ctx, newTestSvc())
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	mdlwr, err := New(ctx, next, commonMetrics, llmMetrics)
	assert.Nil(t, err)

	reqCtx := &middlewares.RequestContext{
		CreatedAt:    time.Now(),
		IsAuthorized: false,
		DecisionReason: &corev1.AccessLog_Entry_Common_Reason{
			Type: corev1.AccessLog_Entry_Common_Reason_SESSION_EXPIRED,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req = req.WithContext(context.WithValue(req.Context(), middlewares.CtxRequestContext, reqCtx))

	rec := httptest.NewRecorder()
	mdlwr.ServeHTTP(rec, req)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	dp := findSumDataPoint(t, &rm, "req.total")

	stateVal, ok := dp.Attributes.Value("state")
	assert.True(t, ok)
	assert.Equal(t, "DENIED", stateVal.AsString())

	reasonVal, ok := dp.Attributes.Value("reason")
	assert.True(t, ok)
	assert.Equal(t, "SESSION_EXPIRED", reasonVal.AsString())
}

func TestServeHTTPAllowedNoReason(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	commonMetrics, err := metricutils.NewCommonMetrics(ctx, newTestSvc())
	assert.Nil(t, err)

	llmMetrics, err := metricutils.NewLLMMetrics(ctx, newTestSvc())
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mdlwr, err := New(ctx, next, commonMetrics, llmMetrics)
	assert.Nil(t, err)

	reqCtx := &middlewares.RequestContext{
		CreatedAt:    time.Now(),
		IsAuthorized: true,
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req = req.WithContext(context.WithValue(req.Context(), middlewares.CtxRequestContext, reqCtx))

	rec := httptest.NewRecorder()
	mdlwr.ServeHTTP(rec, req)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	dp := findSumDataPoint(t, &rm, "req.total")

	stateVal, ok := dp.Attributes.Value("state")
	assert.True(t, ok)
	assert.Equal(t, "ALLOWED", stateVal.AsString())

	_, ok = dp.Attributes.Value("reason")
	assert.False(t, ok)
}

func TestMCPAttributes(t *testing.T) {

	tsts := []struct {
		method   string
		version  string
		versions []string
		outMethd string
		outVer   string
	}{
		{"tools/call", "2026-07-28", nil, "tools/call", "2026-07-28"},
		{"acme/custom", "2026-07-28", nil, "OTHER", "2026-07-28"},
		{"", "", nil, "UNKNOWN", "UNSET"},
		{"tools/call", "9999-12-31", nil, "tools/call", "OTHER"},
		{"tools/call", "9999-12-31", []string{"9999-12-31"}, "tools/call", "9999-12-31"},
	}

	for _, tst := range tsts {
		svc := newTestSvc()
		svc.Spec.Mode = corev1.Service_Spec_MCP

		reqCtx := &middlewares.RequestContext{
			CreatedAt: time.Now(),
			Service:   svc,
			ServiceConfig: &corev1.Service_Spec_Config{
				Type: &corev1.Service_Spec_Config_Mcp{
					Mcp: &corev1.Service_Spec_Config_MCP{
						Protocol: &corev1.Service_Spec_Config_MCP_Protocol{
							Versions: tst.versions,
						},
					},
				},
			},
			MCP: &httputils.MCPRequest{
				Method:          tst.method,
				ProtocolVersion: tst.version,
			},
		}

		assert.Equal(t, tst.outMethd, getMCPMethod(reqCtx), tst.method)
		assert.Equal(t, tst.outVer, getMCPProtocolVersion(reqCtx), tst.version)
	}
}

func newGRPCTestSvc() *corev1.Service {
	svc := newTestSvc()
	svc.Spec.Mode = corev1.Service_Spec_GRPC
	return svc
}

func newK8sTestSvc() *corev1.Service {
	svc := newTestSvc()
	svc.Spec.Mode = corev1.Service_Spec_KUBERNETES
	return svc
}

func newAuthorizedReqCtx(svc *corev1.Service) *middlewares.RequestContext {
	return &middlewares.RequestContext{
		CreatedAt:    time.Now(),
		Service:      svc,
		IsAuthorized: true,
	}
}

func TestServeHTTPBytesAndTTFB(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("0123456789"))
	})

	svc := newTestSvc()
	mdlwr := newTestMiddleware(t, svc, next)

	req := newTestReq(t, http.MethodPost, "http://localhost/",
		strings.NewReader("abcd"), newAuthorizedReqCtx(svc))

	mdlwr.ServeHTTP(httptest.NewRecorder(), req)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	sentDP := findSumDataPoint(t, &rm, "req.bytes_sent")
	assert.Equal(t, int64(10), sentDP.Value)

	receivedDP := findSumDataPoint(t, &rm, "req.bytes_received")
	assert.Equal(t, int64(4), receivedDP.Value)

	streamVal, ok := sentDP.Attributes.Value("req.http.stream")
	assert.True(t, ok)
	assert.Equal(t, "NONE", streamVal.AsString())

	_, ok = sentDP.Attributes.Value("req.http.method")
	assert.False(t, ok)

	ttfbDP := findHistogramDataPoint(t, &rm, "req.ttfb")
	assert.Equal(t, uint64(1), ttfbDP.Count)
}

func TestServeHTTPResponseDiscoveredSSE(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data: hi\n\n"))
	})

	svc := newTestSvc()
	mdlwr := newTestMiddleware(t, svc, next)

	req := newTestReq(t, http.MethodPost, "http://localhost/v1/chat/completions",
		strings.NewReader(`{"stream":true}`), newAuthorizedReqCtx(svc))

	mdlwr.ServeHTTP(httptest.NewRecorder(), req)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	activeDPs := findSumDataPoints(t, &rm, "session.active")
	assert.Len(t, activeDPs, 1)
	assert.Equal(t, int64(0), activeDPs[0].Value)

	durationDP := findHistogramDataPoint(t, &rm, "session.duration")
	assert.Equal(t, uint64(1), durationDP.Count)

	streamVal, ok := durationDP.Attributes.Value("req.http.stream")
	assert.True(t, ok)
	assert.Equal(t, "SSE", streamVal.AsString())

	totalDP := findSumDataPoint(t, &rm, "req.total")
	reqStreamVal, ok := totalDP.Attributes.Value("req.http.stream")
	assert.True(t, ok)
	assert.Equal(t, "SSE", reqStreamVal.AsString())
}

func TestServeHTTPNonStreamHasNoSession(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	svc := newTestSvc()
	mdlwr := newTestMiddleware(t, svc, next)

	mdlwr.ServeHTTP(httptest.NewRecorder(),
		newTestReq(t, http.MethodGet, "http://localhost/", nil, newAuthorizedReqCtx(svc)))

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	assert.False(t, hasMetric(&rm, "session.active"))
	assert.False(t, hasMetric(&rm, "session.duration"))
}

func TestServeHTTPPanicKeepsActiveBalanced(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		panic(http.ErrAbortHandler)
	})

	svc := newTestSvc()
	mdlwr := newTestMiddleware(t, svc, next)

	req := newTestReq(t, http.MethodGet, "http://localhost/", nil, newAuthorizedReqCtx(svc))

	assert.Panics(t, func() {
		mdlwr.ServeHTTP(httptest.NewRecorder(), req)
	})

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	activeDPs := findSumDataPoints(t, &rm, "req.active")
	assert.Len(t, activeDPs, 1)
	assert.Equal(t, int64(0), activeDPs[0].Value)

	sessionDPs := findSumDataPoints(t, &rm, "session.active")
	assert.Len(t, sessionDPs, 1)
	assert.Equal(t, int64(0), sessionDPs[0].Value)
}

func TestGRPCStatusAttributes(t *testing.T) {

	tsts := []struct {
		name      string
		header    string
		value     string
		outStatus string
		outClass  string
	}{
		{"trailers-only", "Grpc-Status", "0", "OK", "OK"},
		{"late trailer", http.TrailerPrefix + "Grpc-Status", "5", "NOT_FOUND", "CLIENT_ERROR"},
		{"server error", "Grpc-Status", "14", "UNAVAILABLE", "SERVER_ERROR"},
		{"unknown code", "Grpc-Status", "99", "OTHER", "OTHER"},
		{"absent", "", "", "UNSET", "UNSET"},
	}

	for _, tst := range tsts {
		t.Run(tst.name, func(t *testing.T) {
			ctx := context.Background()
			reader := setTestMeterProvider(t)

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tst.header != "" {
					w.Header().Set(tst.header, tst.value)
				}
				w.WriteHeader(http.StatusOK)
			})

			svc := newGRPCTestSvc()
			mdlwr := newTestMiddleware(t, svc, next)

			reqCtx := newAuthorizedReqCtx(svc)
			reqCtx.DownstreamInfo = &corev1.RequestContext{
				Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Grpc{
						Grpc: &corev1.RequestContext_Request_GRPC{
							ServiceFullName: "acme.v1.Greeter",
							Method:          "SayHello",
						},
					},
				},
			}

			mdlwr.ServeHTTP(httptest.NewRecorder(),
				newTestReq(t, http.MethodPost,
					"http://localhost/acme.v1.Greeter/SayHello", nil, reqCtx))

			var rm metricdata.ResourceMetrics
			assert.Nil(t, reader.Collect(ctx, &rm))

			dp := findSumDataPoint(t, &rm, "req.total")

			statusVal, ok := dp.Attributes.Value("req.grpc.status")
			assert.True(t, ok)
			assert.Equal(t, tst.outStatus, statusVal.AsString())

			classVal, ok := dp.Attributes.Value("req.grpc.status_class")
			assert.True(t, ok)
			assert.Equal(t, tst.outClass, classVal.AsString())

			svcVal, ok := dp.Attributes.Value("req.grpc.service_full_name")
			assert.True(t, ok)
			assert.Equal(t, "acme.v1.Greeter", svcVal.AsString())

			methodVal, ok := dp.Attributes.Value("req.grpc.method")
			assert.True(t, ok)
			assert.Equal(t, "SayHello", methodVal.AsString())
		})
	}
}

func TestGRPCRouteIsBoundedAsPair(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	svc := newGRPCTestSvc()
	mdlwr := newTestMiddleware(t, svc, next)

	for i := 0; i < maxGRPCRouteValues*4; i++ {
		reqCtx := newAuthorizedReqCtx(svc)
		reqCtx.DownstreamInfo = &corev1.RequestContext{
			Request: &corev1.RequestContext_Request{
				Type: &corev1.RequestContext_Request_Grpc{
					Grpc: &corev1.RequestContext_Request_GRPC{
						ServiceFullName: fmt.Sprintf("acme.v1.Svc%d", i%64),
						Method:          fmt.Sprintf("Method%d", i/64),
					},
				},
			},
		}

		mdlwr.ServeHTTP(httptest.NewRecorder(),
			newTestReq(t, http.MethodPost, "http://localhost/acme.v1.Svc/Method", nil, reqCtx))
	}

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	dps := findSumDataPoints(t, &rm, "req.total")
	assert.LessOrEqual(t, len(dps), maxGRPCRouteValues+1)
}

func TestGetStreamKind(t *testing.T) {

	tsts := []struct {
		name    string
		svc     *corev1.Service
		target  string
		headers map[string]string
		out     streamKind
	}{
		{"plain", newTestSvc(), "http://localhost/", nil, streamKindNone},
		{
			"websocket", newTestSvc(), "http://localhost/",
			map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"},
			streamKindWebSocket,
		},
		{
			"sse accept", newTestSvc(), "http://localhost/",
			map[string]string{"Accept": "TEXT/EVENT-STREAM"}, streamKindSSE,
		},
		{
			"k8s exec over websocket", newK8sTestSvc(),
			"http://localhost/api/v1/namespaces/ns1/pods/p1/exec",
			map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"},
			streamKindK8sExec,
		},
		{
			"k8s portforward", newK8sTestSvc(),
			"http://localhost/api/v1/namespaces/ns1/pods/p1/portforward", nil,
			streamKindK8sPortForward,
		},
		{
			"k8s log without follow", newK8sTestSvc(),
			"http://localhost/api/v1/namespaces/ns1/pods/p1/log", nil, streamKindNone,
		},
		{
			"k8s log with follow", newK8sTestSvc(),
			"http://localhost/api/v1/namespaces/ns1/pods/p1/log?follow=true", nil,
			streamKindK8sLog,
		},
		{
			"k8s watch", newK8sTestSvc(),
			"http://localhost/api/v1/namespaces/ns1/pods?watch=1", nil,
			streamKindK8sWatch,
		},
	}

	for _, tst := range tsts {
		t.Run(tst.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tst.target, nil)
			for k, v := range tst.headers {
				req.Header.Set(k, v)
			}

			reqCtx := &middlewares.RequestContext{Service: tst.svc}
			assert.Equal(t, tst.out, getStreamKind(req, reqCtx))
		})
	}
}
