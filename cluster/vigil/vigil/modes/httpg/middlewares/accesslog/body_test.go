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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/protobuf/types/known/structpb"
)

type tstAccessLogProcessor struct {
	mu      sync.Mutex
	records []*corev1.AccessLog
	errs    []error
}

func (p *tstAccessLogProcessor) Enabled(ctx context.Context, param sdklog.EnabledParameters) bool {
	return true
}

func (p *tstAccessLogProcessor) OnEmit(ctx context.Context, record *sdklog.Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	logE := &corev1.AccessLog{}
	if err := pbutils.UnmarshalJSONStrict([]byte(record.Body().String()), logE); err != nil {
		p.errs = append(p.errs, err)
		return err
	}
	p.records = append(p.records, logE)
	return nil
}

func (p *tstAccessLogProcessor) Shutdown(ctx context.Context) error {
	return nil
}

func (p *tstAccessLogProcessor) ForceFlush(ctx context.Context) error {
	return nil
}

func (p *tstAccessLogProcessor) getRecords(t *testing.T) []*corev1.AccessLog {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()

	assert.Empty(t, p.errs)
	ret := p.records
	p.records = nil
	p.errs = nil
	return ret
}

func newAccessLogRecorder(t *testing.T) *tstAccessLogProcessor {
	t.Helper()
	previous := otel.GetLoggerProvider()
	processor := &tstAccessLogProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	otel.SetLoggerProvider(provider)
	t.Cleanup(func() {
		otel.SetLoggerProvider(previous)
		assert.Nil(t, provider.Shutdown(context.Background()))
	})
	return processor
}

func newHTTPVisibilityConfig(cfg *corev1.Service_Spec_Config_HTTP_Visibility) *corev1.Service_Spec_Config {
	return &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Http{
			Http: &corev1.Service_Spec_Config_HTTP{
				Visibility: cfg,
			},
		},
	}
}

func getTestVisibilityConfigs() map[string]*corev1.Service_Spec_Config {
	return map[string]*corev1.Service_Spec_Config{
		"Nil":           nil,
		"Empty":         {},
		"NilVisibility": newHTTPVisibilityConfig(nil),
		"NoBody":        newHTTPVisibilityConfig(&corev1.Service_Spec_Config_HTTP_Visibility{}),
		"Body": newHTTPVisibilityConfig(&corev1.Service_Spec_Config_HTTP_Visibility{
			EnableResponseBody: true,
		}),
		"BodyMap": newHTTPVisibilityConfig(&corev1.Service_Spec_Config_HTTP_Visibility{
			EnableResponseBodyMap: true,
		}),
		"BodyAndBodyMap": newHTTPVisibilityConfig(&corev1.Service_Spec_Config_HTTP_Visibility{
			EnableResponseBody:    true,
			EnableResponseBodyMap: true,
		}),
		"RequestOnly": newHTTPVisibilityConfig(&corev1.Service_Spec_Config_HTTP_Visibility{
			EnableRequestBody:         true,
			EnableRequestBodyMap:      true,
			IncludeAllRequestHeaders:  true,
			IncludeAllResponseHeaders: true,
		}),
		"MCP": {
			Type: &corev1.Service_Spec_Config_Mcp{
				Mcp: &corev1.Service_Spec_Config_MCP{},
			},
		},
	}
}

func newTestBodyReqCtx(mode corev1.Service_Spec_Mode, cfg *corev1.Service_Spec_Config) *middlewares.RequestContext {
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "service", Uid: "service"},
		Spec:     &corev1.Service_Spec{Mode: mode, Config: cfg},
		Status:   &corev1.Service_Status{},
	}

	return &middlewares.RequestContext{
		CreatedAt:      time.Now(),
		Service:        svc,
		ServiceConfig:  cfg,
		Body:           []byte(`{"request":"body"}`),
		DownstreamInfo: &corev1.RequestContext{Service: svc},
	}
}

func getTestResponseBodies() map[string]string {
	maxJSON := fmt.Sprintf(`{"a":"%s"}`, strings.Repeat("x", maxBodyLen-8))

	return map[string]string{
		"Empty":        "",
		"JSON":         `{"a":"b","c":[1,2]}`,
		"Array":        `[1,2]`,
		"Text":         "not json",
		"MaxJSON":      maxJSON,
		"OverMaxJSON":  fmt.Sprintf(`{"a":"%s"}`, strings.Repeat("x", maxBodyLen-7)),
		"OverMaxBytes": maxJSON + "trailing",
		"Large":        utilrand.GetRandomString(100 * 1024),
	}
}

type tstResponse struct {
	body       string
	chunk      int
	statusCode int
	final      *corev1.Service_Spec_Config
}

func serveNonStreamingLog(t *testing.T, reqCtx *middlewares.RequestContext,
	resp *tstResponse) (*responseWriter, []*corev1.AccessLog, *httptest.ResponseRecorder) {
	t.Helper()
	recorder := newAccessLogRecorder(t)

	var crw *responseWriter
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		crw = w.(*responseWriter)
		reqCtx.ServiceConfig = resp.final

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.statusCode)

		_, err := w.Write(nil)
		assert.Nil(t, err)

		body := []byte(resp.body)
		for len(body) > 0 {
			n := min(resp.chunk, len(body))
			_, err := w.Write(body[:n])
			assert.Nil(t, err)
			body = body[n:]
		}
	})

	mdlwr, err := New(context.Background(), next)
	require.Nil(t, err)

	req := httptest.NewRequest(http.MethodPost, "/prefix/path", strings.NewReader(`{"request":"body"}`))
	req = req.WithContext(context.WithValue(req.Context(), middlewares.CtxRequestContext, reqCtx))
	rw := httptest.NewRecorder()
	mdlwr.ServeHTTP(rw, req)

	require.NotNil(t, crw)
	assert.Equal(t, resp.statusCode, rw.Code)
	assert.Equal(t, resp.body, rw.Body.String())

	return crw, recorder.getRecords(t), rw
}

func getTestLoggedBody(body string) string {
	if len(body) > maxBodyLen {
		return body[:maxBodyLen]
	}
	return body
}

func isTestBodyVisible(cfg *corev1.Service_Spec_Config) bool {
	visibilityCfg := cfg.GetHttp().GetVisibility()
	return visibilityCfg.GetEnableResponseBody() || visibilityCfg.GetEnableResponseBodyMap()
}

func getTestLogHTTP(logE *corev1.AccessLog) *corev1.AccessLog_Entry_Info_HTTP {
	switch {
	case logE.Entry.Info.GetGrpc() != nil:
		return logE.Entry.Info.GetGrpc().Http
	case logE.Entry.Info.GetKubernetes() != nil:
		return logE.Entry.Info.GetKubernetes().Http
	default:
		return logE.Entry.Info.GetHttp()
	}
}

func assertTestResponseLog(t *testing.T, logE *corev1.AccessLog, resp *tstResponse) {
	t.Helper()

	httpC := getTestLogHTTP(logE)
	require.NotNil(t, httpC)

	visibilityCfg := resp.final.GetHttp().GetVisibility()
	logged := getTestLoggedBody(resp.body)

	assert.Equal(t, uint32(resp.statusCode), httpC.Response.Code)
	assert.Equal(t, uint64(len(resp.body)), httpC.Response.BodyBytes)
	assert.Equal(t, "application/json", httpC.Response.ContentType)

	if visibilityCfg.GetEnableResponseBody() {
		assert.Equal(t, logged, string(httpC.Response.Body))
	} else {
		assert.Empty(t, httpC.Response.Body)
	}

	wantMap := &structpb.Struct{}
	if visibilityCfg.GetEnableResponseBodyMap() && logged != "" &&
		pbutils.UnmarshalJSON([]byte(logged), wantMap) == nil {
		require.NotNil(t, httpC.Response.BodyMap)
		assert.Equal(t, wantMap.AsMap(), httpC.Response.BodyMap.AsMap())
	} else {
		assert.Nil(t, httpC.Response.BodyMap)
	}

	if visibilityCfg.GetEnableRequestBody() {
		assert.Equal(t, `{"request":"body"}`, string(httpC.Request.Body))
	} else {
		assert.Empty(t, httpC.Request.Body)
	}
}

func TestServeNonStreamingResponseBody(t *testing.T) {
	for _, mode := range []corev1.Service_Spec_Mode{
		corev1.Service_Spec_HTTP, corev1.Service_Spec_WEB,
		corev1.Service_Spec_GRPC, corev1.Service_Spec_KUBERNETES,
	} {
		for cfgName, cfg := range getTestVisibilityConfigs() {
			for bodyName, body := range getTestResponseBodies() {
				for _, chunk := range []int{1000, 32 * 1024, 200 * 1024} {
					t.Run(fmt.Sprintf("%s/%s/%s/%d", mode, cfgName, bodyName, chunk), func(t *testing.T) {
						reqCtx := newTestBodyReqCtx(mode, cfg)
						resp := &tstResponse{body: body, chunk: chunk, statusCode: 201, final: cfg}

						_, logs, _ := serveNonStreamingLog(t, reqCtx, resp)
						require.Len(t, logs, 1)
						assertTestResponseLog(t, logs[0], resp)
					})
				}
			}
		}
	}
}

func TestServeNonStreamingResponseBodyDynamicConfig(t *testing.T) {
	bodies := getTestResponseBodies()
	for baseName, base := range getTestVisibilityConfigs() {
		for finalName, final := range getTestVisibilityConfigs() {
			for _, bodyName := range []string{"JSON", "OverMaxBytes"} {
				t.Run(fmt.Sprintf("%s/%s/%s", baseName, finalName, bodyName), func(t *testing.T) {
					reqCtx := newTestBodyReqCtx(corev1.Service_Spec_HTTP, base)
					resp := &tstResponse{body: bodies[bodyName], chunk: 1000, statusCode: 200, final: final}

					crw, logs, _ := serveNonStreamingLog(t, reqCtx, resp)
					require.Len(t, logs, 1)
					assertTestResponseLog(t, logs[0], resp)

					if isTestBodyVisible(final) {
						assert.Equal(t, getTestLoggedBody(resp.body), crw.body.String())
					} else {
						assert.Zero(t, crw.body.Len())
					}
				})
			}
		}
	}
}

func TestServeNonStreamingResponseBodyBuffer(t *testing.T) {
	for cfgName, cfg := range getTestVisibilityConfigs() {
		for bodyName, body := range getTestResponseBodies() {
			t.Run(fmt.Sprintf("%s/%s", cfgName, bodyName), func(t *testing.T) {
				reqCtx := newTestBodyReqCtx(corev1.Service_Spec_HTTP, cfg)
				resp := &tstResponse{body: body, chunk: 1000, statusCode: 200, final: cfg}

				crw, _, _ := serveNonStreamingLog(t, reqCtx, resp)
				assert.Equal(t, int64(len(body)), crw.bytesWritten)

				if isTestBodyVisible(cfg) {
					assert.Equal(t, getTestLoggedBody(body), crw.body.String())
				} else {
					assert.Zero(t, crw.body.Len())
					assert.Zero(t, crw.body.Cap())
				}
			})
		}
	}
}

func TestServeNonStreamingResponseBodyNoDownstreamInfo(t *testing.T) {
	for cfgName, cfg := range getTestVisibilityConfigs() {
		t.Run(cfgName, func(t *testing.T) {
			reqCtx := newTestBodyReqCtx(corev1.Service_Spec_HTTP, cfg)
			reqCtx.DownstreamInfo = nil
			resp := &tstResponse{body: `{"a":"b"}`, chunk: 1000, statusCode: 200, final: cfg}

			_, logs, _ := serveNonStreamingLog(t, reqCtx, resp)
			assert.Empty(t, logs)
		})
	}
}

type tstErrWriter struct {
	http.ResponseWriter
	n   int
	err error
}

func (w *tstErrWriter) Write(b []byte) (int, error) {
	if w.err != nil {
		return min(w.n, len(b)), w.err
	}
	return w.ResponseWriter.Write(b)
}

func TestResponseWriterSkipBody(t *testing.T) {
	{
		crw := newResponseWriter(httptest.NewRecorder(), streamKindNone)
		_, err := crw.Write([]byte("body"))
		assert.Nil(t, err)
		assert.Equal(t, "body", crw.body.String())
	}

	{
		calls := 0
		isLogged := false
		crw := newResponseWriter(httptest.NewRecorder(), streamKindNone)
		crw.isBodyLogged = func() bool {
			calls++
			return isLogged
		}

		_, err := crw.Write(nil)
		assert.Nil(t, err)
		_, err = crw.Write([]byte{})
		assert.Nil(t, err)
		assert.Equal(t, 0, calls)

		_, err = crw.Write([]byte("first"))
		assert.Nil(t, err)
		isLogged = true
		_, err = crw.Write([]byte("second"))
		assert.Nil(t, err)

		assert.Equal(t, 1, calls)
		assert.Zero(t, crw.body.Len())
		assert.Equal(t, int64(len("firstsecond")), crw.bytesWritten)
	}

	{
		calls := 0
		isLogged := true
		crw := newResponseWriter(httptest.NewRecorder(), streamKindNone)
		crw.isBodyLogged = func() bool {
			calls++
			return isLogged
		}

		_, err := crw.Write([]byte("first"))
		assert.Nil(t, err)
		isLogged = false
		_, err = crw.Write([]byte("second"))
		assert.Nil(t, err)

		assert.Equal(t, 1, calls)
		assert.Equal(t, "firstsecond", crw.body.String())
	}

	{
		calls := 0
		w := &tstErrWriter{ResponseWriter: httptest.NewRecorder(), err: errors.New("closed")}
		crw := newResponseWriter(w, streamKindNone)
		crw.isBodyLogged = func() bool {
			calls++
			return calls > 1
		}

		_, err := crw.Write([]byte("lost"))
		assert.NotNil(t, err)
		assert.Equal(t, 0, calls)

		w.n = 3
		n, err := crw.Write([]byte("partial"))
		assert.NotNil(t, err)
		assert.Equal(t, 3, n)
		assert.Equal(t, 1, calls)
		assert.Zero(t, crw.body.Len())
	}

	{
		w := &tstErrWriter{ResponseWriter: httptest.NewRecorder(), n: 3, err: errors.New("closed")}
		crw := newResponseWriter(w, streamKindNone)
		crw.isBodyLogged = func() bool {
			return true
		}

		n, err := crw.Write([]byte("partial"))
		assert.NotNil(t, err)
		assert.Equal(t, 3, n)
		assert.Equal(t, "par", crw.body.String())
	}

	for _, kind := range []streamKind{
		streamKindSSE, streamKindWS, streamKindK8sExec, streamKindK8sLog, streamKindGeneric,
	} {
		crw := newResponseWriter(httptest.NewRecorder(), kind)
		crw.isBodyLogged = func() bool {
			return true
		}
		_, err := crw.Write([]byte("body"))
		assert.Nil(t, err)
		assert.Zero(t, crw.body.Len())
		assert.False(t, crw.bodyResolved)
	}

	for _, kind := range []streamKind{streamKindMCP, streamKindLLM} {
		crw := newResponseWriter(httptest.NewRecorder(), kind)
		crw.isBodyLogged = func() bool {
			return false
		}
		_, err := crw.Write([]byte(`{"a":"b"}`))
		assert.Nil(t, err)
		assert.Equal(t, `{"a":"b"}`, crw.body.String())
		assert.False(t, crw.bodyResolved)
	}
}

func TestServeLLMResponseBodyNotVisible(t *testing.T) {
	recorder := newAccessLogRecorder(t)

	reqCtx := newLLMReqCtx(t, &corev1.Service_Spec_Config_LLM{})
	assert.False(t, getVisibilityConfig(reqCtx).EnableResponseBody)
	assert.False(t, getVisibilityConfig(reqCtx).EnableResponseBodyMap)

	var crw *responseWriter
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		crw = w.(*responseWriter)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(llmRespBody))
	})

	mdlwr, err := New(context.Background(), next)
	require.Nil(t, err)

	req := httptest.NewRequest(http.MethodPost,
		"http://my-llm.example.com/v1/chat/completions", strings.NewReader(llmReqBody))
	req = req.WithContext(context.WithValue(req.Context(), middlewares.CtxRequestContext, reqCtx))
	mdlwr.ServeHTTP(httptest.NewRecorder(), req)

	require.NotNil(t, crw)
	assert.Equal(t, llmRespBody, crw.body.String())

	logs := recorder.getRecords(t)
	require.Len(t, logs, 1)
	llmC := logs[0].Entry.Info.GetLlm()
	require.NotNil(t, llmC)
	assert.Equal(t, uint64(20), llmC.Usage.TotalTokens)
	assert.Empty(t, llmC.Http.Response.Body)
}
