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

package retry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestMiddleware(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		})
		mdlwr, err := New(ctx, next)
		assert.Nil(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, http.StatusOK, rw.Code)
	}

	{

		respBody := utilrand.GetRandomString(128)
		now := time.Now()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			zap.L().Debug("Since====", zap.Int64("dur", time.Since(now).Milliseconds()))
			if time.Since(now) < 3*time.Second {
				w.WriteHeader(http.StatusBadGateway)
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(respBody))
			}
		})
		mdlwr, err := New(ctx, next)
		assert.Nil(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Retry: &corev1.Service_Spec_Config_HTTP_Retry{},
						},
					},
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		resp := rw.Result()
		body, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)

		assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
		assert.Equal(t, string(body), respBody)
	}

	{

		respBody := utilrand.GetRandomString(128)
		now := time.Now()
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			zap.L().Debug("Since====", zap.Int64("dur", time.Since(now).Milliseconds()))
			if time.Since(now) < 6*time.Second {
				w.WriteHeader(http.StatusBadGateway)
			} else {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(respBody))
			}
		})
		mdlwr, err := New(ctx, next)
		assert.Nil(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Retry: &corev1.Service_Spec_Config_HTTP_Retry{
								MaxElapsedTime: &metav1.Duration{
									Type: &metav1.Duration_Milliseconds{
										Milliseconds: 2000,
									},
								},
							},
						},
					},
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, http.StatusBadGateway, rw.Result().StatusCode)
	}

}

func newRetryReqCtx(svc *corev1.Service) *middlewares.RequestContext {
	return &middlewares.RequestContext{
		CreatedAt: time.Now(),
		Service:   svc,
		ServiceConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					Retry: &corev1.Service_Spec_Config_HTTP_Retry{
						MaxRetries: 4,
						InitialInterval: &metav1.Duration{
							Type: &metav1.Duration_Milliseconds{
								Milliseconds: 1,
							},
						},
					},
				},
			},
		},
	}
}

func serveRetry(t *testing.T, reqCtx *middlewares.RequestContext,
	req *http.Request) (int, int) {
	t.Helper()

	ctx := context.Background()

	var attempts int
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadGateway)
	})

	mdlwr, err := New(ctx, next)
	assert.Nil(t, err)

	req = req.WithContext(context.WithValue(context.Background(),
		middlewares.CtxRequestContext, reqCtx))

	rw := httptest.NewRecorder()
	mdlwr.ServeHTTP(rw, req)

	return attempts, rw.Result().StatusCode
}

func TestNonIdempotentMethodsAreNotRetried(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodConnect} {
		req := httptest.NewRequest(method, "http://localhost/v1",
			strings.NewReader("body"))

		attempts, statusCode := serveRetry(t, newRetryReqCtx(nil), req)

		assert.Equal(t, 1, attempts, method)
		assert.Equal(t, http.StatusBadGateway, statusCode, method)
	}
}

func TestIdempotentMethodsAreRetried(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead,
		http.MethodOptions, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "http://localhost/v1",
			strings.NewReader("body"))

		attempts, statusCode := serveRetry(t, newRetryReqCtx(nil), req)

		assert.Equal(t, 4, attempts, method)
		assert.Equal(t, http.StatusBadGateway, statusCode, method)
	}
}

func TestUpgradeAndGRPCAreNotRetried(t *testing.T) {
	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")

		attempts, _ := serveRetry(t, newRetryReqCtx(nil), req)
		assert.Equal(t, 1, attempts)
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
		req.Header.Set("Content-Type", "application/grpc+proto")

		attempts, _ := serveRetry(t, newRetryReqCtx(nil), req)
		assert.Equal(t, 1, attempts)
	}

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{Name: "tst.default"},
			Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_GRPC},
			Status:   &corev1.Service_Status{},
		}

		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)

		attempts, _ := serveRetry(t, newRetryReqCtx(svc), req)
		assert.Equal(t, 1, attempts)
	}
}

func TestOversizedAndStreamingBodiesAreNotRetried(t *testing.T) {
	{
		req := httptest.NewRequest(http.MethodPut, "http://localhost/v1",
			strings.NewReader(strings.Repeat("a", 16)))
		req.ContentLength = -1

		attempts, _ := serveRetry(t, newRetryReqCtx(nil), req)
		assert.Equal(t, 1, attempts)
	}

	{
		reqCtx := newRetryReqCtx(nil)
		reqCtx.ServiceConfig.GetHttp().Body = &corev1.Service_Spec_Config_HTTP_Body{
			MaxRequestSize: 8,
		}

		req := httptest.NewRequest(http.MethodPut, "http://localhost/v1",
			strings.NewReader(strings.Repeat("a", 16)))

		attempts, _ := serveRetry(t, reqCtx, req)
		assert.Equal(t, 1, attempts)
	}

	{
		reqCtx := newRetryReqCtx(nil)
		reqCtx.ServiceConfig.GetHttp().Body = &corev1.Service_Spec_Config_HTTP_Body{
			MaxRequestSize: 64,
		}

		req := httptest.NewRequest(http.MethodPut, "http://localhost/v1",
			strings.NewReader(strings.Repeat("a", 16)))

		attempts, _ := serveRetry(t, reqCtx, req)
		assert.Equal(t, 4, attempts)
	}
}

func TestBufferedBodyIsReusedAndReplayed(t *testing.T) {
	ctx := context.Background()

	reqCtx := newRetryReqCtx(nil)
	reqCtx.Body = []byte("buffered-body")

	var bodies []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.Nil(t, err)
		bodies = append(bodies, string(body))
		w.WriteHeader(http.StatusBadGateway)
	})

	mdlwr, err := New(ctx, next)
	assert.Nil(t, err)

	req := httptest.NewRequest(http.MethodPut, "http://localhost/v1",
		strings.NewReader("stale-body"))
	req = req.WithContext(context.WithValue(context.Background(),
		middlewares.CtxRequestContext, reqCtx))

	rw := httptest.NewRecorder()
	mdlwr.ServeHTTP(rw, req)

	assert.Equal(t, []string{
		"buffered-body", "buffered-body", "buffered-body", "buffered-body",
	}, bodies)
}
