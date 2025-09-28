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
