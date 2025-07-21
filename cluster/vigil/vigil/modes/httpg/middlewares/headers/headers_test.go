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

package headers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Response", "octelium")
	})
	mdlwr, err := New(ctx, next, secretMan)
	assert.Nil(t, err)

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec:   &corev1.Service_Spec{},
			Status: &corev1.Service_Status{},
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
			}))
		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)
		assert.Equal(t, "octelium", rw.Header().Get("X-Response"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", utilrand.GetRandomString(32)))

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec:   &corev1.Service_Spec{},
			Status: &corev1.Service_Status{},
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
			}))
		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, "", req.Header.Get("Authorization"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		req.Header.Set("X-Del-1", fmt.Sprintf("Bearer %s", utilrand.GetRandomString(32)))

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								AddRequestHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
									{
										Key:   "X-Set-1",
										Value: utilrand.GetRandomString(32),
									},
									{
										Key:   "X-Set-2",
										Value: utilrand.GetRandomString(32),
									},
								},

								RemoveRequestHeaders: []string{
									"X-Del-1",
								},

								AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
									{
										Key:   "X-Set-3",
										Value: utilrand.GetRandomString(32),
									},
									{
										Key:   "X-Set-4",
										Value: utilrand.GetRandomString(32),
									},
								},

								RemoveResponseHeaders: []string{
									"X-Response",
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, "", req.Header.Get("X-Del-1"))

		assert.Equal(t, svc.Spec.Config.GetHttp().Header.AddRequestHeaders[0].Value, req.Header.Get("X-Set-1"))
		assert.Equal(t, svc.Spec.Config.GetHttp().Header.AddRequestHeaders[1].Value, req.Header.Get("X-Set-2"))
		assert.Equal(t, svc.Spec.Config.GetHttp().Header.AddResponseHeaders[0].Value, rw.Header().Get("X-Set-3"))
		assert.Equal(t, svc.Spec.Config.GetHttp().Header.AddResponseHeaders[1].Value, rw.Header().Get("X-Set-4"))
		assert.Equal(t, "", rw.Header().Get("X-Response"))
	}
}
