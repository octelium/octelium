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

package path

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	var path string
	var requestURI string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		requestURI = r.RequestURI
	})

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	mdlwr, err := New(ctx, next, celEngine, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),

				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{
										Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{
											RemovePrefix: "/prefix",
										},
									},
								},
							},
						},
					},
				},
			}))
		mdlwr.ServeHTTP(nil, req)

		assert.Equal(t, "/v1", path)
		assert.Equal(t, "/v1", requestURI)
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),

				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{

							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{
										Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{
											AddPrefix: "/add01",
										},
									},
								},
							},
						},
					},
				},
			}))
		mdlwr.ServeHTTP(nil, req)

		assert.Equal(t, "/add01/prefix/v1", path)
		assert.Equal(t, "/add01/prefix/v1", requestURI)
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),

				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{
										Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{

											RemovePrefix: "/v1",
											AddPrefix:    "/v2",
										},
									},
								},
							},
						},
					},
				},
			}))
		mdlwr.ServeHTTP(nil, req)

		assert.Equal(t, "/v2/path", path)
		assert.Equal(t, "/v2/path", requestURI)
	}
}
