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

package direct

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
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

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

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
			}))

		rw := httptest.NewRecorder()

		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, "", rw.Body.String())
		assert.Equal(t, http.StatusOK, rw.Code)
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		svcCfg := &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{
									MatchAny: true,
								},
							},
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_{
								Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{

									StatusCode: 407,
									Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{
											Inline: utilrand.GetRandomString(100),
										},
									},
									Headers: map[string]string{
										"X-Octelium-1": utilrand.GetRandomString(32),
									},
								},
							},
						},
					},
				},
			},
		}
		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				ServiceConfig: svcCfg,
			}))

		rw := httptest.NewRecorder()

		mdlwr.ServeHTTP(rw, req)

		body, err := io.ReadAll(rw.Body)
		assert.Nil(t, err)

		assert.Equal(t, "", rw.Body.String())
		assert.Equal(t, svcCfg.GetHttp().Plugins[0].GetDirect().StatusCode, int32(rw.Code))
		assert.Equal(t, svcCfg.GetHttp().Plugins[0].GetDirect().Body.GetInline(), string(body))
		assert.Equal(t, svcCfg.GetHttp().Plugins[0].GetDirect().Headers["X-Octelium-1"], rw.Header().Get("X-Octelium-1"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		svcCfg := &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: "2 < 1",
								},
							},

							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_{
								Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{

									StatusCode: 407,
									Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{
											Inline: utilrand.GetRandomString(100),
										},
									},
								},
							},
						},

						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: "2 > 1",
								},
							},

							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_{
								Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{

									StatusCode: 417,
									Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{
											Inline: utilrand.GetRandomString(100),
										},
									},
								},
							},
						},
					},
				},
			},
		}
		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				ServiceConfig: svcCfg,
			}))

		rw := httptest.NewRecorder()

		mdlwr.ServeHTTP(rw, req)

		body, err := io.ReadAll(rw.Body)
		assert.Nil(t, err)

		assert.Equal(t, "", rw.Body.String())
		assert.Equal(t, svcCfg.GetHttp().Plugins[1].GetDirect().StatusCode, int32(rw.Code))
		assert.Equal(t, svcCfg.GetHttp().Plugins[1].GetDirect().Body.GetInline(), string(body))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		svcCfg := &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: "2 < 1",
								},
							},
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_{
								Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{

									StatusCode: 407,
									Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{
											Inline: utilrand.GetRandomString(100),
										},
									},
								},
							},
						},

						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: "4 < 3",
								},
							},
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_{
								Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{

									StatusCode: 417,
									Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{
											Inline: utilrand.GetRandomString(100),
										},
									},
								},
							},
						},
					},
				},
			},
		}
		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				ServiceConfig: svcCfg,
			}))

		rw := httptest.NewRecorder()

		mdlwr.ServeHTTP(rw, req)

		body, err := io.ReadAll(rw.Body)
		assert.Nil(t, err)

		assert.Equal(t, "", rw.Body.String())
		assert.Equal(t, 200, (rw.Code))
		assert.Equal(t, "", string(body))
	}
}
