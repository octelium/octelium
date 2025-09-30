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

package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
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

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	mdlwr, err := New(ctx, next, celEngine, tst.C.OcteliumC, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	{
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
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_{
								RateLimit: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit{

									Limit: 2,
									Window: &metav1.Duration{
										Type: &metav1.Duration_Seconds{
											Seconds: 3,
										},
									},
								},
							},
						},
					},
				},
			},
		}

		{
			// user-1
			usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)

			req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
			req = req.WithContext(context.WithValue(context.Background(),
				middlewares.CtxRequestContext,
				&middlewares.RequestContext{
					CreatedAt:     time.Now(),
					ServiceConfig: svcCfg,
					DownstreamInfo: &corev1.RequestContext{
						Session: usrT.Session,
						User:    usrT.Usr,
					},
				}))

			{
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
			}

			{
				time.Sleep(1 * time.Millisecond)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
			}

			{
				time.Sleep(1 * time.Millisecond)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				assert.Equal(t, http.StatusTooManyRequests, rw.Result().StatusCode)
			}
		}

		{
			// user-2
			usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)

			req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
			req = req.WithContext(context.WithValue(context.Background(),
				middlewares.CtxRequestContext,
				&middlewares.RequestContext{
					CreatedAt:     time.Now(),
					ServiceConfig: svcCfg,
					DownstreamInfo: &corev1.RequestContext{
						Session: usrT.Session,
						User:    usrT.Usr,
					},
				}))
			{
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
			}

			{
				time.Sleep(1 * time.Millisecond)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
			}

			{
				time.Sleep(1 * time.Millisecond)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				assert.Equal(t, http.StatusTooManyRequests, rw.Result().StatusCode)
			}
		}
	}

	{
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
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_{
								RateLimit: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit{

									Limit:      2,
									StatusCode: 407,
									Key: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_Eval{
											Eval: `"some-global-key"`,
										},
									},
									Window: &metav1.Duration{
										Type: &metav1.Duration_Seconds{
											Seconds: 3,
										},
									},
								},
							},
						},
					},
				},
			},
		}

		{
			// user-1
			usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)

			req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
			req = req.WithContext(context.WithValue(context.Background(),
				middlewares.CtxRequestContext,
				&middlewares.RequestContext{
					CreatedAt:     time.Now(),
					ServiceConfig: svcCfg,
					DownstreamInfo: &corev1.RequestContext{
						Session: usrT.Session,
						User:    usrT.Usr,
					},
				}))

			{
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
			}

			{
				time.Sleep(1 * time.Millisecond)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
			}

			{
				time.Sleep(1 * time.Millisecond)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				assert.Equal(t, 407, rw.Result().StatusCode)
			}
		}

		{
			// user-2
			usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)

			req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
			req = req.WithContext(context.WithValue(context.Background(),
				middlewares.CtxRequestContext,
				&middlewares.RequestContext{
					CreatedAt:     time.Now(),
					ServiceConfig: svcCfg,
					DownstreamInfo: &corev1.RequestContext{
						Session: usrT.Session,
						User:    usrT.Usr,
					},
				}))

			{
				time.Sleep(1 * time.Millisecond)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				assert.Equal(t, 407, rw.Result().StatusCode)
			}
		}

	}

}
