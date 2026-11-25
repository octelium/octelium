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
	"github.com/octelium/octelium/pkg/common/pbutils"
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

func TestGetKeyEval(t *testing.T) {
	ctx := context.Background()
	celEngine, err := celengine.New(ctx, nil)
	assert.Nil(t, err)
	m := &middleware{celEngine: celEngine}

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "tst.default", Uid: "rl-svc-uid", ResourceVersion: "rl-svc-rv"},
	}
	usr := &corev1.User{
		Metadata: &metav1.Metadata{Name: "usr", Uid: "rl-usr-uid", ResourceVersion: "rl-usr-rv"},
	}
	sess := &corev1.Session{
		Metadata: &metav1.Metadata{Name: "sess", Uid: "rl-sess-uid", ResourceVersion: "rl-sess-rv"},
	}
	request := &corev1.RequestContext_Request{
		Type: &corev1.RequestContext_Request_Http{
			Http: &corev1.RequestContext_Request_HTTP{
				Path:    "/v1",
				Headers: map[string]string{"x-tenant": "tenant"},
			},
		},
	}

	authenticated := func() *middlewares.RequestContext {
		ret := &middlewares.RequestContext{
			DownstreamInfo: &corev1.RequestContext{Request: request, Service: svc, User: usr, Session: sess},
		}
		ret.SetReqCtxMap()
		return ret
	}
	preAuth := func() *middlewares.RequestContext {
		downstreamInfo := &corev1.RequestContext{Request: request, Service: svc}
		return &middlewares.RequestContext{
			DownstreamInfo: downstreamInfo,
			ReqCtxMap:      pbutils.MustConvertToMap(downstreamInfo),
		}
	}
	anonymous := func() *middlewares.RequestContext {
		return &middlewares.RequestContext{
			DownstreamInfo: &corev1.RequestContext{Request: request, Service: svc},
		}
	}
	noDownstreamInfo := func() *middlewares.RequestContext {
		return &middlewares.RequestContext{}
	}

	evalKey := func(eval string) *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key {
		return &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_Eval{
				Eval: eval,
			},
		}
	}

	for i, tc := range []struct {
		reqCtx func() *middlewares.RequestContext
		key    *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key
		want   string
	}{
		{authenticated, nil, "rl-sess-uid"},
		{authenticated, evalKey(`ctx.user.metadata.name`), "usr"},
		{authenticated, evalKey(`ctx.request.http.headers["x-tenant"] + ":" + ctx.session.metadata.name`), "tenant:sess"},
		{authenticated, evalKey(`ctx.service.metadata.uid`), "rl-svc-uid"},
		{authenticated, evalKey(`"const"`), "const"},
		{authenticated, evalKey(`""`), "rl:rl-sess-uid"},
		{authenticated, evalKey(`ctx.missing.field`), "rl:rl-sess-uid"},
		{authenticated, evalKey(`1`), "rl:rl-sess-uid"},
		{authenticated, &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_PerUser{PerUser: true},
		}, "rl-usr-uid"},
		{authenticated, &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_PerSession{PerSession: true},
		}, "rl:rl-sess-uid"},
		{preAuth, evalKey(`ctx.request.http.headers["x-tenant"]`), "tenant"},
		{preAuth, evalKey(`ctx.user.metadata.name`), "rl:"},
		{anonymous, evalKey(`ctx.request.http.headers["x-tenant"] + ":" + ctx.service.metadata.name`), "tenant:tst.default"},
		{anonymous, evalKey(`ctx.session.metadata.uid`), "rl:"},
		{noDownstreamInfo, evalKey(`"const"`), "const"},
		{noDownstreamInfo, evalKey(`ctx.request.http.path`), "rl:"},
	} {
		reqCtx := tc.reqCtx()
		assert.Equal(t, tc.want, m.getKey(ctx, "rl", &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit{
			Key: tc.key,
		}, reqCtx), "%d", i)
		if tc.key.GetEval() == "" {
			assert.Nil(t, reqCtx.ReqCtxMap, "%d", i)
		}
	}
}
