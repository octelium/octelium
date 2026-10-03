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

package auth

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/cluster/vigil/vigil/vigilutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
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

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},
			},
			Mode: corev1.Service_Spec_HTTP,
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svc)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})

	mdlwr, err := New(ctx, next, tst.C.OcteliumC, octovigilC, "example.com")
	assert.Nil(t, err)

	{
		reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))

		usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		jsn, err := pbutils.MarshalJSON(usrT.Usr, false)
		assert.Nil(t, err)
		req := httptest.NewRequest(http.MethodGet, reqPath, bytes.NewBuffer(jsn))

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service:   svc,
				DownstreamRequest: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "127.0.0.1",
						Port:    12345,
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{},
						},
					},
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)
		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		assert.Equal(t, http.StatusUnauthorized, rw.Code)
		assert.False(t, reqCtx.IsAuthorized)
		assert.False(t, reqCtx.IsAuthenticated)
	}

	{
		reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))

		usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		jsn, err := pbutils.MarshalJSON(usrT.Usr, false)
		assert.Nil(t, err)
		req := httptest.NewRequest(http.MethodGet, reqPath, bytes.NewBuffer(jsn))

		svc.Spec.IsAnonymous = true
		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service:   svc,
				DownstreamInfo: &corev1.RequestContext{
					Service: svc,
				},
				DownstreamRequest: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "127.0.0.1",
						Port:    12345,
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{},
						},
					},
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)
		// reqCtx := middlewares.GetCtxRequestContext(req.Context())
		assert.Equal(t, http.StatusOK, rw.Code)
		svc.Spec.IsAnonymous = false
	}

}

func TestAnonymous(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic:    true,
			IsAnonymous: true,
			Port:        uint32(tests.GetPort()),
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},
			},
			Mode: corev1.Service_Spec_HTTP,
		},
	})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svc)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})

	mdlwr, err := New(ctx, next, tst.C.OcteliumC, octovigilC, "example.com")
	assert.Nil(t, err)

	{
		reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))

		usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		jsn, err := pbutils.MarshalJSON(usrT.Usr, false)
		assert.Nil(t, err)
		req := httptest.NewRequest(http.MethodGet, reqPath, bytes.NewBuffer(jsn))

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service:   svc,
				DownstreamRequest: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "127.0.0.1",
						Port:    12345,
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{},
						},
					},
				},
				DownstreamInfo: &corev1.RequestContext{
					Service: svc,
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)
		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.True(t, reqCtx.IsAuthorized)
		assert.False(t, reqCtx.IsAuthenticated)
	}

	svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
		EnableAnonymous: true,
	}

	svc, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svc)
	assert.Nil(t, err)
	vCache.SetService(svc)

	{
		reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))

		req := httptest.NewRequest(http.MethodGet, reqPath, nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service:   svc,
				DownstreamRequest: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "127.0.0.1",
						Port:    12345,
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{},
						},
					},
				},
				DownstreamInfo: &corev1.RequestContext{
					Service: svc,
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)
		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.False(t, reqCtx.IsAuthorized)
		assert.False(t, reqCtx.IsAuthenticated)
	}

	reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))
	svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
		EnableAnonymous: true,
		InlinePolicies: []*corev1.InlinePolicy{
			{
				Spec: &corev1.Policy_Spec{
					Rules: []*corev1.Policy_Spec_Rule{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: fmt.Sprintf(`ctx.request.http.path == "%s"`, reqPath),
								},
							},
							Effect: corev1.Policy_Spec_Rule_ALLOW,
						},
					},
				},
			},
		},
	}

	svc, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svc)
	assert.Nil(t, err)
	vCache.SetService(svc)

	{

		req := httptest.NewRequest(http.MethodGet, reqPath, nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service:   svc,
				DownstreamRequest: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "127.0.0.1",
						Port:    12345,
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{
								Path: reqPath,
							},
						},
					},
				},
				DownstreamInfo: &corev1.RequestContext{
					Service: svc,
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)
		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.True(t, reqCtx.IsAuthorized)
		assert.False(t, reqCtx.IsAuthenticated)
	}

	{
		reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))

		req := httptest.NewRequest(http.MethodGet, reqPath, nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service:   svc,
				DownstreamRequest: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "127.0.0.1",
						Port:    12345,
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{
								Path: reqPath,
							},
						},
					},
				},
				DownstreamInfo: &corev1.RequestContext{
					Service: svc,
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)
		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.False(t, reqCtx.IsAuthorized)
		assert.False(t, reqCtx.IsAuthenticated)
	}
}

func TestAnonymousDynamicConfig(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic:    true,
			IsAnonymous: true,
			Port:        uint32(tests.GetPort()),
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://default.example.com",
					},
				},
			},
			DynamicConfig: &corev1.Service_Spec_DynamicConfig{
				Configs: []*corev1.Service_Spec_Config{
					{
						Name: "cfg1",
						Upstream: &corev1.Service_Spec_Config_Upstream{
							Type: &corev1.Service_Spec_Config_Upstream_Url{
								Url: "https://cfg1.example.com",
							},
						},
					},
				},
				Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
					{
						Condition: &corev1.Condition{
							Type: &corev1.Condition_Match{
								Match: `ctx.request.http.path == "/cfg1"`,
							},
						},
						Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{
							ConfigName: "cfg1",
						},
					},
					{
						Condition: &corev1.Condition{
							Type: &corev1.Condition_Match{
								Match: `ctx.request.http.path == "/eval"`,
							},
						},
						Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{
							Eval: `{"upstream": {"url": "https://eval.example.com"}}`,
						},
					},
					{
						Condition: &corev1.Condition{
							Type: &corev1.Condition_Match{
								Match: `ctx.request.http.path == "/opa"`,
							},
						},
						Type: &corev1.Service_Spec_DynamicConfig_Rule_Opa{
							Opa: `
package octelium.eval

result := {
	"upstream": {
		"url": "https://opa.example.com"
	}
}`,
						},
					},
				},
			},
			Mode: corev1.Service_Spec_HTTP,
		},
	})
	assert.Nil(t, err, "%+v", err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svc)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	lbManager := loadbalancer.NewLbManager(fakeC.OcteliumC, vCache)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})

	mdlwr, err := New(ctx, next, tst.C.OcteliumC, octovigilC, "example.com")
	assert.Nil(t, err)

	tstCases := []struct {
		path string
		host string
	}{
		{
			path: "/default",
			host: "default.example.com",
		},
		{
			path: "/cfg1",
			host: "cfg1.example.com",
		},
		{
			path: "/eval",
			host: "eval.example.com",
		},
		{
			path: "/opa",
			host: "opa.example.com",
		},
	}

	for _, tstCase := range tstCases {
		reqInfo := &corev1.RequestContext_Request{
			Type: &corev1.RequestContext_Request_Http{
				Http: &corev1.RequestContext_Request_HTTP{
					Path: tstCase.path,
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, tstCase.path, nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				ServiceConfig: svc.Spec.Config,
				DownstreamRequest: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "127.0.0.1",
						Port:    12345,
					},
					Request: reqInfo,
				},
				DownstreamInfo: &corev1.RequestContext{
					Service: svc,
					Request: reqInfo,
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)
		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		assert.Equal(t, http.StatusOK, rw.Code)
		assert.True(t, reqCtx.IsAuthorized)

		assert.Equal(t, fmt.Sprintf("https://%s", tstCase.host), reqCtx.ServiceConfig.Upstream.GetUrl())
		assert.True(t, pbutils.IsEqual(reqCtx.ServiceConfig,
			vigilutils.GetServiceConfig(ctx, reqCtx.AuthResponse)), tstCase.path)

		upstream, err := lbManager.GetUpstream(ctx, reqCtx.AuthResponse)
		assert.Nil(t, err)
		assert.Equal(t, tstCase.host, upstream.URL.Host, tstCase.path)
	}
}
