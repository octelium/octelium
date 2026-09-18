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

package cache

import (
	"context"
	"io"
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
	"github.com/octelium/octelium/cluster/common/vutils"
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

	hdr1Val := utilrand.GetRandomString(32)
	respBody := utilrand.GetRandomString(32)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("X-Custom-1", hdr1Val)
		w.WriteHeader(203)
		w.Write([]byte(respBody))
	})

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	mdlwr, err := New(ctx, next, celEngine, tst.C.OcteliumC,
		vutils.UUIDv4(), corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
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

		assert.Equal(t, 203, rw.Code)
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

							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_{
								Cache: &corev1.Service_Spec_Config_HTTP_Plugin_Cache{
									UseXCacheHeader: true,
									Ttl: &metav1.Duration{
										Type: &metav1.Duration_Seconds{
											Seconds: 2,
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
				resp := rw.Result()
				assert.Equal(t, resp.StatusCode, 203)

				bb, err := io.ReadAll(resp.Body)
				assert.Nil(t, err)
				resp.Body.Close()

				assert.Equal(t, respBody, string(bb))
				assert.Equal(t, hdr1Val, resp.Header.Get("X-Custom-1"))
				assert.Equal(t, "MISS", resp.Header.Get("X-Cache"))
			}

			{
				time.Sleep(1 * time.Second)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				resp := rw.Result()
				assert.Equal(t, resp.StatusCode, 203)

				bb, err := io.ReadAll(resp.Body)
				assert.Nil(t, err)
				resp.Body.Close()

				assert.Equal(t, respBody, string(bb))
				assert.Equal(t, hdr1Val, resp.Header.Get("X-Custom-1"))
				assert.Equal(t, "HIT", resp.Header.Get("X-Cache"))
			}

			{
				time.Sleep(2 * time.Second)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				resp := rw.Result()
				assert.Equal(t, resp.StatusCode, 203)

				bb, err := io.ReadAll(resp.Body)
				assert.Nil(t, err)
				resp.Body.Close()

				assert.Equal(t, respBody, string(bb))
				assert.Equal(t, hdr1Val, resp.Header.Get("X-Custom-1"))
				assert.Equal(t, "MISS", resp.Header.Get("X-Cache"))
			}

			{
				time.Sleep(1 * time.Second)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				resp := rw.Result()
				assert.Equal(t, resp.StatusCode, 203)

				bb, err := io.ReadAll(resp.Body)
				assert.Nil(t, err)
				resp.Body.Close()

				assert.Equal(t, respBody, string(bb))
				assert.Equal(t, hdr1Val, resp.Header.Get("X-Custom-1"))
				assert.Equal(t, "HIT", resp.Header.Get("X-Cache"))
			}
		}
	}

}

func TestGetNormalizedAcceptEncoding(t *testing.T) {
	for _, e := range []struct {
		arg      []string
		expected string
	}{
		{nil, ""},
		{[]string{""}, ""},
		{[]string{"gzip"}, "gzip"},
		{[]string{"GZIP"}, "gzip"},
		{[]string{" gzip , br "}, "br,gzip"},
		{[]string{"br, gzip"}, "br,gzip"},
		{[]string{"gzip, br"}, "br,gzip"},
		{[]string{"gzip", "br"}, "br,gzip"},
		{[]string{"gzip;q=0.5, br;q=1.0"}, "br,gzip"},
		{[]string{"gzip;q=0, br"}, "br"},
		{[]string{"gzip;q=0.000, br"}, "br"},
		{[]string{"gzip, gzip"}, "gzip"},
		{[]string{"*"}, "*"},
		{[]string{"identity;q=0"}, ""},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
		for _, val := range e.arg {
			req.Header.Add("Accept-Encoding", val)
		}

		assert.Equal(t, e.expected, getNormalizedAcceptEncoding(req), "%v", e.arg)
	}
}

func newCacheTestReqCtx(svcCfg *corev1.Service_Spec_Config) *middlewares.RequestContext {
	return &middlewares.RequestContext{
		CreatedAt:     time.Now(),
		ServiceConfig: svcCfg,
	}
}

func newCacheTestSvcCfg(key *corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key) *corev1.Service_Spec_Config {
	return &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Http{
			Http: &corev1.Service_Spec_Config_HTTP{
				Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
					{
						Condition: &corev1.Condition{
							Type: &corev1.Condition_MatchAny{MatchAny: true},
						},
						Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_{
							Cache: &corev1.Service_Spec_Config_HTTP_Plugin_Cache{
								UseXCacheHeader: true,
								Key:             key,
								Ttl: &metav1.Duration{
									Type: &metav1.Duration_Seconds{Seconds: 30},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestAcceptEncodingIsInTheKey(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	serve := func(mdlwr http.Handler, svcCfg *corev1.Service_Spec_Config,
		acceptEncoding string) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
		if acceptEncoding != "" {
			req.Header.Set("Accept-Encoding", acceptEncoding)
		}

		reqCtx := newCacheTestReqCtx(svcCfg)
		reqCtx.DownstreamInfo = &corev1.RequestContext{
			Session: usrT.Session,
			User:    usrT.Usr,
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext, reqCtx))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		return rw.Result()
	}

	for _, key := range []*corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key{
		nil,
		{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key_Eval{
				Eval: `"tst-key"`,
			},
		},
	} {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(200)
			w.Write([]byte("compressed"))
		})

		mdlwr, err := New(ctx, next, celEngine, tst.C.OcteliumC,
			vutils.UUIDv4(), corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
		assert.Nil(t, err)

		svcCfg := newCacheTestSvcCfg(key)

		assert.Equal(t, "MISS", serve(mdlwr, svcCfg, "gzip").Header.Get("X-Cache"))
		assert.Equal(t, "HIT", serve(mdlwr, svcCfg, "gzip").Header.Get("X-Cache"))

		assert.Equal(t, "MISS", serve(mdlwr, svcCfg, "gzip, br").Header.Get("X-Cache"))
		assert.Equal(t, "HIT", serve(mdlwr, svcCfg, "br, gzip").Header.Get("X-Cache"))
		assert.Equal(t, "HIT", serve(mdlwr, svcCfg, "GZIP;q=0.5, br").Header.Get("X-Cache"))

		assert.Equal(t, "MISS", serve(mdlwr, svcCfg, "").Header.Get("X-Cache"))
		assert.Equal(t, "HIT", serve(mdlwr, svcCfg, "gzip;q=0").Header.Get("X-Cache"))

		assert.Equal(t, "MISS", serve(mdlwr, svcCfg, "identity").Header.Get("X-Cache"))
	}
}

func TestCustomKeyIsScopedPerPrincipal(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("private"))
	})

	mdlwr, err := New(ctx, next, celEngine, tst.C.OcteliumC,
		vutils.UUIDv4(), corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)

	svcCfg := newCacheTestSvcCfg(&corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key{
		Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key_Eval{
			Eval: `"shared-by-everyone"`,
		},
	})

	serve := func(usrT *tstuser.User) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
		req.Header.Set("Cookie", "octelium_auth="+utilrand.GetRandomString(8))

		reqCtx := newCacheTestReqCtx(svcCfg)
		reqCtx.IsAuthenticated = true
		reqCtx.DownstreamInfo = &corev1.RequestContext{
			Session: usrT.Session,
			User:    usrT.Usr,
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext, reqCtx))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		return rw.Result()
	}

	usr1, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	usr2, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	assert.Equal(t, "MISS", serve(usr1).Header.Get("X-Cache"))
	assert.Equal(t, "HIT", serve(usr1).Header.Get("X-Cache"))

	assert.Equal(t, "MISS", serve(usr2).Header.Get("X-Cache"))
	assert.Equal(t, "HIT", serve(usr2).Header.Get("X-Cache"))
}

func TestPreAuthRefusesCredentialedRequests(t *testing.T) {
	for _, isCustomKey := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
		req.Header.Set("Authorization", "Bearer tkn")

		assert.False(t, requestAllowsCache(req, isCustomKey,
			corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH))

		req = httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
		req.Header.Set("Cookie", "octelium_auth=tkn")

		assert.False(t, requestAllowsCache(req, isCustomKey,
			corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH))

		req = httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)

		assert.True(t, requestAllowsCache(req, isCustomKey,
			corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH))
	}
}
