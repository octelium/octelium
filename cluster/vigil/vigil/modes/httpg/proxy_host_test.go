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

package httpg

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyHostEval(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Host))
	}))
	defer upstream.Close()
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	celEngine, err := celengine.New(t.Context(), nil)
	require.Nil(t, err)

	usr := &corev1.User{
		Metadata: &metav1.Metadata{Name: "usr", Uid: "host-usr-uid", ResourceVersion: "host-usr-rv"},
	}
	request := &corev1.RequestContext_Request{
		Type: &corev1.RequestContext_Request_Http{
			Http: &corev1.RequestContext_Request_HTTP{
				Path:    "/v1",
				Headers: map[string]string{"x-host": "custom.example.com"},
			},
		},
	}

	newReqCtx := map[string]func(svc *corev1.Service) *middlewares.RequestContext{
		"authenticated": func(svc *corev1.Service) *middlewares.RequestContext {
			ret := &middlewares.RequestContext{
				DownstreamInfo: &corev1.RequestContext{Request: request, Service: svc, User: usr},
			}
			ret.SetReqCtxMap()
			return ret
		},
		"anonymous": func(svc *corev1.Service) *middlewares.RequestContext {
			return &middlewares.RequestContext{
				DownstreamInfo: &corev1.RequestContext{Request: request, Service: svc},
			}
		},
		"plugin": func(svc *corev1.Service) *middlewares.RequestContext {
			downstreamInfo := &corev1.RequestContext{Request: request, Service: svc, User: usr}
			return &middlewares.RequestContext{
				DownstreamInfo: downstreamInfo,
				ReqCtxMap:      pbutils.MustConvertToMap(downstreamInfo),
			}
		},
	}

	hostEval := func(eval string) *corev1.Service_Spec_Config_HTTP_Header_Host {
		return &corev1.Service_Spec_Config_HTTP_Header_Host{
			Type: &corev1.Service_Spec_Config_HTTP_Header_Host_Eval{Eval: eval},
		}
	}

	for i, tc := range []struct {
		host      *corev1.Service_Spec_Config_HTTP_Header_Host
		want      string
		anonymous string
	}{
		{nil, upstreamHost, upstreamHost},
		{&corev1.Service_Spec_Config_HTTP_Header_Host{
			Type: &corev1.Service_Spec_Config_HTTP_Header_Host_Value{Value: "value.example.com"},
		}, "value.example.com", "value.example.com"},
		{hostEval(`ctx.service.metadata.name + ".example.com"`), "tst.default.example.com", "tst.default.example.com"},
		{hostEval(`ctx.user.metadata.name + ".users.example.com"`), "usr.users.example.com", upstreamHost},
		{hostEval(`ctx.request.http.headers["x-host"]`), "custom.example.com", "custom.example.com"},
		{hostEval(`"const.example.com"`), "const.example.com", "const.example.com"},
		{hostEval(`""`), upstreamHost, upstreamHost},
		{hostEval(`ctx.missing.field`), upstreamHost, upstreamHost},
		{hostEval(`1`), upstreamHost, upstreamHost},
	} {
		for name, fn := range newReqCtx {
			cfg := &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: upstream.URL},
				},
				Type: &corev1.Service_Spec_Config_Http{Http: &corev1.Service_Spec_Config_HTTP{
					Header: &corev1.Service_Spec_Config_HTTP_Header{Host: tc.host},
				}},
			}
			svc := newForwardedSvc(false)
			svc.Metadata.Uid = "host-svc-uid"
			svc.Metadata.ResourceVersion = vutils.UUIDv4()
			svc.Spec.Mode = corev1.Service_Spec_HTTP
			svc.Spec.Config = cfg

			cache, err := vcache.NewCache(t.Context())
			require.Nil(t, err)
			cache.SetService(svc)
			client := &tstSigV4Client{core: &tstSigV4CoreClient{}}
			secrets, err := secretman.New(t.Context(), client, cache)
			require.Nil(t, err)
			s := &Server{
				secretMan:  secrets,
				lbManager:  loadbalancer.NewLbManager(client, cache),
				transports: newTransportCache(),
				celEngine:  celEngine,
			}

			reqCtx := fn(svc)
			reqCtx.Service = svc
			reqCtx.ServiceConfig = cfg
			reqCtx.AuthResponse = &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: &corev1.RequestContext{Service: svc},
				Config:         cfg,
			}
			ctx := context.WithValue(t.Context(), middlewares.CtxRequestContext, reqCtx)
			proxy, err := s.getProxy(ctx)
			require.Nil(t, err)

			req := httptest.NewRequest(http.MethodGet, "https://public.example.com/v1", nil).WithContext(ctx)
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, req)
			s.transports.closeAll()

			assert.Equal(t, http.StatusOK, rec.Code, "%d %s", i, name)
			body, err := io.ReadAll(rec.Body)
			require.Nil(t, err)
			want := tc.want
			if name == "anonymous" {
				want = tc.anonymous
			}
			assert.Equal(t, want, string(body), "%d %s", i, name)
			if tc.host.GetEval() == "" && name != "plugin" {
				assert.Nil(t, reqCtx.ReqCtxMap, "%d %s", i, name)
			}
		}
	}
}
