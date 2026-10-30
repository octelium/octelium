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

package preauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownstreamNetwork(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd00::/64")
	for _, mode := range []corev1.Service_Spec_Mode{
		corev1.Service_Spec_HTTP, corev1.Service_Spec_WEB, corev1.Service_Spec_GRPC,
		corev1.Service_Spec_KUBERNETES, corev1.Service_Spec_MCP, corev1.Service_Spec_LLM,
		corev1.Service_Spec_RDP_WEB,
	} {
		for _, public := range []bool{false, true} {
			for _, tc := range []struct {
				name      string
				remote    string
				header    string
				ip        string
				forwarded string
			}{
				{"Client4", "100.64.0.9:39481", "203.0.113.7", "100.64.0.9", ""},
				{"Client6", "[fd00::9]:39481", "203.0.113.7", "fd00::9", ""},
				{"Ingress", "10.4.1.9:39481", "203.0.113.7", "", "203.0.113.7"},
				{"Ingress6", "[2001:db8::9]:39481", "2001:db8::7", "", "2001:db8::7"},
				{"NoForwardedIP", "10.4.1.9:39481", "", "", ""},
				{"InvalidForwardedIP", "10.4.1.9:39481", "invalid", "", ""},
				{"InvalidPort", "100.64.0.9:65536", "203.0.113.7", "", ""},
			} {
				t.Run(fmt.Sprintf("%s/Public=%t/%s", mode, public, tc.name), func(t *testing.T) {
					reqCtx := &middlewares.RequestContext{Service: &corev1.Service{
						Spec: &corev1.Service_Spec{Mode: mode, IsPublic: public},
					}}
					path := "/example.Service/Method"
					if mode == corev1.Service_Spec_KUBERNETES {
						path = "/api/v1/namespaces/default/pods"
					}
					req := httptest.NewRequest(http.MethodGet, "http://service.example.com"+path, nil)
					req.RemoteAddr = tc.remote
					req.Header.Set(vutils.GetDownstreamIPHeaderCanonical(), tc.header)
					req = req.WithContext(context.WithValue(req.Context(), middlewares.CtxRequestContext, reqCtx))
					called := false
					m := &middleware{
						v4Prefix: &v4,
						v6Prefix: &v6,
						next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							called = true
						}),
					}
					m.ServeHTTP(httptest.NewRecorder(), req)
					require.True(t, called)
					network := reqCtx.GetNetwork()
					if tc.ip == "" && tc.forwarded == "" {
						assert.Nil(t, network)
						return
					}
					require.NotNil(t, network)
					assert.Equal(t, tc.forwarded, network.ForwardedClientIP)
					assert.Nil(t, network.UpstreamLocal)
					assert.Nil(t, network.UpstreamRemote)
					if tc.ip != "" {
						require.NotNil(t, network.Downstream)
						assert.Equal(t, tc.ip, network.Downstream.Ip)
						assert.Equal(t, uint32(39481), network.Downstream.Port)
						assert.Empty(t, reqCtx.DownstreamRequest.Request.Ip)
						assert.Empty(t, req.Header.Get(vutils.GetDownstreamIPHeaderCanonical()))
					} else {
						assert.Nil(t, network.Downstream)
						assert.NotEmpty(t, reqCtx.DownstreamRequest.Source.Address)
					}
				})
			}
		}
	}
}

func BenchmarkClientAddressClassification(b *testing.B) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd00::/64")
	m := &middleware{v4Prefix: &v4, v6Prefix: &v6}
	for _, tc := range []struct {
		address string
		client  bool
	}{
		{"100.64.0.9", true},
		{"fd00::9", true},
		{"10.4.1.9", false},
	} {
		b.Run(tc.address, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if m.isAddressFromClient(tc.address) != tc.client {
					b.Fatal("unexpected client address classification")
				}
			}
		})
	}
}
