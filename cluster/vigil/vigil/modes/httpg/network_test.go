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
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestHTTPUpstreamNetwork(t *testing.T) {
	for _, protocol := range []string{"HTTP1", "H2C", "HTTP2TLS"} {
		t.Run(protocol, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, r.RemoteAddr)
			})
			var upstreamHandler http.Handler = handler
			if protocol == "H2C" {
				upstreamHandler = h2c.NewHandler(handler, &http2.Server{})
			}
			backend := httptest.NewUnstartedServer(upstreamHandler)
			backend.EnableHTTP2 = protocol == "HTTP2TLS"
			if protocol == "HTTP2TLS" {
				backend.StartTLS()
			} else {
				backend.Start()
			}
			defer backend.Close()
			upstreamURL, err := url.Parse(backend.URL)
			require.Nil(t, err)
			if protocol == "H2C" {
				upstreamURL.Scheme = "h2c"
			}
			cfg := &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: upstreamURL.String()},
				},
				Type: &corev1.Service_Spec_Config_Http{Http: &corev1.Service_Spec_Config_HTTP{
					IsUpstreamHTTP2: protocol != "HTTP1",
				}},
			}
			if protocol == "HTTP2TLS" {
				cfg.Tls = &corev1.Service_Spec_Config_TLS{
					TrustedCAs: []string{string(pem.EncodeToMemory(&pem.Block{
						Type: "CERTIFICATE", Bytes: backend.Certificate().Raw,
					}))},
				}
			}
			svc := &corev1.Service{
				Metadata: &metav1.Metadata{Uid: "service"},
				Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Config: cfg},
			}
			vc, err := vcache.NewCache(t.Context())
			require.Nil(t, err)
			vc.SetService(svc)
			sm, err := secretman.New(t.Context(), nil, vc)
			require.Nil(t, err)
			r := &roundTripper{
				secretMan: sm, transports: newTransportCache(),
				upstream: &loadbalancer.Upstream{HostPort: upstreamURL.Host, URL: upstreamURL},
			}
			defer r.transports.closeAll()
			var traceCalls atomic.Int32
			var reused atomic.Bool
			run := func(port int) {
				reqCtx := &middlewares.RequestContext{Service: svc, ServiceConfig: cfg}
				reqCtx.SetNetwork(logentry.GetNetwork(&net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: port}))
				before := reqCtx.GetNetwork()
				ctx := context.WithValue(t.Context(), middlewares.CtxRequestContext, reqCtx)
				ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
					GotConn: func(info httptrace.GotConnInfo) {
						traceCalls.Add(1)
						reused.Store(info.Reused)
					},
				})
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.URL, nil)
				require.Nil(t, err)
				resp, err := r.RoundTrip(req)
				require.Nil(t, err)
				body, err := io.ReadAll(resp.Body)
				require.Nil(t, err)
				require.Nil(t, resp.Body.Close())
				if protocol != "HTTP1" {
					assert.Equal(t, 2, resp.ProtoMajor)
				}
				peerIP, peerPort, err := net.SplitHostPort(string(body))
				require.Nil(t, err)
				network := reqCtx.GetNetwork()
				require.NotNil(t, network.GetUpstreamLocal())
				assert.Equal(t, peerIP, network.UpstreamLocal.Ip)
				assert.Equal(t, peerPort, strconv.Itoa(int(network.UpstreamLocal.Port)))
				assert.Equal(t, logentry.GetEndpoint(backend.Listener.Addr()), network.UpstreamRemote)
				assert.Equal(t, uint32(port), network.Downstream.Port)
				assert.Nil(t, before.UpstreamLocal)
				assert.Nil(t, before.UpstreamRemote)
			}
			run(40000)
			run(40001)
			assert.True(t, reused.Load())
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Go(func() { run(40002 + i) })
			}
			wg.Wait()
			assert.Equal(t, int32(10), traceCalls.Load())
		})
	}
}
