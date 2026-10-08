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

package harness

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/e2e/scenario"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testIngress struct {
	h        *H
	upstream *CountingUpstream
	srv      *http.Server
}

func newTestIngress(t *testing.T, readHeaderTimeout time.Duration) *testIngress {
	t.Helper()

	crt, err := utils_cert.GenerateSelfSignedCert("example.com",
		[]string{"example.com", "*.example.com"}, time.Hour)
	require.NoError(t, err)

	crtPEM, err := crt.GetCertPEM()
	require.NoError(t, err)
	keyPEM, err := crt.GetPrivateKeyPEM()
	require.NoError(t, err)

	certPath := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(certPath, []byte(crtPEM), 0o600))

	pair, err := tls.X509KeyPair([]byte(crtPEM), []byte(keyPEM))
	require.NoError(t, err)

	upstream, err := NewCountingUpstream("127.0.0.1:0", 512)
	require.NoError(t, err)
	t.Cleanup(upstream.Close)

	target, err := url.Parse(upstream.URL())
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(target)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := &http.Server{
		ReadHeaderTimeout: readHeaderTimeout,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pair},
			NextProtos:   []string{"h2", "http/1.1"},
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer good" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
	}

	go srv.ServeTLS(lis, "", "")
	t.Cleanup(func() { srv.Close() })

	h := &H{State: &scenario.State{CertPath: certPath}}
	h.ingressOnce.Do(func() { h.ingressAddr = lis.Addr().String() })

	return &testIngress{h: h, upstream: upstream, srv: srv}
}

func mixedTokens(worker, iteration int) HTTPRequestSpec {
	if iteration%2 == 0 {
		return HTTPRequestSpec{Token: "good", Class: "good", ID: fmt.Sprintf("good-%d", iteration)}
	}
	return HTTPRequestSpec{Token: "forged", Class: "forged", ID: fmt.Sprintf("forged-%d", iteration)}
}

func TestHTTPLoad(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts HTTPLoadOpts
	}{
		{name: "HTTP/1.1 keep-alive", opts: HTTPLoadOpts{Workers: 8}},
		{name: "a new connection per request", opts: HTTPLoadOpts{Workers: 8, NewConnPerRequest: true}},
		{name: "HTTP/2 multiplexed", opts: HTTPLoadOpts{Workers: 8, HTTP2: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ing := newTestIngress(t, 5*time.Second)

			o := tc.opts
			o.URL = "https://svc.example.com/"
			o.Requests = 200
			o.Request = mixedTokens

			res, err := ing.h.HTTPLoad(t.Context(), o)
			require.NoError(t, err)

			assert.Equal(t, 200, res.Succeeded, res.String())
			assert.Equal(t, 100, res.Count("good", http.StatusOK))
			assert.Equal(t, 100, res.Count("forged", http.StatusUnauthorized))
			assert.Zero(t, res.CountOther("good", http.StatusOK))
			assert.Equal(t, []string{"forged", "good"}, res.Classes())
			assert.Equal(t, 100, res.ClassLatency("good").Count)

			assert.Equal(t, 100, ing.upstream.SeenWithPrefix("good-"))
			assert.Zero(t, ing.upstream.SeenWithPrefix("forged-"),
				"a rejected request must never reach the upstream")
			assert.Empty(t, ing.upstream.Duplicates())
			assert.Equal(t, int64(100), ing.upstream.Total())
			assert.Equal(t, 1, ing.upstream.Seen("good-0"))
		})
	}
}

func TestHTTPLoadForADuration(t *testing.T) {
	ing := newTestIngress(t, 5*time.Second)

	started := time.Now()
	res, err := ing.h.HTTPLoad(t.Context(), HTTPLoadOpts{
		URL:      "https://svc.example.com/",
		Workers:  4,
		Duration: 300 * time.Millisecond,
		Request: func(worker, iteration int) HTTPRequestSpec {
			return HTTPRequestSpec{Token: "good", Class: "good", Path: "/?holdMs=10"}
		},
	})
	require.NoError(t, err)

	assert.Less(t, time.Since(started), 5*time.Second)
	assert.Greater(t, res.Count("good", http.StatusOK), 10)
	assert.LessOrEqual(t, ing.upstream.PeakInFlight(), int64(4))
}

func TestSlowClients(t *testing.T) {
	ing := newTestIngress(t, time.Second)

	res, err := ing.h.SlowClients(t.Context(), "svc.example.com", 5, 10*time.Second, false)
	require.NoError(t, err)

	assert.Equal(t, 5, res.Opened, res.String())
	assert.Equal(t, 5, res.Closed, "the header timeout must close every slow client")
	assert.Less(t, res.Lifetime.Summary().Max, 8*time.Second)
}
