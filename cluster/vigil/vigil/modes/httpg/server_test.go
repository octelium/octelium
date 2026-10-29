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
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"context"

	"github.com/go-resty/resty/v2"
	"github.com/gorilla/websocket"
	"github.com/klauspost/compress/zstd"
	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type tstSrvHTTP struct {
	port        int
	srv         *http.Server
	isHTTP2     bool
	crt         *tls.Certificate
	isWS        bool
	bearerToken string
	caPool      *x509.CertPool
	lis         net.Listener

	wait      time.Duration
	startedAt time.Time
}

func newTestHTTPServer(t *testing.T, handler http.Handler, cfg *corev1.Service_Spec_Config_HTTP) (*Server, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	adminSrv := admin.NewServer(&admin.Opts{OcteliumC: tst.C.OcteliumC, IsEmbedded: true})
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP, Port: uint32(tests.GetPort()), IsPublic: true, IsAnonymous: true,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: upstream.URL},
				},
				Type: &corev1.Service_Spec_Config_Http{Http: cfg},
			},
		},
	})
	require.Nil(t, err)
	vc, err := vcache.NewCache(ctx)
	require.Nil(t, err)
	vc.SetService(svc)
	secretMan, err := secretman.New(ctx, tst.C.OcteliumC, vc)
	require.Nil(t, err)
	oc, err := octovigilc.NewClient(ctx, &octovigilc.Opts{OcteliumC: tst.C.OcteliumC, VCache: vc})
	require.Nil(t, err)
	srv, err := New(ctx, &modes.Opts{
		OcteliumC: tst.C.OcteliumC, VCache: vc, SecretMan: secretMan, OctovigilC: oc,
		LBManager: loadbalancer.NewLbManager(tst.C.OcteliumC, vc),
	})
	require.Nil(t, err)
	require.Nil(t, srv.Run(ctx))
	t.Cleanup(func() { srv.Close() })
	return srv, fmt.Sprintf("http://127.0.0.1:%d", ucorev1.ToService(svc).RealPort())
}

func TestHTTPRetryReplaysRequestAndIsolatesResponse(t *testing.T) {
	var attempts atomic.Int32
	payload := strings.Repeat("request payload ", 256)
	_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.Nil(t, err)
		assert.Equal(t, payload, string(body))
		if attempts.Add(1) == 1 {
			w.Header().Set("X-Failed-Attempt", "true")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("retry body"))
			return
		}
		w.Header().Set("X-Upstream-Success", "true")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	}), &corev1.Service_Spec_Config_HTTP{
		EnableRequestBuffering: true,
		Retry: &corev1.Service_Spec_Config_HTTP_Retry{
			MaxRetries:      3,
			InitialInterval: &metav1.Duration{Type: &metav1.Duration_Seconds{Seconds: 1}},
		},
	})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, addr+"/resource", strings.NewReader(payload))
	require.Nil(t, err)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.Nil(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, "created", string(body))
	assert.Equal(t, "true", resp.Header.Get("X-Upstream-Success"))
	assert.Empty(t, resp.Header.Get("X-Failed-Attempt"))
	assert.Equal(t, int32(2), attempts.Load())
}

func TestHTTPPathRewritePreservesEscapedSuffix(t *testing.T) {
	_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.RequestURI))
	}), &corev1.Service_Spec_Config_HTTP{Path: &corev1.Service_Spec_Config_HTTP_Path{
		RemovePrefix: "/api/v1", AddPrefix: "/backend",
	}})
	client := &http.Client{Timeout: 5 * time.Second}
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/api/v1/item%2Fpart?q=a%2Fb", "/backend/item%2Fpart?q=a%2Fb"},
		{"/api%2Fv1/item%2Fpart?q=a%2Fb", "/backend/item%2Fpart?q=a%2Fb"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := client.Get(addr + tc.path)
			require.Nil(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.Nil(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tc.want, string(body))
		})
	}
}

func TestHTTPResponseCacheAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header http.Header
		cached bool
	}{
		{name: "Cacheable", cached: true},
		{name: "Private", header: http.Header{"Cache-Control": {"private"}}},
		{name: "NoStore", header: http.Header{"Cache-Control": {"no-store"}}},
		{name: "SetCookie", header: http.Header{"Set-Cookie": {"session=private"}}},
		{name: "Vary", header: http.Header{"Vary": {"X-Tenant"}}},
		{name: "EmptyFirstVary", header: http.Header{"Vary": {"", "X-Tenant"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				for key, values := range tc.header {
					w.Header()[key] = append([]string(nil), values...)
				}
				w.Write([]byte(r.Header.Get("X-Tenant")))
			}), &corev1.Service_Spec_Config_HTTP{Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
				{Name: "response-cache", Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_{Cache: &corev1.Service_Spec_Config_HTTP_Plugin_Cache{UseXCacheHeader: true}}},
			}})
			client := &http.Client{Timeout: 5 * time.Second}
			for i, tenant := range []string{"tenant-one", "tenant-two"} {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, addr+"/cached", nil)
				require.Nil(t, err)
				req.Header.Set("X-Tenant", tenant)
				resp, err := client.Do(req)
				require.Nil(t, err)
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				require.Nil(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				if tc.cached && i == 1 {
					assert.Equal(t, "HIT", resp.Header.Get("X-Cache"))
					assert.Equal(t, "tenant-one", string(body))
				} else {
					assert.Equal(t, tenant, string(body))
				}
			}
			want := int32(2)
			if tc.cached {
				want = 1
			}
			assert.Equal(t, want, calls.Load())
		})
	}
}

func TestHTTPClientCancellationReachesUpstream(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-release:
		}
	}), &corev1.Service_Spec_Config_HTTP{})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr+"/slow", nil)
	require.Nil(t, err)
	done := make(chan error, 1)
	go func() {
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("The upstream request did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Error("The upstream request was not canceled")
	}
	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(3 * time.Second):
		t.Error("The canceled client request did not finish")
	}
}

func TestHTTPMalformedRequests(t *testing.T) {
	var rejectedCalls atomic.Int64
	_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rejected" {
			rejectedCalls.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}), &corev1.Service_Spec_Config_HTTP{EnableRequestBuffering: true})

	for _, tc := range []struct {
		name string
		raw  string
		code int
	}{
		{"duplicate host", "GET /rejected HTTP/1.1\r\nHost: example.com\r\nHost: other.example.com\r\n\r\n", http.StatusBadRequest},
		{"conflicting length", "POST /rejected HTTP/1.1\r\nHost: example.com\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab", http.StatusBadRequest},
		{"negative length", "POST /rejected HTTP/1.1\r\nHost: example.com\r\nContent-Length: -1\r\n\r\n", http.StatusBadRequest},
		{"invalid length", "POST /rejected HTTP/1.1\r\nHost: example.com\r\nContent-Length: invalid\r\n\r\n", http.StatusBadRequest},
		{"invalid header name", "GET /rejected HTTP/1.1\r\nHost: example.com\r\nBad Header: value\r\n\r\n", http.StatusBadRequest},
		{"NUL header", "GET /rejected HTTP/1.1\r\nHost: example.com\r\nX-Test: a\x00b\r\n\r\n", http.StatusBadRequest},
		{"missing host", "GET /rejected HTTP/1.1\r\nConnection: close\r\n\r\n", http.StatusBadRequest},
		{"invalid method", "G(ET /rejected HTTP/1.1\r\nHost: example.com\r\n\r\n", http.StatusBadRequest},
		{"large header", "GET /rejected HTTP/1.1\r\nHost: example.com\r\nX-Test: " + strings.Repeat("a", 2*maxHeaderBytes) + "\r\n\r\n", http.StatusRequestHeaderFieldsTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", strings.TrimPrefix(addr, "http://"), 3*time.Second)
			require.Nil(t, err)
			defer conn.Close()
			require.Nil(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			_, err = io.WriteString(conn, tc.raw)
			require.Nil(t, err)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			require.Nil(t, err)
			defer resp.Body.Close()
			assert.Equal(t, tc.code, resp.StatusCode)
			assert.Zero(t, rejectedCalls.Load())
		})
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(addr + "/healthy")
	require.Nil(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestHTTPConcurrentRequests(t *testing.T) {
	const limit = 16 * 1024
	var calls atomic.Int64
	_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		assert.Nil(t, err)
		assert.Equal(t, r.Header.Get("X-Test-ID"), r.URL.Query().Get("id"))
		assert.Equal(t, r.Header.Get("X-Test-ID"), strings.TrimRight(string(body), "x"))
		w.Header().Set("X-Test-ID", r.Header.Get("X-Test-ID"))
		_, _ = w.Write(body)
	}), &corev1.Service_Spec_Config_HTTP{
		ListenHTTP2: true, EnableRequestBuffering: true,
		Body: &corev1.Service_Spec_Config_HTTP_Body{MaxRequestSize: limit},
	})

	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("HTTP2-%t", h2), func(t *testing.T) {
			tr := &http.Transport{}
			tr.Protocols = new(http.Protocols)
			if h2 {
				tr.Protocols.SetUnencryptedHTTP2(true)
			} else {
				tr.Protocols.SetHTTP1(true)
			}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
			var wg sync.WaitGroup
			for i := range 48 {
				wg.Go(func() {
					id := fmt.Sprintf("request-%d-%t", i, h2)
					size := limit
					if i%3 == 0 {
						size++
					}
					body := id + strings.Repeat("x", size-len(id))
					req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, addr+"/?id="+id, strings.NewReader(body))
					if !assert.Nil(t, err) {
						return
					}
					if i%2 == 0 {
						req.ContentLength = -1
					}
					req.Header.Set("X-Test-ID", id)
					resp, err := client.Do(req)
					if !assert.Nil(t, err) {
						return
					}
					defer resp.Body.Close()
					got, err := io.ReadAll(resp.Body)
					assert.Nil(t, err)
					if size > limit {
						assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
						assert.Empty(t, resp.Header.Get("X-Test-ID"))
						return
					}
					assert.Equal(t, http.StatusOK, resp.StatusCode)
					assert.Equal(t, body, string(got))
					assert.Equal(t, id, resp.Header.Get("X-Test-ID"))
					if h2 {
						assert.Equal(t, 2, resp.ProtoMajor)
					}
				})
			}
			wg.Wait()
		})
	}
	assert.Equal(t, int64(64), calls.Load())
}

func TestHTTPIncompleteBodies(t *testing.T) {
	var incompleteCalls atomic.Int64
	_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/incomplete" {
			incompleteCalls.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	}), &corev1.Service_Spec_Config_HTTP{
		EnableRequestBuffering: true,
		Body:                   &corev1.Service_Spec_Config_HTTP_Body{MaxRequestSize: 1024},
	})

	var conns []net.Conn
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()
	for range 16 {
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(addr, "http://"), time.Second)
		require.Nil(t, err)
		conns = append(conns, conn)
		require.Nil(t, conn.SetWriteDeadline(time.Now().Add(2*time.Second)))
		_, err = io.WriteString(conn, "POST /incomplete HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\nx")
		require.Nil(t, err)
	}

	resp, err := (&http.Client{Timeout: 3 * time.Second}).Get(addr + "/healthy")
	require.Nil(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	for _, conn := range conns {
		require.Nil(t, conn.Close())
	}
	assert.Zero(t, incompleteCalls.Load())
}

func TestPluginConditionError(t *testing.T) {
	window := &metav1.Duration{Type: &metav1.Duration_Seconds{Seconds: 60}}

	for _, tc := range []struct {
		name   string
		plugin *corev1.Service_Spec_Config_HTTP_Plugin
	}{
		{"Direct", &corev1.Service_Spec_Config_HTTP_Plugin{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_{
				Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{StatusCode: http.StatusForbidden},
			},
		}},
		{"Path", &corev1.Service_Spec_Config_HTTP_Plugin{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{
				Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{AddPrefix: "/blocked"},
			},
		}},
		{"JSONSchema", &corev1.Service_Spec_Config_HTTP_Plugin{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_JsonSchema{
				JsonSchema: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema{
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline{
						Inline: `{"type": "object", "required": ["id"]}`,
					},
				},
			},
		}},
		{"Lua", &corev1.Service_Spec_Config_HTTP_Plugin{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
				Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
						Inline: "function onRequest(ctx)\n  octelium.req.exit(403)\nend\n",
					},
				},
			},
		}},
		{"RateLimit", &corev1.Service_Spec_Config_HTTP_Plugin{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_{
				RateLimit: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit{Limit: 1, Window: window},
			},
		}},
		{"Cache", &corev1.Service_Spec_Config_HTTP_Plugin{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_{
				Cache: &corev1.Service_Spec_Config_HTTP_Plugin_Cache{Ttl: window},
			},
		}},
		{"ExtProc", &corev1.Service_Spec_Config_HTTP_Plugin{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_{
				ExtProc: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc{
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_Address{Address: "localhost:1"},
				},
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.plugin.Name = "plugin"
			tc.plugin.Condition = &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `json.parse(ctx.request.http.headers["x-meta"]).priority > 5.0`,
				},
			}

			var upstreamCalls atomic.Int64
			_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}), &corev1.Service_Spec_Config_HTTP{
				EnableRequestBuffering: true,
				Plugins:                []*corev1.Service_Spec_Config_HTTP_Plugin{tc.plugin},
			})

			post := func(meta string) *http.Response {
				req, err := http.NewRequest(http.MethodPost, addr+"/", strings.NewReader(`{"name": "test"}`))
				require.Nil(t, err)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Meta", meta)
				resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
				require.Nil(t, err)
				return resp
			}

			for _, meta := range []string{"not json", `{"priority": 10, "priority": 1}`} {
				resp := post(meta)
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				require.Nil(t, err)

				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, meta)
				assert.Contains(t, string(body), "could not evaluate the Plugins", meta)
				assert.Zero(t, upstreamCalls.Load(), meta)
			}

			{
				resp := post(`{"priority": 1}`)
				resp.Body.Close()

				assert.Equal(t, http.StatusNoContent, resp.StatusCode)
				assert.Equal(t, int64(1), upstreamCalls.Load())
			}
		})
	}
}

func TestHTTPJSONBodyDuplicateNames(t *testing.T) {
	var upstreamCalls atomic.Int64
	_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}), &corev1.Service_Spec_Config_HTTP{
		EnableRequestBuffering: true,
		Body:                   &corev1.Service_Spec_Config_HTTP_Body{Mode: corev1.Service_Spec_Config_HTTP_Body_JSON},
	})

	post := func(body string) int {
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Post(addr+"/", "application/json", strings.NewReader(body))
		require.Nil(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	for _, body := range []string{
		`{"role":"user","role":"admin"}`,
		`{"user":{"role":"user","role":"admin"}}`,
	} {
		assert.Equal(t, http.StatusBadRequest, post(body), body)
		assert.Zero(t, upstreamCalls.Load(), body)
	}

	assert.Equal(t, http.StatusNoContent, post(`{"role":"user","Role":"admin"}`))
	assert.Equal(t, int64(1), upstreamCalls.Load())
}

type tstResp struct {
	Hello string `json:"hello"`
}

func (s *tstSrvHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.wait > 0 && time.Since(s.startedAt) < s.wait {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		var req tstResp
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		resp, err := json.Marshal(&tstResp{
			Hello: req.Hello,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	}

	if s.bearerToken != "" {
		bearer := r.Header.Get("Authorization")
		tkn := strings.TrimPrefix(bearer, "Bearer ")
		if s.bearerToken != tkn {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	if !s.isWS {
		w.Header().Set("Content-Type", "application/json")
		resp, err := json.Marshal(&tstResp{
			Hello: "world",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer wsConn.Close()
	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, payload, err := wsConn.ReadMessage()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			wsConn.WriteMessage(websocket.BinaryMessage, payload)
		}
	}
}

func newSrvHTTP(t *testing.T, port int, isHTTP2 bool, crt *tls.Certificate) *tstSrvHTTP {
	return &tstSrvHTTP{
		port:    port,
		isHTTP2: isHTTP2,
		crt:     crt,
	}
}

func (s *tstSrvHTTP) run(t *testing.T) {
	addr := fmt.Sprintf("localhost:%d", s.port)
	var err error

	handler := http.AllowQuerySemicolons(s)
	if s.isHTTP2 {
		handler = h2c.NewHandler(handler, &http2.Server{})
	}
	s.srv = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	if s.crt != nil {
		zap.L().Debug("upstream listening over TLS")
		s.lis, err = func() (net.Listener, error) {
			for range 100 {
				ret, err := tls.Listen("tcp", addr, s.getTLSConfig())
				if err == nil {
					return ret, nil
				}
				time.Sleep(1 * time.Second)
			}
			return nil, errors.Errorf("Could not listen tstSrvHTTP")
		}()
		assert.Nil(t, err)
	} else {
		s.lis, err = func() (net.Listener, error) {
			for range 100 {
				ret, err := net.Listen("tcp", addr)
				if err == nil {
					return ret, nil
				}
				time.Sleep(1 * time.Second)
			}
			return nil, errors.Errorf("Could not listen tstSrvHTTP")
		}()
		assert.Nil(t, err)
	}

	s.startedAt = time.Now()
	go s.srv.Serve(s.lis)
}

func (s *tstSrvHTTP) getTLSConfig() *tls.Config {
	if s.crt == nil {
		return nil
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*s.crt},
		NextProtos: func() []string {
			if s.isHTTP2 {
				return []string{"h2", "http/1.1"}
			} else {
				return []string{"http/1.1"}
			}
		}(),
		RootCAs: s.caPool,
	}

}

func (s *tstSrvHTTP) close() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.lis != nil {
		s.lis.Close()
	}

	time.Sleep(1 * time.Second)
}

type tstSrvGRPC struct {
	port int
	crt  *tls.Certificate
	corev1.UnimplementedMainServiceServer
	grpcSrv *grpc.Server
}

func newSrvGRPC(t *testing.T, port int, crt *tls.Certificate) *tstSrvGRPC {
	return &tstSrvGRPC{
		port: port,
		crt:  crt,
	}
}

func (s *tstSrvGRPC) run(t *testing.T) {
	addr := fmt.Sprintf("localhost:%d", s.port)
	lis, err := func() (net.Listener, error) {
		for i := 0; i < 100; i++ {
			listener, err := net.Listen("tcp", addr)
			if err == nil {
				return listener, nil
			}
			zap.L().Debug("Could not listen tstTCPProxy. Trying again...", zap.Error(err))
			time.Sleep(1 * time.Second)
		}
		return nil, errors.Errorf("Could not listen tstTCPProxy")
	}()

	assert.Nil(t, err)

	s.grpcSrv = grpc.NewServer()

	corev1.RegisterMainServiceServer(s.grpcSrv, s)
	go func() {
		s.grpcSrv.Serve(lis)
	}()
	time.Sleep(1 * time.Second)
}

func (s *tstSrvGRPC) CreateUser(ctx context.Context, req *corev1.User) (*corev1.User, error) {
	return req, nil
}

func (s *tstSrvGRPC) CreateSecret(ctx context.Context, req *corev1.Secret) (*corev1.Secret, error) {
	return nil, status.Errorf(codes.InvalidArgument, "Un-auth")
}

func (s *tstSrvGRPC) close() {
	s.grpcSrv.Stop()
	time.Sleep(1 * time.Second)
}

type tstOAuthSrv struct {
	srv         *http.Server
	port        int
	accessToken string
}

func (s *tstOAuthSrv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ret := map[string]any{
		"token_type":   "Bearer",
		"access_token": s.accessToken,
		"expires_in":   3600,
	}
	respBytes, _ := json.Marshal(&ret)
	w.Write(respBytes)
}

func (s *tstOAuthSrv) run(t *testing.T) {
	s.srv = &http.Server{
		Addr:    net.JoinHostPort("localhost", fmt.Sprintf("%d", s.port)),
		Handler: s,
	}

	lis, err := net.Listen("tcp", net.JoinHostPort("localhost", fmt.Sprintf("%d", s.port)))
	assert.Nil(t, err)
	go s.srv.Serve(lis)
}

func (s *tstOAuthSrv) close() {
	s.srv.Close()
	time.Sleep(1 * time.Second)
}

func TestServer(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	upstreamPort := tests.GetPort()
	getUpstreamSpec := func(isTLS bool) *corev1.Service_Spec_Config_Upstream {
		scheme := func() string {
			if isTLS {
				return "https"
			}
			return "http"
		}()

		return &corev1.Service_Spec_Config_Upstream{
			Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
				Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
					Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
						{
							Url: fmt.Sprintf("%s://localhost:%d", scheme, upstreamPort),
						},
					},
				},
			},

			/*
				Config: &corev1.Service_Spec_Config_Upstream_Config{
					Type: &corev1.Service_Spec_Config_Upstream_Config_Http{
						Http: &corev1.Service_Spec_Config_Upstream_Config_HTTP{
							EnableHTTP2: isHTTP2,
						},
					},
				},
			*/
		}
	}
	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Config: &corev1.Service_Spec_Config{
				Upstream: getUpstreamSpec(false),
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

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,

		LBManager: loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	/*
		{
			resp, err := resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
			assert.Nil(t, err)

			assert.True(t, resp.IsSuccess())
			assert.Equal(t, "world", resp.Result().(*tstResp).Hello)

			// now unauthorized
			svc.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].GroupsAny = []string{"root"}

			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err)

			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vCache.SetService(svcV)

			resp, err = resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, 403, resp.StatusCode())

			// authorized again
			svc.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].GroupsAny = []string{"all"}

			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err)

			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vCache.SetService(svcV)

			resp, err = resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
			assert.Nil(t, err)
			assert.True(t, resp.IsSuccess())
			assert.Equal(t, "world", resp.Result().(*tstResp).Hello)
		}
	*/

	{
		usr, err := tstuser.NewUserWorkloadClientless(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		srv.octovigilC.GetCache().SetSession(usr.Session)

		resp, err := resty.New().R().SetHeader("X-Octelium-Auth", usr.GetAccessToken().AccessToken).
			SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)
	}

	{
		// test bearer token
		tkn := utilrand.GetRandomString(16)
		srv.Close()
		upstreamSrv.close()
		upstreamSrv.bearerToken = tkn
		upstreamSrv.run(t)

		sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Secret_Spec{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: tkn,
				},
			},
		})
		assert.Nil(t, err)

		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: getUpstreamSpec(false),
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					Auth: &corev1.Service_Spec_Config_HTTP_Auth{
						Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_{
							Bearer: &corev1.Service_Spec_Config_HTTP_Auth_Bearer{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{
									FromSecret: sec.Metadata.Name,
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		resp, err := resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)

		/*
			svc.Spec.Config = nil
			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err, "%+v", err)
			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vCache.SetService(svcV)
		*/

		upstreamSrv.bearerToken = utilrand.GetRandomString(32)
		resp, err = resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode())

	}

	{
		// test oauth2 client credentials
		tkn := utilrand.GetRandomString(16)
		srv.Close()
		upstreamSrv.close()
		upstreamSrv.bearerToken = tkn
		upstreamSrv.run(t)

		oauth2Srv := &tstOAuthSrv{
			accessToken: tkn,
			port:        tests.GetPort(),
		}

		oauth2Srv.run(t)
		defer oauth2Srv.close()
		time.Sleep(2 * time.Second)

		sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Secret_Spec{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: tkn,
				},
			},
		})
		assert.Nil(t, err)

		if svc.Spec.Config == nil {
			svc.Spec.Config = &corev1.Service_Spec_Config{
				Upstream: getUpstreamSpec(false),
			}
		}
		svc.Spec.Config.Type = &corev1.Service_Spec_Config_Http{
			Http: &corev1.Service_Spec_Config_HTTP{
				Auth: &corev1.Service_Spec_Config_HTTP_Auth{
					Type: &corev1.Service_Spec_Config_HTTP_Auth_Oauth2ClientCredentials{
						Oauth2ClientCredentials: &corev1.Service_Spec_Config_HTTP_Auth_OAuth2ClientCredentials{
							ClientID: utilrand.GetRandomStringCanonical(8),
							TokenURL: fmt.Sprintf("http://localhost:%d/oauth2/token", oauth2Srv.port),
							ClientSecret: &corev1.Service_Spec_Config_HTTP_Auth_OAuth2ClientCredentials_ClientSecret{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_OAuth2ClientCredentials_ClientSecret_FromSecret{
									FromSecret: sec.Metadata.Name,
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			OctovigilC: octovigilC,
			VCache:     vCache,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		err = secretMan.ApplyService(ctx)
		assert.Nil(t, err)

		resp, err := resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)

		/*
			svc.Spec.Config = nil
			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err)
			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vCache.SetService(svcV)
		*/

		upstreamSrv.bearerToken = utilrand.GetRandomString(32)
		resp, err = resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode())

	}

	{
		// test mTLS
		srv.Close()
		upstreamSrv.close()

		root, err := utils_cert.GenerateCARoot()
		assert.Nil(t, err)
		sn, err := utils_cert.GenerateSerialNumber()
		assert.Nil(t, err)
		srvCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
			BasicConstraintsValid: true,
			SerialNumber:          sn,
			Subject: pkix.Name{
				CommonName: "localhost",
			},

			DNSNames: []string{"localhost"},

			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, root.Certificate, root.PrivateKey, false)
		assert.Nil(t, err)

		srvCert, err := tls.X509KeyPair((srvCrt.MustGetCertPEM()), (srvCrt.MustGetPrivateKeyPEM()))
		assert.Nil(t, err)
		upstreamSrv = newSrvHTTP(t, upstreamPort, false, &srvCert)
		srvCaPool := x509.NewCertPool()
		ok := srvCaPool.AppendCertsFromPEM(root.MustGetCertPEM())
		assert.True(t, ok)
		upstreamSrv.caPool = srvCaPool
		upstreamSrv.run(t)

		clientCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
			BasicConstraintsValid: true,
			SerialNumber:          sn,
			Subject: pkix.Name{
				CommonName: "client",
			},

			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, root.Certificate, root.PrivateKey, false)
		assert.Nil(t, err)

		sec := &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Secret_Spec{},
		}
		ucorev1.ToSecret(sec).SetCertificate(string(clientCrt.MustGetCertPEM()),
			string(clientCrt.MustGetPrivateKeyPEM()))
		sec, err = adminSrv.CreateSecret(ctx, sec)
		assert.Nil(t, err)

		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: getUpstreamSpec(true),
			ClientCertificate: &corev1.Service_Spec_Config_ClientCertificate{

				Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{
					FromSecret: sec.Metadata.Name,
				},

				TrustedCAs: []string{
					string(root.MustGetCertPEM()),
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secV, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Uid: sec.Metadata.Uid})
		assert.Nil(t, err)

		secretMan.Set(secV)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		resp, err := resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.True(t, resp.IsSuccess())
		zap.L().Debug("response", zap.Int("code", resp.StatusCode()), zap.String("body", string(resp.Body())))
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)

		/*
			svc.Spec.Config = nil
			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err)
			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vCache.SetService(svcV)


		*/

		upstreamSrv.bearerToken = ""
		upstreamSrv.caPool = nil
		upstreamSrv.crt = nil
	}

	{

		srv.Close()
		upstreamSrv.close()
		upstreamSrv.isHTTP2 = true
		upstreamSrv.run(t)

		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: getUpstreamSpec(false),
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					IsUpstreamHTTP2: true,
				},
			},
		}
		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		resp, err := resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)

		svc.Spec.Config = nil
	}

	{

		srv.Close()
		upstreamSrv.close()
		upstreamSrv.isHTTP2 = false
		upstreamSrv.isWS = true
		upstreamSrv.run(t)

		if svc.Spec.Config == nil {
			svc.Spec.Config = &corev1.Service_Spec_Config{}
		}
		svc.Spec.Config.Upstream = getUpstreamSpec(false)
		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		wsClient := websocket.Dialer{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}

		wsC, _, err := wsClient.DialContext(ctx,
			fmt.Sprintf("ws://localhost:%d/", ucorev1.ToService(svcV).RealPort()), http.Header{})
		assert.Nil(t, err)

		for i := 0; i < 10; i++ {
			msg := utilrand.GetRandomBytesMust(32)
			err = wsC.WriteMessage(websocket.BinaryMessage, msg)
			assert.Nil(t, err)
			_, read, err := wsC.ReadMessage()
			assert.Nil(t, err)
			assert.True(t, utils.SecureBytesEqual(msg, read))
		}

		wsC.Close()
	}

	{
		srv.Close()
		upstreamSrv.close()
		upstreamSrv.isWS = false
		upstreamSrv.isHTTP2 = false
		upstreamSrv.run(t)

		if svc.Spec.Config == nil {
			svc.Spec.Config = &corev1.Service_Spec_Config{}
		}
		svc.Spec.Config.Upstream = getUpstreamSpec(false)
		svc.Spec.IsTLS = true
		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		cert, err := srv.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: vutils.ClusterCertSecretName})
		assert.Nil(t, err)

		err = srv.SetClusterCertificate(cert)
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err, "%+v", err)

		time.Sleep(1 * time.Second)
		rootCa := x509.NewCertPool()

		ca, err := utils_cert.ParseX509LeafCertificateChainPEM(ucorev1.ToSecret(cert).GetSpecValueBytes())
		assert.Nil(t, err)
		rootCa.AddCert(ca)

		resp, err := resty.New().SetDebug(true).SetTLSClientConfig(&tls.Config{
			RootCAs: rootCa,
		}).R().SetResult(&tstResp{}).Get(fmt.Sprintf("https://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)
	}

	{

		srv.Close()
		upstreamSrv.close()

		grpcSrv := newSrvGRPC(t, upstreamPort, nil)
		grpcSrv.run(t)

		svc.Spec.IsTLS = false
		svc.Spec.Port = uint32(tests.GetPort())
		svc.Spec.Mode = corev1.Service_Spec_GRPC
		if svc.Spec.Config == nil {
			svc.Spec.Config = &corev1.Service_Spec_Config{}
		}
		svc.Spec.Config.Upstream = &corev1.Service_Spec_Config_Upstream{
			Type: &corev1.Service_Spec_Config_Upstream_Url{
				Url: fmt.Sprintf("http://localhost:%d", upstreamPort),
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)
		time.Sleep(1 * time.Second)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err, "%+v", err)

		time.Sleep(1 * time.Second)
		grcpConn, err := grpc.Dial(fmt.Sprintf("localhost:%d", ucorev1.ToService(svcV).RealPort()), grpc.WithTransportCredentials(insecure.NewCredentials()))
		assert.Nil(t, err)
		grpcC := corev1.NewMainServiceClient(grcpConn)
		req := &corev1.User{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomString(10),
				Uid:  utilrand.GetRandomString(10),
			},
		}
		resp, err := grpcC.CreateUser(ctx, req)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, pbutils.IsEqual(req, resp))

		_, err = grpcC.CreateSecret(ctx, &corev1.Secret{})
		assert.NotNil(t, err, "%+v", err)
		assert.True(t, grpcerr.IsInvalidArg(err))

		grpcSrv.close()
	}

	time.Sleep(2 * time.Second)
	err = srv.Close()
	assert.Nil(t, err)

}

func TestServerK8s(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	upstreamPort := tests.GetPort()

	root, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	sn, err := utils_cert.GenerateSerialNumber()
	assert.Nil(t, err)

	srvCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          sn,
		Subject: pkix.Name{
			CommonName: "localhost",
		},

		DNSNames: []string{"localhost"},

		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, root.Certificate, root.PrivateKey, false)
	assert.Nil(t, err)

	clientCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          sn,
		Subject: pkix.Name{
			CommonName: "client",
		},

		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, root.Certificate, root.PrivateKey, false)
	assert.Nil(t, err)

	sec := &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
	}
	ucorev1.ToSecret(sec).SetCertificate(string(clientCrt.MustGetCertPEM()),
		string(clientCrt.MustGetPrivateKeyPEM()))
	sec, err = adminSrv.CreateSecret(ctx, sec)
	assert.Nil(t, err)

	srvCert, err := tls.X509KeyPair((srvCrt.MustGetCertPEM()), (srvCrt.MustGetPrivateKeyPEM()))
	assert.Nil(t, err)

	upstreamSrv := newSrvHTTP(t, upstreamPort, false, &srvCert)
	upstreamSrv.caPool = x509.NewCertPool()
	upstreamSrv.caPool.AddCert(root.Certificate)
	upstreamSrv.run(t)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_KUBERNETES,

			Config: &corev1.Service_Spec_Config{

				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("https://localhost:%d", upstreamPort),
					},
				},
				Type: &corev1.Service_Spec_Config_Kubernetes_{
					Kubernetes: &corev1.Service_Spec_Config_Kubernetes{
						Type: &corev1.Service_Spec_Config_Kubernetes_ClientCertificate{
							ClientCertificate: &corev1.Service_Spec_Config_ClientCertificate{
								TrustedCAs: []string{
									string(root.MustGetCertPEM()),
								},

								Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{
									FromSecret: sec.Metadata.Name,
								},
							},
						},
					},
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())
	assert.Equal(t, "world", resp.Result().(*tstResp).Hello)
}

func TestUserUpstream(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, false, nil)

	upstreamSrv.run(t)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
					User: usr.Usr.Metadata.Name,
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)

	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usrDownstream, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usrDownstream.Connect()
	assert.Nil(t, err, "%+v", err)

	usrDownstream.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usrDownstream.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usrDownstream.Session)
	assert.Nil(t, err)
	usrDownstream.Resync()

	srv.octovigilC.GetCache().SetSession(usrDownstream.Session)
	usrDownstream.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsError())
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode())

	err = usr.ConnectWithServeAll()
	assert.Nil(t, err)

	usr.Resync()

	usr.Session.Status.Connection.Addresses = []*metav1.DualStackNetwork{
		{
			V4: "127.0.0.1/32",
			V6: "::1/128",
		},
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usrDownstream.Resync()

	tstP := &tstTCPProxy{
		host:       "www.google.com",
		port:       443,
		listenPort: 23000,
		ready:      make(chan struct{}),
	}
	err = tstP.run(ctx)
	assert.Nil(t, err)

	zap.L().Debug("Running tcp proxy", zap.Int("port", tstP.listenPort))

	<-tstP.ready
	time.Sleep(1 * time.Second)

	resp, err = resty.New().SetDebug(true).R().
		SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), "code: %d", resp.StatusCode())
}

type tstTCPProxy struct {
	host string
	port int

	listenPort int

	ready chan struct{}
}

func (p *tstTCPProxy) run(ctx context.Context) error {
	go func(ctx context.Context) {
		if err := p.doRun(ctx); err != nil {
			zap.L().Error("Could not doRun", zap.Error(err))
		}
	}(ctx)
	return nil
}

func (p *tstTCPProxy) doRun(ctx context.Context) error {
	zap.L().Debug("Starting TCP listener")
	var err error
	var listener net.Listener

	if err := func() error {
		for i := 0; i < 100; i++ {
			listener, err = net.Listen("tcp", fmt.Sprintf(":%d", p.listenPort))
			if err == nil {
				p.ready <- struct{}{}
				return nil
			}
			zap.L().Debug("Could not listen tstTCPProxy. Trying again...", zap.Error(err))
			time.Sleep(1 * time.Second)
		}
		return err
	}(); err != nil {
		return err
	}

	zap.L().Debug("created listener")

	defer listener.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()

			zap.L().Debug("new conn")
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			go func(conn net.Conn) {
				connBackend, err := p.getConnBackend()
				if err != nil {
					return
				}
				p.ServeTCP(conn.(*net.TCPConn), connBackend)
			}(conn)
		}
	}

}

func (p *tstTCPProxy) getConnBackend() (WriteCloser, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(p.host, fmt.Sprintf("%d", p.port)))
	if err != nil {
		return nil, err
	}
	return net.DialTCP("tcp", nil, tcpAddr)

}

func (p *tstTCPProxy) ServeTCP(conn, connBackend WriteCloser) {
	zap.L().Debug("Starting serveTCP")
	defer conn.Close()
	defer connBackend.Close()

	errChan := make(chan error, 2)
	go p.connCopy(conn, connBackend, errChan)
	go p.connCopy(connBackend, conn, errChan)

	<-errChan
}

func (p tstTCPProxy) connCopy(dst, src WriteCloser, errCh chan error) {
	_, err := io.Copy(dst, src)
	errCh <- err

	errClose := dst.CloseWrite()
	if errClose != nil {
		return
	}

	{
		dst.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
}

type WriteCloser interface {
	net.Conn
	CloseWrite() error
}

func TestAnonymous(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, false, nil)

	upstreamSrv.run(t)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic:    true,
			IsAnonymous: true,
			Port:        uint32(tests.GetPort()),
			Mode:        corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())

	svc.Spec.IsAnonymous = false
	svc, err = adminSrv.UpdateService(ctx, svc)
	assert.Nil(t, err)
	svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)
	vCache.SetService(svcV)
	time.Sleep(1 * time.Second)
	resp, err = resty.New().SetDebug(true).R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsError())
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode())
}

func TestBuffered(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstreamSrv.port),
					},
				},
				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						EnableRequestBuffering: true,
						Body: &corev1.Service_Spec_Config_HTTP_Body{
							Mode: corev1.Service_Spec_Config_HTTP_Body_JSON,
						},
					},
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	res := &tstResp{}
	tReq := &tstResp{
		Hello: utilrand.GetRandomString(32),
	}
	resp, err := resty.New().SetDebug(true).R().
		SetResult(res).
		SetBody(tReq).
		Post(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())
	assert.Equal(t, tReq.Hello, res.Hello)
}

func TestDirectResponse(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Response: &corev1.Service_Spec_Config_HTTP_Response{
							Type: &corev1.Service_Spec_Config_HTTP_Response_Direct_{
								Direct: &corev1.Service_Spec_Config_HTTP_Response_Direct{
									ContentType: fmt.Sprintf("application/%s", utilrand.GetRandomStringCanonical(8)),
									StatusCode:  209,
									Type: &corev1.Service_Spec_Config_HTTP_Response_Direct_Inline{
										Inline: utilrand.GetRandomString(400),
									},
								},
							},
						},
					},
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().
		Post(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())

	assert.Equal(t, svc.Spec.Config.GetHttp().Response.GetDirect().GetInline(), string(resp.Body()))
	assert.Equal(t, svc.Spec.Config.GetHttp().Response.GetDirect().ContentType,
		string(resp.Header().Get("Content-Type")))
	assert.Equal(t, svc.Spec.Config.GetHttp().Response.GetDirect().StatusCode, int32(resp.StatusCode()))
}

func TestJSONSchemaPlugin(t *testing.T) {

	const schema = `
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "User",
  "description": "A user in the system",
  "type": "object",
  "properties": {
    "id": {
      "description": "The unique identifier for the user",
      "type": "integer"
    },
    "username": {
      "description": "The user's username",
      "type": "string",
      "minLength": 3,
      "maxLength": 20,
      "pattern": "^[a-zA-Z0-9_]+$"
    },
    "email": {
      "description": "The user's email address",
      "type": "string",
      "format": "email"
    },
    "age": {
      "description": "Age in years",
      "type": "integer",
      "minimum": 13,
      "maximum": 120
    },
    "isActive": {
      "description": "Whether the user account is active",
      "type": "boolean",
      "default": true
    },
    "roles": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["admin", "editor", "viewer"]
      },
      "minItems": 1,
      "uniqueItems": true
    },
    "address": {
      "type": "object",
      "properties": {
        "street": { "type": "string" },
        "city": { "type": "string" },
        "state": { "type": "string" },
        "zip": { "type": "string", "pattern": "^\\d{5}(-\\d{4})?$" }
      },
      "required": ["street", "city", "zip"]
    }
  },
  "required": ["id", "username", "email"],
  "additionalProperties": false
}`

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstreamSrv.port),
					},
				},
				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						EnableRequestBuffering: true,
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "validation-1",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_JsonSchema{
									JsonSchema: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline{
											Inline: schema,
										},
										StatusCode: 417,
										Body: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Body{
											Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Body_Inline{
												Inline: utilrand.GetRandomString(32),
											},
										},
									},
								},
							},
						},
					},
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().SetBody(map[string]any{
		"id":       utilrand.GetRandomStringCanonical(8),
		"username": utilrand.GetRandomStringCanonical(8),
		"email":    fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
	}).
		Post(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsError())

	assert.Equal(t, svc.Spec.Config.GetHttp().Plugins[0].GetJsonSchema().Body.GetInline(), string(resp.Body()))
	assert.Equal(t, svc.Spec.Config.GetHttp().Plugins[0].GetJsonSchema().StatusCode, int32(resp.StatusCode()))
}

func TestHTTPSUpstream(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://raw.githubusercontent.com",
					},
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().
		Get(fmt.Sprintf("http://localhost:%d/octelium/octelium/refs/heads/main/unsorted/latest_release", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())

	resp2, err := resty.New().SetDebug(true).R().
		Get("https://raw.githubusercontent.com/octelium/octelium/refs/heads/main/unsorted/latest_release")
	assert.Nil(t, err)

	assert.Equal(t, resp.Body(), resp2.Body())
}

func TestLua(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "lua-1",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
									Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
											Inline: `
function onResponse(ctx)
  octelium.req.setResponseHeader("Content-Encoding", "application/json")
  octelium.req.setResponseBody(json.encode(ctx.user))
  octelium.req.setStatusCode(218)
end
																`,
										},
									},
								},
							},
						},
					},
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)
	resp, err := resty.New().SetDebug(true).R().
		Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())
	assert.Equal(t, 218, resp.StatusCode())

}

func TestLua2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "lua-1",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
									Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
											Inline: `
function onRequest(ctx)
  if strings.hasSuffix(ctx.request.http.path, ".php") then
    local resp = {}
	resp.uid = ctx.user.metadata.uid
	octelium.req.setResponseBody(json.encode(resp))
    octelium.req.exit(400)
  end
end
																`,
										},
									},
								},
							},
						},
					},
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())

	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d/page.php", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)

		res := make(map[string]any)
		err = json.Unmarshal(resp.Body(), &res)
		assert.Nil(t, err)
		assert.Equal(t, 400, resp.StatusCode())

		assert.Equal(t, usr.Usr.Metadata.Uid, res["uid"].(string))
	}

}

func TestLuaMultiple(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "lua-1",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
									Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
											Inline: `
function onResponse(ctx)
  octelium.req.setResponseHeader("X-Custom-Resp", "lua-1")
  octelium.req.setStatusCode(206)
end
																`,
										},
									},
								},
							},
							{
								Name: "lua-2",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
									Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
											Inline: `
function onResponse(ctx)
  octelium.req.setResponseHeader("X-Custom-Resp", "lua-2")
  octelium.req.setStatusCode(207)
end
																`,
										},
									},
								},
							},
						},
					},
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())

		assert.Equal(t, 207, resp.StatusCode())
		assert.Equal(t, "lua-2", resp.Header().Get("X-Custom-Resp"))
	}

}

func TestRateLimitPlugin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "rl-1",
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
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)
	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsError())
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode())
	}

	time.Sleep(4 * time.Second)
	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsError())
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode())
	}
}

func TestRetry(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.wait = 3 * time.Second
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstreamSrv.port),
					},
				},
				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Retry: &corev1.Service_Spec_Config_HTTP_Retry{
							MaxElapsedTime: &metav1.Duration{
								Type: &metav1.Duration_Seconds{
									Seconds: 9,
								},
							},
						},
					},
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().
		Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())

	assert.Equal(t, http.StatusOK, resp.StatusCode())
}

func TestIsDisabled(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic:   true,
			IsDisabled: true,
			Port:       uint32(tests.GetPort()),
			Mode:       corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstreamSrv.port),
					},
				},
			},
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
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().
		Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsError())

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode())

	svcV.Spec.IsDisabled = false
	svcV, err = srv.octeliumC.CoreC().UpdateService(ctx, svcV)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	time.Sleep(1 * time.Second)
	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())

		assert.Equal(t, http.StatusOK, resp.StatusCode())
	}
}

func TestAnonymousAuthorization(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, false, nil)

	upstreamSrv.run(t)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic:    true,
			IsAnonymous: true,
			Port:        uint32(tests.GetPort()),
			Mode:        corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://github.com",
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				EnableAnonymous: true,
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Name: "deny-about",
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_Match{
											Match: `ctx.request.http.path.startsWith("/about")`,
										},
									},
									Effect: corev1.Policy_Spec_Rule_DENY,
								},
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Effect: corev1.Policy_Spec_Rule_ALLOW,
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svc, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svc)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	{
		time.Sleep(1 * time.Second)
		resp, err := resty.New().SetDebug(true).
			R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svc).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		time.Sleep(1 * time.Second)
		resp, err := resty.New().SetDebug(true).
			R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d/about", ucorev1.ToService(svc).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsError())
		assert.Equal(t, http.StatusForbidden, resp.StatusCode())
	}

	{
		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			EnableAnonymous: true,
		}
		svc, err = srv.octeliumC.CoreC().UpdateService(ctx, svc)
		assert.Nil(t, err)
		vCache.SetService(svc)

		time.Sleep(1 * time.Second)
	}

	{
		time.Sleep(1 * time.Second)
		resp, err := resty.New().SetDebug(true).
			R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d/", ucorev1.ToService(svc).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsError())
		assert.Equal(t, http.StatusForbidden, resp.StatusCode())
	}

	{
		time.Sleep(1 * time.Second)
		resp, err := resty.New().SetDebug(true).
			R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d/about", ucorev1.ToService(svc).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsError())
		assert.Equal(t, http.StatusForbidden, resp.StatusCode())
	}

	{
		svc.Spec.Authorization = nil
		svc, err = srv.octeliumC.CoreC().UpdateService(ctx, svc)
		assert.Nil(t, err)
		vCache.SetService(svc)

		time.Sleep(1 * time.Second)
	}

	{
		time.Sleep(1 * time.Second)
		resp, err := resty.New().SetDebug(true).
			R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svc).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		time.Sleep(1 * time.Second)
		resp, err := resty.New().SetDebug(true).
			R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d/about", ucorev1.ToService(svc).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}
}

func TestMaxHeaderBytes(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	upstreamSrv := newSrvHTTP(t, tests.GetPort(), false, nil)
	upstreamSrv.run(t)
	t.Cleanup(func() {
		upstreamSrv.close()
	})

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic:    true,
			IsAnonymous: true,
			Port:        uint32(tests.GetPort()),
			Mode:        corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstreamSrv.port),
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		srv.Close()
	})

	time.Sleep(1 * time.Second)

	url := fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort())

	{
		resp, err := resty.New().R().
			SetHeader("X-Octelium-Tst", utilrand.GetRandomString(4*1024)).
			Get(url)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		resp, err := resty.New().R().
			SetHeader("X-Octelium-Tst", utilrand.GetRandomString(2*maxHeaderBytes)).
			Get(url)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusRequestHeaderFieldsTooLarge, resp.StatusCode())
	}

	{
		req := resty.New().R()
		for i := range 64 {
			req = req.SetHeader(fmt.Sprintf("X-Octelium-Tst-%d", i),
				utilrand.GetRandomString(1024))
		}

		resp, err := req.Get(url)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusRequestHeaderFieldsTooLarge, resp.StatusCode())
	}
}

func TestH2C(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	upstreamSrv := newSrvHTTP(t, tests.GetPort(), false, nil)
	upstreamSrv.run(t)
	t.Cleanup(func() {
		upstreamSrv.close()
	})

	maxRequestSize := 1024

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic:    true,
			IsAnonymous: true,
			Port:        uint32(tests.GetPort()),
			Mode:        corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstreamSrv.port),
					},
				},
				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						ListenHTTP2:            true,
						EnableRequestBuffering: true,
						Body: &corev1.Service_Spec_Config_HTTP_Body{
							MaxRequestSize: uint32(maxRequestSize),
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		srv.Close()
	})

	time.Sleep(1 * time.Second)

	url := fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort())

	{
		resp, err := resty.New().R().SetResult(&tstResp{}).Get(url)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)
	}

	{
		tr := &http.Transport{}
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetUnencryptedHTTP2(true)
		defer tr.CloseIdleConnections()

		resp, err := (&http.Client{Transport: tr}).Get(url)
		assert.Nil(t, err, "%+v", err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)

		res := &tstResp{}
		assert.Nil(t, json.NewDecoder(resp.Body).Decode(res))
		assert.Equal(t, "world", res.Hello)
	}

	doUpgrade := func(body []byte) *http.Response {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		assert.Nil(t, err)
		req.Header.Set("Connection", "Upgrade, HTTP2-Settings")
		req.Header.Set("Upgrade", "h2c")
		req.Header.Set("HTTP2-Settings", "AAMAAABkAAQAoAAAAAIAAAAA")

		tr := &http.Transport{}
		t.Cleanup(tr.CloseIdleConnections)

		resp, err := (&http.Client{Transport: tr}).Do(req)
		assert.Nil(t, err, "%+v", err)
		t.Cleanup(func() {
			resp.Body.Close()
		})
		return resp
	}

	{
		tReq := &tstResp{
			Hello: utilrand.GetRandomString(32),
		}
		body, err := json.Marshal(tReq)
		assert.Nil(t, err)

		resp := doUpgrade(body)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, 1, resp.ProtoMajor)

		res := &tstResp{}
		assert.Nil(t, json.NewDecoder(resp.Body).Decode(res))
		assert.Equal(t, tReq.Hello, res.Hello)
	}

	{
		resp := doUpgrade([]byte(utilrand.GetRandomString(2 * maxRequestSize)))
		assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	}
}

func TestRemoveH2CUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name     string
		header   http.Header
		expected http.Header
	}{
		{
			name: "h2c",
			header: http.Header{
				"Connection":     []string{"Upgrade, HTTP2-Settings"},
				"Upgrade":        []string{"h2c"},
				"Http2-Settings": []string{"AAMAAABkAAQAoAAAAAIAAAAA"},
				"X-Custom":       []string{"value"},
			},
			expected: http.Header{
				"X-Custom": []string{"value"},
			},
		},
		{
			name: "h2c with other connection tokens",
			header: http.Header{
				"Connection":     []string{"keep-alive, upgrade", "http2-settings, X-Hop"},
				"Upgrade":        []string{"H2C"},
				"Http2-Settings": []string{"AAMAAABkAAQAoAAAAAIAAAAA"},
				"X-Hop":          []string{"value"},
			},
			expected: http.Header{
				"Connection": []string{"keep-alive, X-Hop"},
				"X-Hop":      []string{"value"},
			},
		},
		{
			name: "h2c without HTTP2-Settings",
			header: http.Header{
				"Connection": []string{"Upgrade"},
				"Upgrade":    []string{"h2c"},
			},
			expected: http.Header{},
		},
		{
			name: "websocket",
			header: http.Header{
				"Connection": []string{"Upgrade"},
				"Upgrade":    []string{"websocket"},
			},
			expected: http.Header{
				"Connection": []string{"Upgrade"},
				"Upgrade":    []string{"websocket"},
			},
		},
		{
			name: "no upgrade",
			header: http.Header{
				"Connection":     []string{"keep-alive"},
				"Http2-Settings": []string{"AAMAAABkAAQAoAAAAAIAAAAA"},
			},
			expected: http.Header{
				"Connection":     []string{"keep-alive"},
				"Http2-Settings": []string{"AAMAAABkAAQAoAAAAAIAAAAA"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got http.Header
			handler := removeH2CUpgrade(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Clone()
			}))

			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			req.Header = tc.header

			handler.ServeHTTP(httptest.NewRecorder(), req)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestClientServedWSSUpgrade(t *testing.T) {
	crt, err := utils_cert.GenerateSelfSignedCert("virtual.example.com", []string{"virtual.example.com"}, time.Hour)
	require.Nil(t, err)
	certificate, err := tls.X509KeyPair(crt.MustGetCertPEM(), crt.MustGetPrivateKeyPEM())
	require.Nil(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(crt.Certificate)
	for _, explicitTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("ExplicitTLS%t", explicitTLS), func(t *testing.T) {
			sni := make(chan string, 2)
			done := make(chan struct{}, 2)
			upgrader := websocket.Upgrader{}
			backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() { done <- struct{}{} }()
				assert.Equal(t, "virtual.example.com", r.TLS.ServerName)
				assert.Equal(t, "virtual.example.com", r.Host)
				conn, err := upgrader.Upgrade(w, r, nil)
				if !assert.Nil(t, err) {
					return
				}
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
				kind, body, err := conn.ReadMessage()
				if !assert.Nil(t, err) {
					return
				}
				assert.Nil(t, conn.WriteMessage(kind, body))
			}))
			backend.TLS = &tls.Config{
				Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					sni <- hello.ServerName
					return nil, nil
				},
			}
			backend.StartTLS()
			defer backend.Close()
			srv, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("The original upstream should not receive the WebSocket request")
			}), &corev1.Service_Spec_Config_HTTP{IsUpstreamHTTP2: true})
			svc := pbutils.Clone(srv.vCache.GetService()).(*corev1.Service)
			svc.Spec.Config.Upstream = &corev1.Service_Spec_Config_Upstream{
				Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "wss://virtual.example.com/socket"},
				User: "serving-user",
			}
			if explicitTLS {
				svc.Spec.Config.Tls = &corev1.Service_Spec_Config_TLS{TrustedCAs: []string{string(crt.MustGetCertPEM())}}
			}
			srv.vCache.SetService(svc)
			srv.lbManager.SetSession(&corev1.Session{
				Metadata: &metav1.Metadata{Uid: "serving-session"},
				Status: &corev1.Session_Status{
					Type: corev1.Session_Status_CLIENT, UserRef: &metav1.ObjectReference{Name: "serving-user"},
					Connection: &corev1.Session_Status_Connection{
						L3Mode:    corev1.Session_Status_Connection_V4,
						Addresses: []*metav1.DualStackNetwork{{V4: "127.0.0.1/32"}},
						Upstreams: []*corev1.Session_Status_Connection_Upstream{{
							ServiceRef: &metav1.ObjectReference{Uid: svc.Metadata.Uid},
							Port:       int32(backend.Listener.Addr().(*net.TCPAddr).Port),
						}},
					},
				},
			})
			upstream, err := srv.lbManager.GetUpstream(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: &corev1.RequestContext{Service: svc},
			})
			require.Nil(t, err)
			require.True(t, upstream.IsUser)
			require.Equal(t, "virtual.example.com", upstream.SNIHost)
			require.Equal(t, backend.Listener.Addr().String(), upstream.HostPort)
			roundTripper, err := srv.getRoundTripper(upstream)
			require.Nil(t, err)
			req := httptest.NewRequest(http.MethodGet, "https://"+upstream.HostPort+"/socket", nil)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req = req.WithContext(context.WithValue(t.Context(), middlewares.CtxRequestContext, &middlewares.RequestContext{
				Service: svc, ServiceConfig: svc.Spec.Config,
			}))
			rt, err := roundTripper.getRoundTripper(req)
			require.Nil(t, err)
			transport, ok := rt.(*http.Transport)
			require.True(t, ok)
			if !explicitTLS {
				if transport.TLSClientConfig == nil {
					transport.TLSClientConfig = &tls.Config{}
				}
				transport.TLSClientConfig.RootCAs = roots
			}
			assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
			for _, kind := range []int{websocket.TextMessage, websocket.BinaryMessage} {
				dialer := websocket.Dialer{HandshakeTimeout: 3 * time.Second}
				conn, response, err := dialer.DialContext(t.Context(), strings.Replace(addr, "http://", "ws://", 1)+"/socket", nil)
				require.Nil(t, err)
				t.Cleanup(func() { conn.Close() })
				assert.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)
				require.Nil(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
				require.Nil(t, conn.SetWriteDeadline(time.Now().Add(3*time.Second)))
				body := []byte("payload through a client-served secure WebSocket")
				require.Nil(t, conn.WriteMessage(kind, body))
				gotKind, got, err := conn.ReadMessage()
				require.Nil(t, err)
				assert.Equal(t, kind, gotKind)
				assert.Equal(t, body, got)
				conn.Close()
				select {
				case name := <-sni:
					assert.Equal(t, "virtual.example.com", name)
				case <-time.After(3 * time.Second):
					t.Fatal("The TLS backend did not receive a client hello")
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("The WebSocket backend did not finish")
				}
			}
		})
	}
}

func TestHTTPPathRewriteEncodedVariants(t *testing.T) {
	for _, tc := range []struct {
		name     string
		remove   string
		add      string
		requests map[string]string
	}{
		{name: "Replace", remove: "/api/v1", add: "/backend", requests: map[string]string{
			"/api/v1/probe":                            "/backend/probe",
			"/api%2Fv1/item%2fpart?q=a%2Fb&v=%252F":    "/backend/item%2fpart?q=a%2Fb&v=%252F",
			"/%61pi/v%31/%61%2fpart":                   "/backend/%61%2fpart",
			"/api%2Fv1/%25value%3Fquery%23fragment":    "/backend/%25value%3Fquery%23fragment",
			"/api%2Fv1//item%2Fpart?x=a+b&x=%2B&flag=": "/backend//item%2Fpart?x=a+b&x=%2B&flag=",
			"/api%2Fv1?":                               "/backend?",
		}},
		{name: "RemoveOnly", remove: "/api", requests: map[string]string{
			"/api%2Fitem%2fpart?q=a%2Fb": "/item%2fpart?q=a%2Fb",
			"/api%2F%2fitem":             "/%2fitem",
			"/api":                       "/",
			"/api?":                      "/?",
			"/apix%2Fy":                  "/x%2Fy",
		}},
		{name: "ReservedPrefix", remove: "/api", add: "/next%25", requests: map[string]string{
			"/api/item%2Fpart":   "/next%2525/item%2Fpart",
			"/api%2Fitem%2fpart": "/next%2525%2Fitem%2fpart",
			"/api/item":          "/next%2525/item",
			"/api?":              "/next%2525?",
		}},
	} {
		for _, mode := range []string{"Service", "PreAuthPlugin", "PostAuthPlugin", "PluginThenService"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				cfg := &corev1.Service_Spec_Config_HTTP{}
				if mode == "Service" {
					cfg.Path = &corev1.Service_Spec_Config_HTTP_Path{RemovePrefix: tc.remove, AddPrefix: tc.add}
				} else {
					phase := corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH
					if mode == "PreAuthPlugin" {
						phase = corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH
					}
					add := tc.add
					if mode == "PluginThenService" {
						add = "/stage%25"
						cfg.Path = &corev1.Service_Spec_Config_HTTP_Path{RemovePrefix: add, AddPrefix: tc.add}
					}
					cfg.Plugins = []*corev1.Service_Spec_Config_HTTP_Plugin{{
						Name: "rewrite", Phase: phase,
						Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
						Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{
							RemovePrefix: tc.remove, AddPrefix: add,
						}},
					}}
				}
				_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Write([]byte(r.RequestURI))
				}), cfg)
				client := &http.Client{Timeout: 3 * time.Second}
				defer client.CloseIdleConnections()
				for target, want := range tc.requests {
					t.Run(target, func(t *testing.T) {
						response, err := client.Get(addr + target)
						require.Nil(t, err)
						defer response.Body.Close()
						body, err := io.ReadAll(response.Body)
						require.Nil(t, err)
						assert.Equal(t, http.StatusOK, response.StatusCode)
						assert.Equal(t, want, string(body))
					})
				}
			})
		}
	}
}

func TestHTTPIPv6CORS(t *testing.T) {
	var calls atomic.Int32
	_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte("upstream-response"))
	}), &corev1.Service_Spec_Config_HTTP{
		Cors: &corev1.Service_Spec_Config_HTTP_CORS{
			AllowOriginStringMatch: []string{"https://[2001:db8::1]", "https://[2001:db8::1]:8443"},
			AllowCredentials:       true,
		},
	})
	client := &http.Client{Timeout: 5 * time.Second}
	for _, tc := range []struct {
		origin string
		want   string
	}{
		{"https://[2001:db8::1]", "https://[2001:db8::1]"},
		{"https://[2001:DB8::1]:443", "https://[2001:db8::1]"},
		{"https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"},
		{"https://[2001:db8::1]:9443", ""},
		{"https://[2001:db8::2]:8443", ""},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			for _, method := range []string{http.MethodOptions, http.MethodGet} {
				before := calls.Load()
				req, err := http.NewRequestWithContext(t.Context(), method, addr+"/ipv6-cors", nil)
				require.Nil(t, err)
				req.Header.Set("Origin", tc.origin)
				if method == http.MethodOptions {
					req.Header.Set("Access-Control-Request-Method", http.MethodGet)
				}
				resp, err := client.Do(req)
				require.Nil(t, err)
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				require.Nil(t, err)
				assert.Equal(t, tc.want, resp.Header.Get("Access-Control-Allow-Origin"), method)
				assert.Contains(t, resp.Header.Values("Vary"), "Origin", method)
				if tc.want != "" {
					assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"), method)
				} else {
					assert.Empty(t, resp.Header.Get("Access-Control-Allow-Credentials"), method)
				}
				if method == http.MethodOptions {
					wantStatus := http.StatusNoContent
					if tc.want == "" {
						wantStatus = http.StatusForbidden
					}
					assert.Equal(t, wantStatus, resp.StatusCode)
					assert.Empty(t, body)
					assert.Equal(t, before, calls.Load())
				} else {
					assert.Equal(t, http.StatusOK, resp.StatusCode)
					assert.Equal(t, "upstream-response", string(body))
					assert.Equal(t, before+1, calls.Load())
				}
			}
		})
	}
}

func TestHTTPResponseCacheCompression(t *testing.T) {
	for _, phase := range []corev1.Service_Spec_Config_HTTP_Plugin_Phase{
		corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH,
		corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH,
	} {
		t.Run(phase.String(), func(t *testing.T) {
			body := strings.Repeat("cached compressible response ", 256)
			var calls atomic.Int32
			_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Content-Length", fmt.Sprint(len(body)))
				w.Header().Set("X-Upstream", "cached")
				w.Write([]byte(body))
			}), &corev1.Service_Spec_Config_HTTP{Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
				{Name: "response-cache", Phase: phase,
					Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
					Type:      &corev1.Service_Spec_Config_HTTP_Plugin_Cache_{Cache: &corev1.Service_Spec_Config_HTTP_Plugin_Cache{UseXCacheHeader: true}}},
			}})
			transport := &http.Transport{DisableCompression: true}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for _, tc := range []struct {
				acceptEncoding string
				encoding       string
				cache          string
				calls          int32
			}{
				{"", "", "MISS", 1},
				{"gzip;q=0", "", "HIT", 1},
				{"identity", "", "MISS", 2},
				{"gzip", "gzip", "MISS", 3},
				{"gzip", "gzip", "HIT", 3},
				{"zstd", "zstd", "MISS", 4},
				{"gzip;q=1,zstd;q=0.5", "gzip", "MISS", 5},
				{"gzip;q=0.5,zstd;q=1", "zstd", "HIT", 5},
				{"gzip;q=0,zstd;q=1", "zstd", "HIT", 5},
				{"identity", "", "HIT", 5},
				{"", "", "HIT", 5},
			} {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, addr+"/compressed-cache", nil)
				require.Nil(t, err)
				if tc.acceptEncoding != "" {
					req.Header.Set("Accept-Encoding", tc.acceptEncoding)
				}
				resp, err := client.Do(req)
				require.Nil(t, err)
				raw, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				require.Nil(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, tc.cache, resp.Header.Get("X-Cache"), tc.acceptEncoding)
				assert.Equal(t, tc.encoding, resp.Header.Get("Content-Encoding"), tc.acceptEncoding)
				assert.Equal(t, "cached", resp.Header.Get("X-Upstream"))
				assert.Contains(t, strings.Join(resp.Header.Values("Vary"), ","), "Accept-Encoding")
				assert.Equal(t, tc.calls, calls.Load(), tc.acceptEncoding)
				decoded := raw
				switch tc.encoding {
				case "gzip":
					reader, err := gzip.NewReader(bytes.NewReader(raw))
					require.Nil(t, err)
					decoded, err = io.ReadAll(reader)
					reader.Close()
					require.Nil(t, err)
				case "zstd":
					reader, err := zstd.NewReader(nil)
					require.Nil(t, err)
					decoded, err = reader.DecodeAll(raw, nil)
					reader.Close()
					require.Nil(t, err)
				}
				assert.Equal(t, body, string(decoded), tc.acceptEncoding)
			}
		})
	}
}

func TestHTTPResponseCacheEncodedUpstream(t *testing.T) {
	body := strings.Repeat("upstream gzip response ", 256)
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	_, err := writer.Write([]byte(body))
	require.Nil(t, err)
	require.Nil(t, writer.Close())
	var calls atomic.Int32
	_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(encoded.Len()))
		w.Header().Set("Vary", "Accept-Encoding")
		w.Write(encoded.Bytes())
	}), &corev1.Service_Spec_Config_HTTP{Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
		{Name: "response-cache", Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_{Cache: &corev1.Service_Spec_Config_HTTP_Plugin_Cache{UseXCacheHeader: true}}},
	}})
	transport := &http.Transport{DisableCompression: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, cache := range []string{"MISS", "HIT", "HIT"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, addr+"/encoded-cache", nil)
		require.Nil(t, err)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := client.Do(req)
		require.Nil(t, err)
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Nil(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, cache, resp.Header.Get("X-Cache"))
		assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
		assert.Equal(t, encoded.Bytes(), raw)
		assert.Equal(t, int32(1), calls.Load())
	}
}

func TestHTTPResponseCacheSensitiveHeaderLines(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header http.Header
	}{
		{name: "LaterCookie", header: http.Header{"Set-Cookie": {"", "session=private"}}},
		{name: "LaterCookie2", header: http.Header{"Set-Cookie2": {"", "session=private"}}},
		{name: "LaterContentRange", header: http.Header{"Content-Range": {"", "bytes 0-9/100"}}},
		{name: "CombinedVary", header: http.Header{"Vary": {"Accept-Encoding, X-Tenant"}}},
		{name: "LaterVary", header: http.Header{"Vary": {"Accept-Encoding", "X-Tenant"}}},
		{name: "EmptyFirstVary", header: http.Header{"Vary": {"", "X-Tenant"}}},
		{name: "LaterWildcard", header: http.Header{"Vary": {"", "*"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			_, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				for key, values := range tc.header {
					w.Header()[key] = append([]string(nil), values...)
				}
				w.Write([]byte(r.Header.Get("X-Tenant")))
			}), &corev1.Service_Spec_Config_HTTP{Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
				{Name: "response-cache", Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_{Cache: &corev1.Service_Spec_Config_HTTP_Plugin_Cache{UseXCacheHeader: true}}},
			}})
			client := &http.Client{Timeout: 5 * time.Second}
			for _, tenant := range []string{"tenant-one", "tenant-two"} {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, addr+"/sensitive-cache", nil)
				require.Nil(t, err)
				req.Header.Set("X-Tenant", tenant)
				resp, err := client.Do(req)
				require.Nil(t, err)
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				require.Nil(t, err)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				assert.Equal(t, "MISS", resp.Header.Get("X-Cache"))
				assert.Equal(t, tenant, string(body))
			}
			assert.Equal(t, int32(2), calls.Load())
		})
	}
}

func TestHTTPLoginRedirectEncodedTargets(t *testing.T) {
	var calls atomic.Int32
	srv, addr := newTestHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}), &corev1.Service_Spec_Config_HTTP{})
	svc := pbutils.Clone(srv.vCache.GetService()).(*corev1.Service)
	svc.Spec.IsAnonymous = false
	svc, err := srv.octeliumC.CoreC().UpdateService(t.Context(), svc)
	require.Nil(t, err)
	srv.vCache.SetService(svc)
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	wantHost := vutils.GetServicePublicFQDN(svc, srv.domain)
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/items/plain?q=value", "/items/plain?q=value"},
		{"/items/a%2Fb?q=%2F", "/items/a%2Fb?q=%2F"},
		{"/items/a%3Fb%23c?q=value", "/items/a%3Fb%23c?q=value"},
		{"/items/a%252Fb%253Fc%2523d?key=%252F", "/items/a%252Fb%253Fc%2523d?key=%252F"},
		{"/items/%E4%B8%AD?q=a+b&value=a%2Bb", "/items/%E4%B8%AD?q=a+b&value=a%2Bb"},
		{"/items/item?", "/items/item?"},
		{"/items/100%25?flag&empty=&k=1&k=2", "/items/100%25?flag&empty=&k=1&k=2"},
		{"/old/../items/a%3Fb%23c?q=%26%3D", "/items/a%3Fb%23c?q=%26%3D"},
		{"/items/a%2fb%3fc?q=%2f", "/items/a%2fb%3fc?q=%2f"},
		{"/%2F%2Fattacker.test/%40name?q=value", "/%2F%2Fattacker.test/%40name?q=value"},
		{"/items/%5C%5Cattacker.test?q=value", "/items/%5C%5Cattacker.test?q=value"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, addr+tc.path, nil)
			require.Nil(t, err)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
			resp, err := client.Do(req)
			require.Nil(t, err)
			_, err = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			require.Nil(t, err)
			require.Equal(t, http.StatusSeeOther, resp.StatusCode)
			location, err := resp.Location()
			require.Nil(t, err)
			assert.Equal(t, "https", location.Scheme)
			assert.Equal(t, srv.domain, location.Host)
			assert.Equal(t, "/login", location.Path)
			assert.Equal(t, "https://"+wantHost+tc.want, location.Query().Get("redirect"))
			target, err := url.Parse(location.Query().Get("redirect"))
			require.Nil(t, err)
			assert.Equal(t, wantHost, target.Host)
			assert.Empty(t, target.Fragment)
		})
	}
	assert.Zero(t, calls.Load())
}
