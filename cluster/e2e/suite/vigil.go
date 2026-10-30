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

package suite

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type seenRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   string
}

type vigilCtx struct {
	h        *harness.H
	svc      *corev1.Service
	upstream *harness.TestSrvHTTP
	conn     *harness.Conn

	seen atomic.Pointer[seenRequest]
}

func (v *vigilCtx) url(path string) string {
	return v.conn.URL(v.svc.Metadata.Name) + path
}

func (v *vigilCtx) record(t *testing.T, status int, body string) {
	t.Helper()

	v.seen.Store(nil)
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		if r.Body != nil {
			buf := make([]byte, 4096)
			for {
				n, err := r.Body.Read(buf)
				b.Write(buf[:n])
				if err != nil {
					break
				}
			}
		}

		v.seen.Store(&seenRequest{
			Method: r.Method,
			Path:   r.URL.Path,
			Header: r.Header.Clone(),
			Body:   b.String(),
		})

		zap.L().Debug("Upstream received request",
			zap.String("method", r.Method), zap.String("path", r.URL.Path))

		w.WriteHeader(status)
		if body != "" {
			w.Write([]byte(body))
		}
	})
}

func (v *vigilCtx) setHTTP(t *testing.T, cfg *corev1.Service_Spec_Config_HTTP) {
	t.Helper()

	v.svc.Spec.Config.Type = &corev1.Service_Spec_Config_Http{Http: cfg}
	v.svc = v.h.UpdateService(t, v.svc)
}

func (v *vigilCtx) waitSeen(t *testing.T, what, path string,
	check func(r *seenRequest) error) {
	t.Helper()

	v.h.Eventually(t, what, harness.DecisionBudget, func(ctx context.Context) error {
		v.seen.Store(nil)

		res, err := v.h.HTTP().R().SetContext(ctx).Get(v.url(path))
		if err != nil {
			return err
		}
		if !res.IsSuccess() {
			return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
		}

		got := v.seen.Load()
		if got == nil {
			return errors.New("the upstream has not been reached yet")
		}

		return check(got)
	})
}

func (v *vigilCtx) waitStatusAt(t *testing.T, path string, want int) {
	t.Helper()

	v.h.Eventually(t, fmt.Sprintf("GET %s to return %d", path, want),
		harness.DecisionBudget, func(ctx context.Context) error {
			res, err := v.h.HTTP().R().SetContext(ctx).Get(v.url(path))
			if err != nil {
				return err
			}
			if res.StatusCode() != want {
				return errUnexpectedStatus(res.StatusCode(), want)
			}
			return nil
		})
}

func newVigilCtx(t *testing.T, h *harness.H) *vigilCtx {
	t.Helper()

	upstream := h.StartHTTPUpstream(t, nil)

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode:     corev1.Service_Spec_HTTP,
			IsPublic: true,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstream.Port),
					},
					User: "root",
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{svc.Metadata.Name: h.Port()},
		Serve:   []string{svc.Metadata.Name},
	})

	return &vigilCtx{h: h, svc: svc, upstream: upstream, conn: conn}
}

func VigilRegressionPhases() []Phase {
	return []Phase{
		{"VigilRetryReplay", testVigilRetryReplay},
		{"VigilCacheResponseSafety", testVigilCacheResponseSafety},
		{"VigilEscapedPathRewrite", testVigilEscapedPathRewrite},
	}
}

func testVigilRetryReplay(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	v := newVigilCtx(t, h)
	v.svc.Spec.IsAnonymous = true
	v.svc = h.UpdateService(t, v.svc)
	var mu sync.Mutex
	bodies := make(map[string][]string)
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.Nil(t, err)
		mu.Lock()
		bodies[r.URL.Path] = append(bodies[r.URL.Path], string(body))
		attempt := len(bodies[r.URL.Path])
		mu.Unlock()
		w.Header().Set("X-Upstream-Attempt", fmt.Sprint(attempt))
		if attempt == 1 {
			w.Header().Set("X-Failed-Attempt", "true")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("failed attempt"))
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
	})
	v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
		EnableRequestBuffering: true,
		Retry: &corev1.Service_Spec_Config_HTTP_Retry{
			MaxRetries:      3,
			InitialInterval: &metav1.Duration{Type: &metav1.Duration_Seconds{Seconds: 1}},
		},
	})
	routes := []struct {
		name string
		url  string
	}{{"Published", v.url("")}, {"Ingress", h.ServiceURL(v.svc)}}
	for _, route := range routes {
		h.Eventually(t, fmt.Sprintf("Vigil to retry an idempotent %s request", route.name), harness.DecisionBudget, func(ctx context.Context) error {
			res, err := h.HTTPNoRetry().R().SetContext(ctx).SetBody("probe").Put(route.url + "/ready-" + route.name + "-" + h.Name())
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusCreated {
				return errUnexpectedStatus(res.StatusCode(), http.StatusCreated)
			}
			return nil
		})
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodPatch} {
				t.Run(method, func(t *testing.T) {
					path := "/request-" + h.Name()
					payload := strings.Repeat("replayed body ", 256)
					res, err := h.HTTPNoRetry().R().SetContext(t.Context()).SetBody(payload).Execute(method, route.url+path)
					require.Nil(t, err)
					wantStatus, wantAttempts := http.StatusServiceUnavailable, 1
					if method == http.MethodPut {
						wantStatus, wantAttempts = http.StatusCreated, 2
						assert.Equal(t, payload, string(res.Body()))
						assert.Empty(t, res.Header().Get("X-Failed-Attempt"))
					}
					assert.Equal(t, wantStatus, res.StatusCode())
					mu.Lock()
					got := append([]string(nil), bodies[path]...)
					mu.Unlock()
					require.Len(t, got, wantAttempts)
					for _, body := range got {
						assert.Equal(t, payload, body)
					}
				})
			}
		})
	}
}

func testVigilCacheResponseSafety(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	v := newVigilCtx(t, h)
	v.svc.Spec.IsAnonymous = true
	v.svc = h.UpdateService(t, v.svc)
	cases := []struct {
		name   string
		header http.Header
		cached bool
	}{
		{name: "Cacheable", cached: true},
		{name: "Private", header: http.Header{"Cache-Control": {"private"}}},
		{name: "NoStore", header: http.Header{"Cache-Control": {"no-store"}}},
		{name: "Cookie", header: http.Header{"Set-Cookie": {"session=private"}}},
		{name: "Vary", header: http.Header{"Vary": {"X-Tenant"}}},
		{name: "EmptyFirstVary", header: http.Header{"Vary": {"", "X-Tenant"}}},
	}
	var mu sync.Mutex
	calls := make(map[string]int)
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls[r.URL.RequestURI()]++
		mu.Unlock()
		for _, tc := range cases {
			if tc.name == r.URL.Query().Get("case") {
				for key, values := range tc.header {
					w.Header()[key] = append([]string(nil), values...)
				}
			}
		}
		w.Write([]byte(r.Header.Get("X-Tenant")))
	})
	v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
		{Name: "response-cache", Phase: corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH,
			Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
			Type:      &corev1.Service_Spec_Config_HTTP_Plugin_Cache_{Cache: &corev1.Service_Spec_Config_HTTP_Plugin_Cache{UseXCacheHeader: true}}},
	}})
	routes := []struct {
		name string
		url  string
	}{{"Published", v.url("")}, {"Ingress", h.ServiceURL(v.svc)}}
	for _, route := range routes {
		h.Eventually(t, fmt.Sprintf("Vigil to apply the response cache plugin to %s requests", route.name), harness.DecisionBudget, func(ctx context.Context) error {
			res, err := h.HTTPNoRetry().R().SetContext(ctx).Get(route.url + "/ready")
			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK || res.Header().Get("X-Cache") == "" {
				return errors.New("the response cache plugin is not active yet")
			}
			return nil
		})
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					path := "/cached-" + h.Name() + "?case=" + tc.name
					for i, tenant := range []string{"tenant-one", "tenant-two"} {
						res, err := h.HTTPNoRetry().R().SetContext(t.Context()).SetHeader("X-Tenant", tenant).Get(route.url + path)
						require.Nil(t, err)
						assert.Equal(t, http.StatusOK, res.StatusCode())
						if tc.cached && i == 1 {
							assert.Equal(t, "HIT", res.Header().Get("X-Cache"))
							assert.Equal(t, "tenant-one", string(res.Body()))
						} else {
							assert.Equal(t, tenant, string(res.Body()))
						}
					}
					mu.Lock()
					got := calls[path]
					mu.Unlock()
					want := 2
					if tc.cached {
						want = 1
					}
					assert.Equal(t, want, got)
				})
			}
		})
	}
}

func testVigilEscapedPathRewrite(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	v := newVigilCtx(t, h)
	v.svc.Spec.IsAnonymous = true
	v.svc = h.UpdateService(t, v.svc)
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.RequestURI))
	})
	v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{Path: &corev1.Service_Spec_Config_HTTP_Path{
		RemovePrefix: "/api/v1", AddPrefix: "/backend",
	}})
	routes := []struct {
		name string
		url  string
	}{{"Published", v.url("")}, {"Ingress", h.ServiceURL(v.svc)}}
	for _, route := range routes {
		h.Eventually(t, fmt.Sprintf("Vigil to apply the path rewrite to %s requests", route.name), harness.DecisionBudget, func(ctx context.Context) error {
			res, err := h.HTTPNoRetry().R().SetContext(ctx).Get(route.url + "/api/v1/probe")
			if err != nil {
				return err
			}
			if string(res.Body()) != "/backend/probe" {
				return errors.Errorf("got path %q", res.Body())
			}
			return nil
		})
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			for _, path := range []string{"/api/v1/item%2Fpart?q=a%2Fb", "/api%2Fv1/item%2Fpart?q=a%2Fb"} {
				res, err := h.HTTPNoRetry().R().SetContext(t.Context()).Get(route.url + path)
				require.Nil(t, err)
				assert.Equal(t, http.StatusOK, res.StatusCode())
				assert.Equal(t, "/backend/item%2Fpart?q=a%2Fb", string(res.Body()), path)
			}
		})
	}
}

func testVigilRequestLimitsLoad(t *testing.T, h *harness.H) {
	const limit = 4096
	const total = 96
	v := newVigilCtx(t, h)
	var mu sync.Mutex
	seen := make(map[string]int)
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.Nil(t, err)
		id := r.Header.Get(harness.RequestIDHeader)
		mu.Lock()
		seen[id]++
		mu.Unlock()
		w.Header().Set(harness.RequestIDHeader, id)
		_, _ = w.Write(body)
	})
	v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
		EnableRequestBuffering: true,
		Body:                   &corev1.Service_Spec_Config_HTTP_Body{MaxRequestSize: limit},
	})
	h.Eventually(t, "Vigil to enforce the request body limit", harness.DecisionBudget,
		func(ctx context.Context) error {
			resp, err := h.HTTPNoRetry().R().SetContext(ctx).
				SetBody(strings.Repeat("x", limit+1)).Post(v.url("/probe"))
			if err != nil {
				return err
			}
			if resp.StatusCode() != http.StatusRequestEntityTooLarge {
				return errUnexpectedStatus(resp.StatusCode(), http.StatusRequestEntityTooLarge)
			}
			return nil
		})

	tr := &http.Transport{MaxIdleConns: 32, MaxIdleConnsPerHost: 16}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	var latencies harness.Latencies
	var wg sync.WaitGroup
	for worker := range 12 {
		wg.Go(func() {
			for i := worker; i < total; i += 12 {
				id := fmt.Sprintf("request-%d", i)
				body := id + strings.Repeat("x", limit-len(id))
				want := http.StatusOK
				if i%3 == 1 {
					body += "x"
					want = http.StatusRequestEntityTooLarge
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, v.url("/load"), strings.NewReader(body))
				if !assert.Nil(t, err) {
					return
				}
				if i%2 == 0 {
					req.ContentLength = -1
				}
				req.Header.Set(harness.RequestIDHeader, id)
				if i%3 == 2 {
					req.Header.Set("X-Large", strings.Repeat("h", 64*1024))
					want = http.StatusRequestHeaderFieldsTooLarge
				}
				started := time.Now()
				resp, err := client.Do(req)
				if !assert.Nil(t, err) {
					continue
				}
				got, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				latencies.Add(time.Since(started))
				assert.Nil(t, err)
				assert.Equal(t, want, resp.StatusCode, "request %s", id)
				if want == http.StatusOK {
					assert.Equal(t, body, string(got))
					assert.Equal(t, id, resp.Header.Get(harness.RequestIDHeader))
				}
			}
		})
	}
	wg.Wait()
	t.Logf("Vigil request limit load latency: %s", latencies.Summary())

	mu.Lock()
	for i := range total {
		want := 0
		if i%3 == 0 {
			want = 1
		}
		assert.Equal(t, want, seen[fmt.Sprintf("request-%d", i)], "request %d reached the upstream unexpectedly or more than once", i)
	}
	mu.Unlock()
	v.waitStatusAt(t, "/healthy", http.StatusOK)
}

func testVigilPlugins(t *testing.T, h *harness.H) {
	v := newVigilCtx(t, h)

	matchAny := &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}
	matchPath := func(prefix string) *corev1.Condition {
		return &corev1.Condition{
			Type: &corev1.Condition_Match{
				Match: fmt.Sprintf(`ctx.request.http.path.startsWith(%q)`, prefix),
			},
		}
	}

	t.Run("DirectResponse", func(t *testing.T) {
		v.record(t, http.StatusOK, "from-upstream")

		const body = "e2e-teapot"

		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
			Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
				{
					Name:      "teapot",
					Condition: matchPath("/teapot"),
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_{
						Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{
							StatusCode: http.StatusTeapot,
							Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{
									Inline: body,
								},
							},
							Headers: []*corev1.Service_Spec_Config_HTTP_Plugin_Direct_KeyValue{
								{Key: "X-E2E-Direct", Value: "yes"},
							},
						},
					},
				},
			},
		})

		v.waitStatusAt(t, "/teapot", http.StatusTeapot)

		res, err := h.HTTP().R().Get(v.url("/teapot"))
		require.Nil(t, err)
		assert.Equal(t, body, string(res.Body()))
		assert.Equal(t, "yes", res.Header().Get("X-E2E-Direct"))

		v.seen.Store(nil)
		_, err = h.HTTP().R().Get(v.url("/teapot"))
		require.Nil(t, err)
		assert.Nil(t, v.seen.Load(), "a direct response must not reach the upstream")

		v.waitStatusAt(t, "/", http.StatusOK)
	})

	t.Run("PathRewrite", func(t *testing.T) {
		v.record(t, http.StatusOK, "")

		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
			Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
				{
					Name:      "rewrite",
					Condition: matchPath("/api"),
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{
						Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{
							RemovePrefix: "/api",
							AddPrefix:    "/v2",
						},
					},
				},
			},
		})

		v.waitSeen(t, "the upstream to receive the rewritten path", "/api/things",
			func(r *seenRequest) error {
				if r.Path != "/v2/things" {
					return errors.Errorf("the upstream saw the path %q, want %q",
						r.Path, "/v2/things")
				}
				return nil
			})
	})

	t.Run("Headers", func(t *testing.T) {
		v.record(t, http.StatusOK, "")

		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
			Header: &corev1.Service_Spec_Config_HTTP_Header{
				AddRequestHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
					{
						Key:  "X-E2E-Request",
						Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "upstream"},
					},
				},
				AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
					{
						Key:  "X-E2E-Response",
						Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "downstream"},
					},
				},
			},
		})

		v.waitSeen(t, "the upstream to receive the injected request header", "/",
			func(r *seenRequest) error {
				if got := r.Header.Get("X-E2E-Request"); got != "upstream" {
					return errors.Errorf("the upstream saw X-E2E-Request %q, want %q",
						got, "upstream")
				}
				return nil
			})

		h.Eventually(t, "the client to receive the injected response header",
			harness.DecisionBudget, func(ctx context.Context) error {
				res, err := h.HTTP().R().SetContext(ctx).Get(v.url("/"))
				if err != nil {
					return err
				}
				if got := res.Header().Get("X-E2E-Response"); got != "downstream" {
					return errors.Errorf("the client saw X-E2E-Response %q, want %q",
						got, "downstream")
				}
				return nil
			})
	})

	t.Run("JSONSchemaValidation", func(t *testing.T) {
		v.record(t, http.StatusOK, "")

		const schema = `{
  "type": "object",
  "required": ["name"],
  "properties": {
    "name": {"type": "string"}
  }
}`

		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
			EnableRequestBuffering: true,
			Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
				{
					Name:      "schema",
					Condition: matchAny,
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_JsonSchema{
						JsonSchema: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema{
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline{
								Inline: schema,
							},
							StatusCode: http.StatusUnprocessableEntity,
						},
					},
				},
			},
		})

		post := func(ctx context.Context, body string) (int, error) {
			res, err := h.HTTP().R().SetContext(ctx).
				SetHeader("Content-Type", "application/json").
				SetBody(body).
				Post(v.url("/"))
			if err != nil {
				return 0, err
			}
			return res.StatusCode(), nil
		}

		h.Eventually(t, "an invalid body to be rejected by the schema",
			harness.DecisionBudget, func(ctx context.Context) error {
				got, err := post(ctx, `{"unexpected": 1}`)
				if err != nil {
					return err
				}
				if got != http.StatusUnprocessableEntity {
					return errUnexpectedStatus(got, http.StatusUnprocessableEntity)
				}
				return nil
			})

		h.Eventually(t, "a valid body to be accepted", harness.DecisionBudget,
			func(ctx context.Context) error {
				got, err := post(ctx, `{"name": "octelium"}`)
				if err != nil {
					return err
				}
				if got != http.StatusOK {
					return errUnexpectedStatus(got, http.StatusOK)
				}
				return nil
			})
	})

	t.Run("ConditionError", func(t *testing.T) {
		v.record(t, http.StatusOK, "")

		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
			EnableRequestBuffering: true,
			Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
				{
					Name: "schema",
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `json.parse(ctx.request.http.headers["x-meta"]).strict == true`,
						},
					},
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_JsonSchema{
						JsonSchema: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema{
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline{
								Inline: `{"type": "object", "required": ["name"]}`,
							},
							StatusCode: http.StatusUnprocessableEntity,
						},
					},
				},
			},
		})

		post := func(ctx context.Context, meta string) (int, error) {
			res, err := h.HTTP().R().SetContext(ctx).
				SetHeader("Content-Type", "application/json").
				SetHeader("X-Meta", meta).
				SetBody(`{"unexpected": 1}`).
				Post(v.url("/"))
			if err != nil {
				return 0, err
			}
			return res.StatusCode(), nil
		}

		h.Eventually(t, "the schema to be enforced when its condition matches",
			harness.DecisionBudget, func(ctx context.Context) error {
				got, err := post(ctx, `{"strict": true}`)
				if err != nil {
					return err
				}
				if got != http.StatusUnprocessableEntity {
					return errUnexpectedStatus(got, http.StatusUnprocessableEntity)
				}
				return nil
			})

		for _, meta := range []string{"not json", `{"strict": true, "strict": false}`} {
			v.seen.Store(nil)
			got, err := post(t.Context(), meta)
			require.Nil(t, err)
			assert.Equal(t, http.StatusInternalServerError, got, meta)
			assert.Nil(t, v.seen.Load(), "a request whose plugin condition fails must not reach the upstream")
		}

		got, err := post(t.Context(), `{"strict": false}`)
		require.Nil(t, err)
		assert.Equal(t, http.StatusOK, got)
	})

	t.Run("JSONBodyDuplicateNames", func(t *testing.T) {
		v.record(t, http.StatusOK, "")

		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
			EnableRequestBuffering: true,
			Body: &corev1.Service_Spec_Config_HTTP_Body{
				Mode: corev1.Service_Spec_Config_HTTP_Body_JSON,
			},
		})

		post := func(ctx context.Context, body string) (int, error) {
			res, err := h.HTTP().R().SetContext(ctx).
				SetHeader("Content-Type", "application/json").
				SetBody(body).
				Post(v.url("/"))
			if err != nil {
				return 0, err
			}
			return res.StatusCode(), nil
		}

		h.Eventually(t, "a body with duplicate member names to be rejected",
			harness.DecisionBudget, func(ctx context.Context) error {
				got, err := post(ctx, `{"role":"user","role":"admin"}`)
				if err != nil {
					return err
				}
				if got != http.StatusBadRequest {
					return errUnexpectedStatus(got, http.StatusBadRequest)
				}
				return nil
			})

		v.seen.Store(nil)
		got, err := post(t.Context(), `{"user":{"role":"user","role":"admin"}}`)
		require.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, got)
		assert.Nil(t, v.seen.Load(), "a body with duplicate member names must not reach the upstream")

		got, err = post(t.Context(), `{"role":"user","Role":"admin"}`)
		require.Nil(t, err)
		assert.Equal(t, http.StatusOK, got)
	})

	t.Run("Lua", func(t *testing.T) {
		v.record(t, http.StatusOK, "")

		sessName := h.Status(t).Session.Metadata.Name

		script := `
function onRequest(ctx)
  if octelium.req.getQueryParam("deny") == "1" then
    octelium.req.exit(403)
    return
  end
  octelium.req.setRequestHeader("X-E2E-Lua-Session", ctx.session.metadata.name)
end

function onResponse(ctx)
  octelium.req.setResponseHeader("X-E2E-Lua", "done")
end`

		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
			Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
				{
					Name:      "lua",
					Condition: matchAny,
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
						Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
								Inline: script,
							},
						},
					},
				},
			},
		})

		v.waitSeen(t, "the upstream to receive the header set by the Lua script", "/",
			func(r *seenRequest) error {
				if got := r.Header.Get("X-E2E-Lua-Session"); got != sessName {
					return errors.Errorf("the upstream saw X-E2E-Lua-Session %q, want %q",
						got, sessName)
				}
				return nil
			})

		res, err := h.HTTP().R().Get(v.url("/"))
		require.Nil(t, err)
		assert.Equal(t, "done", res.Header().Get("X-E2E-Lua"))

		v.waitStatusAt(t, "/?deny=1", http.StatusForbidden)

		v.seen.Store(nil)
		_, err = h.HTTP().R().Get(v.url("/?deny=1"))
		require.Nil(t, err)
		assert.Nil(t, v.seen.Load(), "a Lua exit must not reach the upstream")
	})

	t.Run("RateLimit", func(t *testing.T) {
		v.record(t, http.StatusOK, "")

		const limit = 3

		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
			Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
				{
					Name:      "ratelimit",
					Condition: matchPath("/limited"),
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_{
						RateLimit: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit{
							Limit:  limit,
							Window: &metav1.Duration{Type: &metav1.Duration_Seconds{Seconds: 60}},
							Key: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_PerSession{
									PerSession: true,
								},
							},
						},
					},
				},
			},
		})

		h.Eventually(t, "the rate limit to start refusing requests", harness.DecisionBudget,
			func(ctx context.Context) error {
				for range limit + 2 {
					res, err := h.HTTP().R().SetContext(ctx).Get(v.url("/limited"))
					if err != nil {
						return err
					}
					if res.StatusCode() == http.StatusTooManyRequests {
						return nil
					}
				}
				return errors.New("the rate limit never refused a request")
			})

		v.waitStatusAt(t, "/", http.StatusOK)
	})
}

func testVigilDynamicConfig(t *testing.T, h *harness.H) {
	v := newVigilCtx(t, h)
	v.record(t, http.StatusOK, "")

	v.svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
		Configs: []*corev1.Service_Spec_Config{
			{
				Name: "beta",
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", v.upstream.Port),
					},
					User: "root",
				},
				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "beta-marker",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{MatchAny: true},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_{
									Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{
										StatusCode: http.StatusAccepted,
										Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
											Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{
												Inline: "beta",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
			{
				Condition: &corev1.Condition{
					Type: &corev1.Condition_Match{
						Match: `"x-e2e-channel" in ctx.request.http.headers && ` +
							`ctx.request.http.headers["x-e2e-channel"] == "beta"`,
					},
				},
				Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "beta"},
			},
		},
	}

	v.svc = h.UpdateService(t, v.svc)

	t.Run("DefaultConfig", func(t *testing.T) {
		h.Eventually(t, "a request without the channel header to use the default config",
			harness.DecisionBudget, func(ctx context.Context) error {
				res, err := h.HTTP().R().SetContext(ctx).Get(v.url("/"))
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
				}
				return nil
			})
	})

	t.Run("NamedConfigSelectedByRule", func(t *testing.T) {
		h.Eventually(t, "the channel header to select the beta config",
			harness.DecisionBudget, func(ctx context.Context) error {
				res, err := h.HTTP().R().SetContext(ctx).
					SetHeader("X-E2E-Channel", "beta").
					Get(v.url("/"))
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusAccepted {
					return errUnexpectedStatus(res.StatusCode(), http.StatusAccepted)
				}
				if got := string(res.Body()); got != "beta" {
					return errors.Errorf("got body %q, want %q", got, "beta")
				}
				return nil
			})
	})
}

func testVigilDynamicConfigValidation(t *testing.T, h *harness.H) {
	v := newVigilCtx(t, h)
	var fallback atomic.Int64
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dynamic/invalid" {
			fallback.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	})
	c := h.HTTPNoRetry()
	t.Cleanup(c.GetClient().CloseIdleConnections)
	for _, engine := range []string{"CEL", "OPA"} {
		if !t.Run(engine, func(t *testing.T) {
			rule := &corev1.Service_Spec_DynamicConfig_Rule{
				Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: `ctx.request.http.path.startsWith("/dynamic/")`}},
			}
			if engine == "CEL" {
				rule.Type = &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: `{"parent": ctx.request.http.headers["x-e2e-config"]}`}
			} else {
				rule.Type = &corev1.Service_Spec_DynamicConfig_Rule_Opa{Opa: "package octelium.eval\nresult := {\"parent\": input.ctx.request.http.headers[\"x-e2e-config\"]}"}
			}
			v.svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
				Configs: []*corev1.Service_Spec_Config{{
					Name: "selected", Upstream: v.svc.Spec.Config.Upstream,
					Type: &corev1.Service_Spec_Config_Http{Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{{
							Name:      "selected",
							Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_{Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{
								StatusCode: http.StatusAccepted,
								Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{Inline: "selected"},
								},
							}},
						}},
					}},
				}},
				Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
					rule,
					{Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
						Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "default"}},
				},
			}
			v.svc = h.UpdateService(t, v.svc)
			check := func(ctx context.Context) error {
				for _, tc := range []struct {
					path   string
					parent string
					status int
				}{
					{"/dynamic/valid", "selected", http.StatusAccepted},
					{"/dynamic/invalid", "missing", http.StatusInternalServerError},
					{"/", "", http.StatusOK},
				} {
					res, err := c.R().SetContext(ctx).SetHeader("X-E2E-Config", tc.parent).Get(v.url(tc.path))
					if err != nil {
						return err
					}
					if res.StatusCode() != tc.status {
						return errUnexpectedStatus(res.StatusCode(), tc.status)
					}
					if tc.status == http.StatusAccepted && string(res.Body()) != "selected" {
						return errors.Errorf("got body %q, want selected", res.Body())
					}
				}
				return nil
			}
			var stableAt time.Time
			h.Eventually(t, "dynamic configuration validation errors to stop requests", harness.DecisionBudget,
				func(ctx context.Context) error {
					if err := check(ctx); err != nil {
						stableAt = time.Time{}
						return err
					}
					if stableAt.IsZero() {
						stableAt = time.Now()
					}
					if time.Since(stableAt) < decisionSettle {
						return errors.New("the dynamic configuration responses are still settling")
					}
					return nil
				})
			fallback.Store(0)
			h.Consistently(t, "invalid dynamic configurations to leave the default upstream unreachable", decisionSettle, check)
			assert.Zero(t, fallback.Load())
		}) {
			return
		}
	}
}

func testVigilServiceState(t *testing.T, h *harness.H) {
	v := newVigilCtx(t, h)
	v.record(t, http.StatusOK, "")

	v.waitStatusAt(t, "/", http.StatusOK)

	t.Run("IsDisabled", func(t *testing.T) {
		v.svc.Spec.IsDisabled = true
		v.svc = h.UpdateService(t, v.svc)

		disable := h.Within(t, "the disabled Service to stop serving", harness.DecisionBudget,
			func(ctx context.Context) error {
				res, err := h.HTTPNoRetry().R().SetContext(ctx).Get(v.url("/"))
				if err != nil {
					return nil
				}
				if res.StatusCode() == http.StatusOK {
					return errStillAllowed
				}
				return nil
			})

		v.svc.Spec.IsDisabled = false
		v.svc = h.UpdateService(t, v.svc)

		enable := h.Within(t, "the re-enabled Service to serve again", harness.DecisionBudget,
			func(ctx context.Context) error {
				res, err := h.HTTPNoRetry().R().SetContext(ctx).Get(v.url("/"))
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
				}
				return nil
			})

		zap.L().Info("Service state propagation",
			zap.Duration("disable", disable), zap.Duration("enable", enable))

		assert.Less(t, disable, propagationBudget,
			"disabling a Service took %s, budget is %s", disable, propagationBudget)
	})

	t.Run("UpstreamFailure", func(t *testing.T) {
		v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		})

		res, err := h.HTTP().
			SetRetryCount(0).
			R().SetContext(t.Context()).Get(v.url("/"))
		require.Nil(t, err)
		assert.Equal(t, http.StatusBadGateway, res.StatusCode())
	})
}
