//go:build e2e

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

package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

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
						Match: `has(ctx.request.http.headers["x-e2e-channel"]) && ` +
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

func testVigilServiceState(t *testing.T, h *harness.H) {
	v := newVigilCtx(t, h)
	v.record(t, http.StatusOK, "")

	v.waitStatusAt(t, "/", http.StatusOK)

	t.Run("IsDisabled", func(t *testing.T) {
		v.svc.Spec.IsDisabled = true
		v.svc = h.UpdateService(t, v.svc)

		disable := h.Within(t, "the disabled Service to stop serving", harness.DecisionBudget,
			func(ctx context.Context) error {
				res, err := h.HTTP().R().SetContext(ctx).Get(v.url("/"))
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
				res, err := h.HTTP().R().SetContext(ctx).Get(v.url("/"))
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
