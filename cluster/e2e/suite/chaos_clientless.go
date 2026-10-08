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
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const (
	chaosClientlessP95 = 3 * time.Second
	longLivedHold      = 20 * time.Second
	clientlessSessions = 200
)

type clientlessEnv struct {
	upstream *harness.CountingUpstream
	authz    *corev1.Service
	anon     *corev1.Service
	allowed  []string
	denied   []string
}

func (c *clientlessEnv) authzURL(h *harness.H) string { return h.ServiceURL(c.authz) + "/" }

func (c *clientlessEnv) anonURL(h *harness.H) string { return h.ServiceURL(c.anon) + "/" }

func (c *clientlessEnv) anonHost(h *harness.H) string {
	u, _ := url.Parse(h.ServiceURL(c.anon))
	return u.Hostname()
}

func newClientlessEnv(t *testing.T, e *chaosEnv) *clientlessEnv {
	t.Helper()

	h := e.h

	fleet, err := h.NewFleet(t.Context(), harness.FleetOpts{
		Sessions:    clientlessSessions,
		Users:       2,
		Concurrency: 16,
		SessionType: corev1.Session_Status_CLIENTLESS,
	})
	require.NoError(t, err)
	t.Cleanup(func() { fleet.Close(context.Background()) })

	allowedUser := fleet.Users[0]

	ret := &clientlessEnv{upstream: h.StartCountingUpstream(t, 4096)}

	for _, sess := range fleet.Sessions {
		if sess.User.Metadata.Uid == allowedUser.Metadata.Uid {
			ret.allowed = append(ret.allowed, sess.AccessToken)
		} else {
			ret.denied = append(ret.denied, sess.AccessToken)
		}
	}
	require.NotEmpty(t, ret.allowed)
	require.NotEmpty(t, ret.denied)

	upstreamCfg := &corev1.Service_Spec_Config{
		Upstream: &corev1.Service_Spec_Config_Upstream{
			Type: &corev1.Service_Spec_Config_Upstream_Url{Url: ret.upstream.URL()},
		},
	}

	ret.authz = h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{Name: fmt.Sprintf("chaos-authz-%s", utilrand.GetRandomStringCanonical(6))},
		Spec: &corev1.Service_Spec{
			Mode:     corev1.Service_Spec_HTTP,
			IsPublic: true,
			Config:   upstreamCfg,
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{{
					Name: "allow-one-user",
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							harness.MatchRule("allow-user", 0, corev1.Policy_Spec_Rule_ALLOW,
								fmt.Sprintf(`ctx.user.metadata.uid == %q`, allowedUser.Metadata.Uid)),
						},
					},
				}},
			},
		},
	})

	ret.anon = h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{Name: fmt.Sprintf("chaos-anon-%s", utilrand.GetRandomStringCanonical(6))},
		Spec: &corev1.Service_Spec{
			Mode:        corev1.Service_Spec_HTTP,
			IsPublic:    true,
			IsAnonymous: true,
			Config:      upstreamCfg,
		},
	})

	h.MustWaitService(t, ret.authz.Metadata.Name, ret.anon.Metadata.Name)

	h.WaitStatus(t, h.ServiceClient(ret.authz, ret.allowed[0]), "/", http.StatusOK)
	h.WaitStatus(t, h.ServiceClient(ret.authz, ret.denied[0]), "/", http.StatusForbidden)
	h.WaitStatus(t, h.ServiceClient(ret.anon, ""), "/", http.StatusOK)

	return ret
}

func (e *chaosEnv) assertLoad(t *testing.T, what string, res *harness.HTTPLoadResult,
	class string, want int, slo time.Duration) {
	t.Helper()

	e.set(t, what, res.String())

	if res.Errors.Total() > 0 {
		e.failf(t, "%s: %d requests failed at the transport: %s", what, res.Errors.Total(), res.Errors)
	}

	if other := res.CountOther(class, want); other > 0 {
		e.failf(t, "%s: %d responses were not %d: %v", what, other, want, res.Status(class))
	}

	if sum := res.ClassLatency(class); slo > 0 && sum.Count > 0 && sum.P95 > slo {
		e.failf(t, "%s: the p95 latency is %s, the budget is %s (%s)", what, sum.P95, slo, sum)
	}
}

func testChaosClientless(t *testing.T, e *chaosEnv) {
	h := e.h

	before := e.healthSnapshot(t)
	c := newClientlessEnv(t, e)

	t.Run("AuthenticatedStorm", func(t *testing.T) {
		res, err := h.HTTPLoad(t.Context(), harness.HTTPLoadOpts{
			URL:      c.authzURL(h),
			Workers:  e.scale.HTTPWorkers,
			Duration: e.scale.HTTPDuration,
			Request: func(worker, iteration int) harness.HTTPRequestSpec {
				return harness.HTTPRequestSpec{
					Token: c.allowed[(worker+iteration)%len(c.allowed)],
					Class: "allowed",
					ID:    fmt.Sprintf("storm-%d-%d", worker, iteration),
				}
			},
		})
		require.NoError(t, err)

		e.set(t, "requestsPerSecond", res.Rate())
		e.assertLoad(t, "storm", res, "allowed", http.StatusOK, chaosClientlessP95)

		if dupes := c.upstream.Duplicates(); len(dupes) > 0 {
			e.failf(t, "The upstream received %d requests more than once, e.g. %v",
				len(dupes), firstN(dupes, 5))
		}
		if got := c.upstream.SeenWithPrefix("storm-"); got != res.Count("allowed", http.StatusOK) {
			e.failf(t, "The upstream received %d storm requests but %d were answered with 200",
				got, res.Count("allowed", http.StatusOK))
		}
	})

	t.Run("AuthorizationIsolation", func(t *testing.T) {
		res, err := h.HTTPLoad(t.Context(), harness.HTTPLoadOpts{
			URL:      c.authzURL(h),
			Workers:  min(64, e.scale.HTTPWorkers),
			Requests: 3000,
			HTTP2:    true,
			Request: func(worker, iteration int) harness.HTTPRequestSpec {
				switch iteration % 3 {
				case 0:
					return harness.HTTPRequestSpec{
						Token: c.allowed[iteration%len(c.allowed)],
						Class: "allowed", ID: fmt.Sprintf("iso-allowed-%d", iteration),
					}
				case 1:
					return harness.HTTPRequestSpec{
						Token: c.denied[iteration%len(c.denied)],
						Class: "denied", ID: fmt.Sprintf("iso-denied-%d", iteration),
					}
				default:
					return harness.HTTPRequestSpec{
						Token: utilrand.GetRandomStringCanonical(160),
						Class: "forged", ID: fmt.Sprintf("iso-forged-%d", iteration),
					}
				}
			},
		})
		require.NoError(t, err)

		e.set(t, "requests", res.String())

		if res.Errors.Total() > 0 {
			e.failf(t, "%d multiplexed requests failed at the transport: %s", res.Errors.Total(), res.Errors)
		}

		for class, want := range map[string]int{
			"allowed": http.StatusOK,
			"denied":  http.StatusForbidden,
			"forged":  http.StatusUnauthorized,
		} {
			if other := res.CountOther(class, want); other > 0 {
				e.failf(t, "%d %s requests were not answered with %d: %v",
					other, class, want, res.Status(class))
			}
		}

		for _, prefix := range []string{"iso-denied-", "iso-forged-"} {
			if n := c.upstream.SeenWithPrefix(prefix); n > 0 {
				e.failf(t, "%d unauthorized requests (%s) reached the upstream", n, prefix)
			}
		}
	})

	t.Run("AnonymousTLSChurn", func(t *testing.T) {
		res, err := h.HTTPLoad(t.Context(), harness.HTTPLoadOpts{
			URL:               c.anonURL(h),
			Workers:           max(8, e.scale.HTTPWorkers/4),
			Duration:          max(20*time.Second, e.scale.HTTPDuration/2),
			NewConnPerRequest: true,
		})
		require.NoError(t, err)

		e.set(t, "handshakesPerSecond", res.Rate())
		e.assertLoad(t, "churn", res, "default", http.StatusOK, chaosClientlessP95)
	})

	t.Run("LongLivedConcurrency", func(t *testing.T) {
		n := e.scale.LongLived

		started := time.Now()
		res, err := h.HTTPLoad(t.Context(), harness.HTTPLoadOpts{
			URL:      c.anonURL(h),
			Workers:  n,
			Requests: n,
			Timeout:  longLivedHold + 90*time.Second,
			Request: func(worker, iteration int) harness.HTTPRequestSpec {
				return harness.HTTPRequestSpec{
					Class: "held",
					Path:  fmt.Sprintf("/?holdMs=%d", longLivedHold.Milliseconds()),
				}
			},
		})
		require.NoError(t, err)

		e.set(t, "concurrent", n)
		e.set(t, "elapsed", time.Since(started).String())
		e.set(t, "upstreamPeakInFlight", c.upstream.PeakInFlight())
		e.assertLoad(t, "held", res, "held", http.StatusOK, 0)

		if peak := c.upstream.PeakInFlight(); peak < int64(n)*9/10 {
			e.failf(t, "Only %d of %d long-lived requests were in flight at the upstream at once", peak, n)
		}
	})

	e.assertHealthy(t, before)
	e.logUsage(t)
}

func testChaosIngressAbuse(t *testing.T, e *chaosEnv) {
	h := e.h

	before := e.healthSnapshot(t)
	c := newClientlessEnv(t, e)
	host := c.anonHost(h)

	legit := func(t *testing.T, ctx context.Context, d time.Duration) (*harness.HTTPLoadResult, error) {
		return h.HTTPLoad(ctx, harness.HTTPLoadOpts{
			URL:      c.anonURL(h),
			Workers:  8,
			Duration: d,
		})
	}

	for _, tc := range []struct {
		name     string
		slowBody bool
		conns    int
		observe  time.Duration
	}{
		{name: "Slowloris", conns: e.scale.IdleStreams, observe: 30 * time.Second},
		{name: "SlowBody", slowBody: true, conns: max(10, e.scale.IdleStreams/2), observe: 45 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wg sync.WaitGroup
			var slow *harness.SlowClientResult
			var slowErr error

			wg.Add(1)
			go func() {
				defer wg.Done()
				slow, slowErr = h.SlowClients(t.Context(), host, tc.conns, tc.observe, tc.slowBody)
			}()

			harness.Sleep(t.Context(), 3*time.Second)
			res, err := legit(t, t.Context(), tc.observe-10*time.Second)
			require.NoError(t, err)

			wg.Wait()
			require.NoError(t, slowErr)

			e.set(t, "attack", slow.String())
			e.set(t, "stillOpenAtEnd", slow.Opened-slow.Closed)
			e.assertLoad(t, "legit", res, "default", http.StatusOK, chaosClientlessP95)

			zap.L().Info("Slow clients against the ingress",
				zap.String("kind", tc.name), zap.String("result", slow.String()))

			if !tc.slowBody {
				if slow.Closed < slow.Opened {
					e.failf(t, "The ingress kept %d of %d slowloris connections open for %s",
						slow.Opened-slow.Closed, slow.Opened, tc.observe)
				}
				if sum := slow.Lifetime.Summary(); sum.P99 > 15*time.Second {
					e.failf(t, "The ingress kept slowloris connections open for up to %s (%s)", sum.Max, sum)
				}
			}
		})
	}

	t.Run("Recovery", func(t *testing.T) {
		h.Eventually(t, "the ingress to serve normally after the abuse", time.Minute,
			func(ctx context.Context) error {
				res, err := legit(t, ctx, 5*time.Second)
				if err != nil {
					return err
				}
				if res.Errors.Total() > 0 || res.CountOther("default", http.StatusOK) > 0 {
					return errors.Errorf("%s", res)
				}
				return nil
			})
	})

	e.assertHealthy(t, before)
}
