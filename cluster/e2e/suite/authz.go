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
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testAuthorization(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)

	ns := h.EnsureTestNamespace(t)
	svc := h.NewPublicService(t, ns.Metadata.Name)
	usr := h.CreateWorkloadUser(t, nil)

	token := h.AccessToken(t, usr)
	c := h.ServiceClient(svc, token)

	clearAuthz := func(t *testing.T) {
		t.Helper()

		svc.Spec.Authorization = nil
		svc = h.UpdateService(t, svc)

		ns.Spec.Authorization = nil
		ns = h.UpdateNamespace(t, ns)

		usr.Spec.Authorization = nil
		usr.Spec.Groups = nil
		usr = h.UpdateUser(t, usr)
	}

	t.Run("DefaultDeny", func(t *testing.T) {
		h.WaitDenied(t, c)
	})

	t.Run("ClusterConfigGlobalPolicy", func(t *testing.T) {
		h.WaitDenied(t, c)

		sessions := h.UserSessions(t, usr)
		require.Equal(t, 1, len(sessions))
		sess := sessions[0]

		cc := h.ClusterConfig(t)
		original := cc.Spec.Authorization

		t.Cleanup(func() {
			cc := h.ClusterConfig(t)
			cc.Spec.Authorization = original
			h.UpdateClusterConfig(t, cc)
		})

		authz := &corev1.ClusterConfig_Spec_Authorization{}
		if original != nil {
			authz.Policies = append(authz.Policies, original.Policies...)
			authz.InlinePolicies = append(authz.InlinePolicies, original.InlinePolicies...)
		}
		authz.InlinePolicies = append(authz.InlinePolicies, &corev1.InlinePolicy{
			Name: "allow-e2e-session",
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					harness.MatchRule("allow-e2e-session", 0,
						corev1.Policy_Spec_Rule_ALLOW,
						fmt.Sprintf(`ctx.user.metadata.uid == %q && ctx.session.metadata.uid == %q`,
							usr.Metadata.Uid, sess.Metadata.Uid)),
				},
			},
		})

		cc.Spec.Authorization = authz
		cc = h.UpdateClusterConfig(t, cc)

		grant := h.WaitAllowed(t, c)

		cc = h.ClusterConfig(t)
		cc.Spec.Authorization = original
		h.UpdateClusterConfig(t, cc)

		revoke := h.WaitDenied(t, c)

		zap.L().Info("ClusterConfig global Policy propagation",
			zap.Duration("grant", grant), zap.Duration("revoke", revoke))

		assert.Less(t, grant, propagationBudget,
			"granting access with a ClusterConfig Policy took %s, budget is %s",
			grant, propagationBudget)
		assert.Less(t, revoke, propagationBudget,
			"removing a ClusterConfig Policy took %s, budget is %s",
			revoke, propagationBudget)
	})

	t.Run("ServiceInlinePolicy", func(t *testing.T) {
		t.Cleanup(func() { clearAuthz(t) })

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow-service"),
		}
		svc = h.UpdateService(t, svc)

		h.WaitAllowed(t, c)
	})

	t.Run("NamespaceInlinePolicy", func(t *testing.T) {
		t.Cleanup(func() { clearAuthz(t) })

		h.WaitDenied(t, c)

		ns.Spec.Authorization = &corev1.Namespace_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow-namespace"),
		}
		ns = h.UpdateNamespace(t, ns)

		h.WaitAllowed(t, c)
	})

	t.Run("UserStandalonePolicy", func(t *testing.T) {
		t.Cleanup(func() { clearAuthz(t) })

		policy := h.CreatePolicy(t, &corev1.Policy{
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{harness.AllowAnyRule("allow", 0)},
			},
		})

		usr.Spec.Authorization = &corev1.User_Spec_Authorization{
			Policies: []string{policy.Metadata.Name},
		}
		usr = h.UpdateUser(t, usr)

		h.WaitAllowed(t, c)

		t.Run("DisablingThePolicyRevokesAccess", func(t *testing.T) {
			policy.Spec.IsDisabled = true
			policy = h.UpdatePolicy(t, policy)

			h.WaitDenied(t, c)
		})
	})

	t.Run("GroupPolicy", func(t *testing.T) {
		t.Cleanup(func() { clearAuthz(t) })

		grp := h.CreateGroup(t, &corev1.Group{
			Spec: &corev1.Group_Spec{
				Authorization: &corev1.Group_Spec_Authorization{
					InlinePolicies: harness.InlineAllowAny("allow-group"),
				},
			},
		})

		h.WaitDenied(t, c)

		usr.Spec.Groups = []string{grp.Metadata.Name}
		usr = h.UpdateUser(t, usr)

		h.WaitAllowed(t, c)
	})

	t.Run("SessionPolicy", func(t *testing.T) {
		t.Cleanup(func() { clearAuthz(t) })

		sessions := h.UserSessions(t, usr)
		require.True(t, len(sessions) > 0, "the User has no Session to attach a Policy to")

		sess := sessions[len(sessions)-1]
		sess.Spec.Authorization = &corev1.Session_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow-session"),
		}
		sess = h.UpdateSession(t, sess)

		h.WaitAllowed(t, c)

		t.Cleanup(func() {
			sess.Spec.Authorization = nil
			h.UpdateSession(t, sess)
		})
	})

	t.Run("Priority", func(t *testing.T) {
		t.Cleanup(func() { clearAuthz(t) })

		usr.Spec.Authorization = &corev1.User_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Name: "priority",
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							harness.DenyAnyRule("deny-low-priority", 2),
							harness.AllowAnyRule("allow-high-priority", -2),
						},
					},
				},
			},
		}
		usr = h.UpdateUser(t, usr)

		h.WaitAllowed(t, c)
	})

	t.Run("DenyWinsAtEqualPriority", func(t *testing.T) {
		t.Cleanup(func() { clearAuthz(t) })

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow-service"),
		}
		svc = h.UpdateService(t, svc)

		usr.Spec.Authorization = &corev1.User_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Name: "deny",
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{harness.DenyAnyRule("deny", 0)},
					},
				},
			},
		}
		usr = h.UpdateUser(t, usr)

		h.WaitDenied(t, c)

		h.Consistently(t, "the denial to hold", 3*decisionSettle,
			func(ctx context.Context) error {
				got, err := h.StatusOf(ctx, c, "/")
				if err != nil {
					return err
				}
				if got != http.StatusForbidden {
					return errUnexpectedStatus(got, http.StatusForbidden)
				}
				return nil
			})
	})

	t.Run("ConditionOnRequest", func(t *testing.T) {
		t.Cleanup(func() { clearAuthz(t) })

		usr.Spec.Authorization = &corev1.User_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Name: "path-scoped",
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							harness.MatchRule("allow-allowed-prefix", 0,
								corev1.Policy_Spec_Rule_ALLOW,
								`ctx.request.http.path.startsWith("/allowed")`),
						},
					},
				},
			},
		}
		usr = h.UpdateUser(t, usr)

		h.WaitStatus(t, c, "/allowed/page", http.StatusNotFound)
		h.WaitStatus(t, c, "/denied/page", http.StatusForbidden)
	})

	t.Run("EnforcementRules", func(t *testing.T) {
		t.Cleanup(func() { clearAuthz(t) })

		usr.Spec.Authorization = &corev1.User_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Name: "enforced",
					Spec: &corev1.Policy_Spec{
						EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{
							{
								Effect: corev1.Policy_Spec_EnforcementRule_IGNORE,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `ctx.request.http.path.startsWith("/ignored")`,
									},
								},
							},
						},
						Rules: []*corev1.Policy_Spec_Rule{harness.AllowAnyRule("allow", 0)},
					},
				},
			},
		}
		usr = h.UpdateUser(t, usr)

		h.WaitStatus(t, c, "/", http.StatusOK)
		h.WaitStatus(t, c, "/ignored/page", http.StatusForbidden)
	})

	t.Run("Propagation", func(t *testing.T) {
		t.Cleanup(func() { clearAuthz(t) })

		usr.Spec.Authorization = &corev1.User_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow"),
		}
		usr = h.UpdateUser(t, usr)
		h.WaitAllowed(t, c)

		usr.Spec.Authorization = nil
		usr = h.UpdateUser(t, usr)

		revoke := h.WaitDenied(t, c)

		usr.Spec.Authorization = &corev1.User_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow"),
		}
		usr = h.UpdateUser(t, usr)

		grant := h.WaitAllowed(t, c)

		zap.L().Info("Authorization propagation",
			zap.Duration("revoke", revoke), zap.Duration("grant", grant))

		assert.Less(t, revoke, propagationBudget,
			"revoking access took %s, budget is %s", revoke, propagationBudget)
		assert.Less(t, grant, propagationBudget,
			"granting access took %s, budget is %s", grant, propagationBudget)
	})
}

func testAuthorizationRevocationLoad(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	ns := h.EnsureTestNamespace(t)
	svc := h.NewPublicService(t, ns.Metadata.Name)
	policy := h.CreatePolicy(t, &corev1.Policy{Spec: &corev1.Policy_Spec{
		Rules: []*corev1.Policy_Spec_Rule{harness.AllowAnyRule("allow-group", 0)},
	}})
	group := h.CreateGroup(t, &corev1.Group{Spec: &corev1.Group_Spec{
		Authorization: &corev1.Group_Spec_Authorization{Policies: []string{policy.Metadata.Name}},
	}})
	usr := h.CreateWorkloadUser(t, nil)
	usr.Spec.Groups = []string{group.Metadata.Name}
	usr = h.UpdateUser(t, usr)
	other := h.CreateWorkloadUser(t, nil)
	tokens := []string{h.AccessToken(t, usr), h.AccessToken(t, other)}
	clients := []func(context.Context) (int, error){}
	for _, token := range tokens {
		client := h.HTTPNoRetry().SetBaseURL(h.ServiceURL(svc)).SetAuthScheme("Bearer").SetAuthToken(token)
		t.Cleanup(client.GetClient().CloseIdleConnections)
		clients = append(clients, func(ctx context.Context) (int, error) { return h.StatusOf(ctx, client, "/") })
	}
	h.Eventually(t, "only the group member to reach the Service", harness.DecisionBudget, func(ctx context.Context) error {
		for idx, check := range clients {
			status, err := check(ctx)
			if err != nil {
				return err
			}
			want := http.StatusOK
			if idx == 1 {
				want = http.StatusForbidden
			}
			if status != want {
				return errUnexpectedStatus(status, want)
			}
		}
		return nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	var phase atomic.Int64
	var violations atomic.Int64
	var completed [2]atomic.Int64
	done := make(chan *harness.PoolResult, 1)
	go func() {
		done <- harness.RunFor(ctx, 5*time.Minute, 16, func(ctx context.Context, worker, iteration int) error {
			idx := worker % len(clients)
			before := phase.Load()
			callCtx, callCancel := context.WithTimeout(ctx, 10*time.Second)
			defer callCancel()
			status, err := clients[idx](callCtx)
			if err != nil {
				return err
			}
			completed[idx].Add(1)
			want := http.StatusForbidden
			if idx == 0 {
				if before == 0 || before != phase.Load() {
					if status == http.StatusOK || status == http.StatusForbidden {
						return nil
					}
				} else if before&1 == 0 {
					want = http.StatusOK
				}
			}
			if status != want {
				violations.Add(1)
				return errUnexpectedStatus(status, want)
			}
			return nil
		})
	}()
	var result *harness.PoolResult
	stop := func() {
		cancel()
		if result == nil {
			select {
			case result = <-done:
			case <-time.After(15 * time.Second):
				assert.Fail(t, "the authorization load did not stop")
			}
		}
	}
	t.Cleanup(stop)
	var generation int64
	waitDecision := func(t *testing.T, want int) {
		t.Helper()
		var stableAt time.Time
		h.Eventually(t, "authorization to converge under request load", harness.DecisionBudget,
			func(ctx context.Context) error {
				for idx, check := range clients {
					status, err := check(ctx)
					expected := want
					if idx == 1 {
						expected = http.StatusForbidden
					}
					if err != nil || status != expected {
						stableAt = time.Time{}
						if err != nil {
							return err
						}
						return errUnexpectedStatus(status, expected)
					}
				}
				if stableAt.IsZero() {
					stableAt = time.Now()
				}
				if time.Since(stableAt) < decisionSettle {
					return fmt.Errorf("the authorization decision is still settling")
				}
				return nil
			})
		generation++
		current := generation << 1
		if want == http.StatusForbidden {
			current |= 1
		}
		before := [2]int64{completed[0].Load(), completed[1].Load()}
		phase.Store(current)
		h.Eventually(t, "both identities to make requests with the stable authorization decision", harness.DecisionBudget,
			func(ctx context.Context) error {
				if violations.Load() > 0 {
					return fmt.Errorf("unexpected authorization decisions were observed")
				}
				if completed[0].Load()-before[0] < 32 || completed[1].Load()-before[1] < 32 {
					return fmt.Errorf("both identities have not completed enough requests")
				}
				return nil
			})
	}
	waitDecision(t, http.StatusOK)
	for _, step := range []string{"RemoveGroup", "RestoreGroup", "DisablePolicy", "EnablePolicy", "DisableUser", "EnableUser"} {
		if !t.Run(step, func(t *testing.T) {
			phase.Store(0)
			want := http.StatusForbidden
			switch step {
			case "RemoveGroup":
				usr.Spec.Groups = nil
				usr = h.UpdateUser(t, usr)
			case "RestoreGroup":
				usr.Spec.Groups = []string{group.Metadata.Name}
				usr = h.UpdateUser(t, usr)
				want = http.StatusOK
			case "DisablePolicy", "EnablePolicy":
				policy.Spec.IsDisabled = step == "DisablePolicy"
				policy = h.UpdatePolicy(t, policy)
				if !policy.Spec.IsDisabled {
					want = http.StatusOK
				}
			case "DisableUser", "EnableUser":
				usr.Spec.IsDisabled = step == "DisableUser"
				usr = h.UpdateUser(t, usr)
				if !usr.Spec.IsDisabled {
					want = http.StatusOK
				}
			}
			waitDecision(t, want)
		}) {
			return
		}
	}
	stop()
	require.NotNil(t, result)
	assert.Zero(t, violations.Load())
	assert.Zero(t, result.Failed(), "%s", result.Errors.String())
	assert.Positive(t, result.Succeeded)
	harness.LogPool("Octovigil authorization changes under HTTP load", result)
}

func testAuthorizationPolicyLookupCompatibility(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	ns := h.EnsureTestNamespace(t)
	svc := h.NewPublicService(t, ns.Metadata.Name)
	usr := h.CreateWorkloadUser(t, nil)
	c := h.ServiceClient(svc, h.AccessToken(t, usr))
	parent := h.CreatePolicy(t, &corev1.Policy{Spec: &corev1.Policy_Spec{
		Rules: []*corev1.Policy_Spec_Rule{harness.AllowAnyRule("allow-parent", 0)},
	}})
	child := h.CreatePolicy(t, &corev1.Policy{
		Metadata: &metav1.Metadata{Name: "child." + parent.Metadata.Name},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{harness.DenyAnyRule("deny-child", 0)},
		},
	})
	svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
		Policies: []string{child.Metadata.Name}, InlinePolicies: harness.InlineAllowAny("allow-service"),
	}
	svc = h.UpdateService(t, svc)
	h.WaitDenied(t, c)

	_, err := h.CoreC().DeletePolicy(t.Context(), &metav1.DeleteOptions{Uid: child.Metadata.Uid})
	require.Nil(t, err)
	h.WaitAllowed(t, c)

	parent.Spec.Rules = []*corev1.Policy_Spec_Rule{harness.DenyAnyRule("deny-parent", 0)}
	parent = h.UpdatePolicy(t, parent)
	h.WaitDenied(t, c)

	_, err = h.CoreC().DeletePolicy(t.Context(), &metav1.DeleteOptions{Uid: parent.Metadata.Uid})
	require.Nil(t, err)
	h.WaitAllowed(t, c)

	parent = h.CreatePolicy(t, &corev1.Policy{
		Metadata: &metav1.Metadata{Name: parent.Metadata.Name},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{harness.DenyAnyRule("deny-parent", 0)},
		},
	})
	h.WaitDenied(t, c)
	h.Consistently(t, "the recreated parent Policy to deny access through the deleted child reference", decisionSettle,
		func(ctx context.Context) error {
			status, err := h.StatusOf(ctx, c, "/")
			if err != nil {
				return err
			}
			if status != http.StatusForbidden {
				return errUnexpectedStatus(status, http.StatusForbidden)
			}
			return nil
		})
}

func testAuthorizationCommonEngineIsolation(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	ns := h.EnsureTestNamespace(t)
	svc := h.NewPublicService(t, ns.Metadata.Name)
	users := []*corev1.User{h.CreateWorkloadUser(t, nil), h.CreateWorkloadUser(t, nil)}
	tokens := []string{h.AccessToken(t, users[0]), h.AccessToken(t, users[1])}

	for _, engine := range []string{"CEL", "OPA"} {
		t.Run(engine, func(t *testing.T) {
			condition := &corev1.Condition{Type: &corev1.Condition_Match{Match: `ctx.request.http.headers["x-e2e-user"] == ctx.user.metadata.uid && ctx.request.http.headers["x-e2e-decision"] == "allow"`}}
			if engine == "OPA" {
				condition = &corev1.Condition{Type: &corev1.Condition_Opa{Opa: &corev1.Condition_OPA{Type: &corev1.Condition_OPA_Inline{Inline: `package octelium.condition
match if {
	input.ctx.request.http.headers["x-e2e-user"] == input.ctx.user.metadata.uid
	input.ctx.request.http.headers["x-e2e-decision"] == "allow"
}`}}}}
			}
			policy := h.CreatePolicy(t, &corev1.Policy{Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{Name: "allow-matching-user", Effect: corev1.Policy_Spec_Rule_ALLOW, Condition: condition}}}})
			svc.Spec.Authorization = &corev1.Service_Spec_Authorization{Policies: []string{policy.Metadata.Name}}
			svc = h.UpdateService(t, svc)
			clients := make([]*resty.Client, len(users))
			for i, token := range tokens {
				clients[i] = h.HTTPNoRetry().SetBaseURL(h.ServiceURL(svc)).SetAuthScheme("Bearer").SetAuthToken(token)
				t.Cleanup(clients[i].GetClient().CloseIdleConnections)
			}
			check := func(ctx context.Context, user, scenario int) error {
				req := clients[user].R().SetContext(ctx)
				uid, decision := users[user].Metadata.Uid, "allow"
				want := http.StatusForbidden
				switch scenario {
				case 0:
					want = http.StatusOK
				case 1:
					uid = users[1-user].Metadata.Uid
				case 2:
					uid = ""
				case 3:
					decision = "ALLOW"
				case 4:
					decision = `allow" || true || "`
				case 5:
					decision = ""
				}
				if scenario != 6 {
					req.SetHeader("X-E2E-User", uid).SetHeader("X-E2E-Decision", decision)
				}
				resp, err := req.Get("/")
				if err != nil {
					return err
				}
				if resp.StatusCode() != want {
					return fmt.Errorf("%s user %d scenario %d: %w", engine, user, scenario, errUnexpectedStatus(resp.StatusCode(), want))
				}
				return nil
			}
			h.Eventually(t, "both identities to have request-specific authorization decisions", harness.DecisionBudget, func(ctx context.Context) error {
				for user := range users {
					for scenario := range 7 {
						if err := check(ctx, user, scenario); err != nil {
							return err
						}
					}
				}
				return nil
			})
			result := harness.RunFor(t.Context(), 3*time.Second, 16, func(ctx context.Context, worker, iteration int) error {
				return check(ctx, worker%len(users), iteration%7)
			})
			assert.Zero(t, result.Failed(), "%s", result.Errors.String())
			assert.Positive(t, result.Succeeded)
			harness.LogPool(engine+" authorization request isolation", result)
		})
	}
}

func testAuthorizationOPAQueryCache(t *testing.T, h *harness.H) {
	h.Require(t, capHostPortIngress)
	ns := h.EnsureTestNamespace(t)
	svc := h.NewPublicService(t, ns.Metadata.Name)
	usr := h.CreateWorkloadUser(t, nil)
	const script = `package octelium
default condition := {"match": false}
condition := {"match": true} if {
	input.ctx.request.http.headers["x-e2e-access"] == "allow"
}
eval := {"result": {"parent": input.ctx.request.http.headers["x-e2e-config"]}}`
	policy := h.CreatePolicy(t, &corev1.Policy{Spec: &corev1.Policy_Spec{
		Rules: []*corev1.Policy_Spec_Rule{{
			Name: "allow-request", Effect: corev1.Policy_Spec_Rule_ALLOW,
			Condition: &corev1.Condition{Type: &corev1.Condition_Opa{Opa: &corev1.Condition_OPA{
				Type: &corev1.Condition_OPA_Inline{Inline: script},
			}}},
		}},
	}})
	svc.Spec.Authorization = &corev1.Service_Spec_Authorization{Policies: []string{policy.Metadata.Name}}
	svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
		Configs: []*corev1.Service_Spec_Config{{
			Name: "selected", Upstream: svc.Spec.Config.Upstream,
			Type: &corev1.Service_Spec_Config_Http{Http: &corev1.Service_Spec_Config_HTTP{
				Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{{
					Name: "selected", Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
					Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_{Direct: &corev1.Service_Spec_Config_HTTP_Plugin_Direct{
						StatusCode: http.StatusAccepted,
						Body: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body{
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Direct_Body_Inline{Inline: "selected"},
						},
					}},
				}},
			}},
		}},
		Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{
			Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
			Type:      &corev1.Service_Spec_DynamicConfig_Rule_Opa{Opa: script},
		}},
	}
	svc = h.UpdateService(t, svc)
	c := h.HTTPNoRetry().SetBaseURL(h.ServiceURL(svc)).SetAuthScheme("Bearer").SetAuthToken(h.AccessToken(t, usr))
	t.Cleanup(c.GetClient().CloseIdleConnections)
	cases := []struct {
		access, config string
		status         int
	}{
		{"allow", "selected", http.StatusAccepted},
		{"deny", "selected", http.StatusForbidden},
		{"allow", "default", http.StatusOK},
		{"deny", "default", http.StatusForbidden},
		{"", "selected", http.StatusForbidden},
	}
	check := func(ctx context.Context, idx int) error {
		tc := cases[idx]
		res, err := c.R().SetContext(ctx).SetHeader("X-E2E-Access", tc.access).SetHeader("X-E2E-Config", tc.config).Get("/")
		if err != nil {
			return err
		}
		if res.StatusCode() != tc.status {
			return errUnexpectedStatus(res.StatusCode(), tc.status)
		}
		if tc.status == http.StatusAccepted && string(res.Body()) != "selected" {
			return fmt.Errorf("got body %q, want selected", res.Body())
		}
		return nil
	}
	var stableAt time.Time
	h.Eventually(t, "the shared Rego source to authorize requests and select their configurations independently", harness.DecisionBudget,
		func(ctx context.Context) error {
			for i := range cases {
				if err := check(ctx, i); err != nil {
					stableAt = time.Time{}
					return err
				}
			}
			if stableAt.IsZero() {
				stableAt = time.Now()
			}
			if time.Since(stableAt) < decisionSettle {
				return fmt.Errorf("the OPA query decisions are still settling")
			}
			return nil
		})
	result := harness.RunFor(t.Context(), 3*time.Second, 16, func(ctx context.Context, worker, iteration int) error {
		return check(ctx, (worker+iteration)%len(cases))
	})
	assert.Zero(t, result.Failed(), "%s", result.Errors.String())
	assert.Positive(t, result.Succeeded)
	harness.LogPool("OPA condition and dynamic configuration query isolation", result)
}
