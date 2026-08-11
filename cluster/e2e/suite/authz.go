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
	"net/http"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
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
