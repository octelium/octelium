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
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
)

func (h *H) CreateNamespace(t *testing.T, ns *corev1.Namespace) *corev1.Namespace {
	t.Helper()

	if ns == nil {
		ns = &corev1.Namespace{}
	}
	if ns.Metadata == nil {
		ns.Metadata = &metav1.Metadata{}
	}
	if ns.Metadata.Name == "" {
		ns.Metadata.Name = h.Name()
	}
	if ns.Spec == nil {
		ns.Spec = &corev1.Namespace_Spec{}
	}

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.CreateNamespace(ctx, ns)
	if err != nil {
		t.Fatalf("Could not create the Namespace %s: %+v", ns.Metadata.Name, err)
	}

	t.Cleanup(func() {
		h.deleteQuietly(t, "Namespace", ret.Metadata.Name, func(ctx context.Context) error {
			_, err := h.coreC.DeleteNamespace(ctx, &metav1.DeleteOptions{Uid: ret.Metadata.Uid})
			return err
		})
	})

	zap.L().Debug("Created Namespace fixture", zap.String("name", ret.Metadata.Name))
	return ret
}

func (h *H) EnsureTestNamespace(t *testing.T) *corev1.Namespace {
	t.Helper()

	name := scenario.TestNamespace

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ns, err := h.coreC.GetNamespace(ctx, &metav1.GetOptions{Name: name})
	if err != nil {
		if !grpcerr.IsNotFound(err) {
			t.Fatalf("Could not read the test Namespace %s: %+v", name, err)
		}

		ns, err = h.coreC.CreateNamespace(ctx, &corev1.Namespace{
			Metadata: &metav1.Metadata{Name: name},
			Spec:     &corev1.Namespace_Spec{},
		})
		if err != nil {
			t.Fatalf("Could not create the test Namespace %s: %+v", name, err)
		}
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		cur, err := h.coreC.GetNamespace(ctx, &metav1.GetOptions{Name: name})
		if err != nil {
			return
		}
		if cur.Spec.Authorization == nil {
			return
		}

		cur.Spec.Authorization = nil
		if _, err := h.coreC.UpdateNamespace(ctx, cur); err != nil {
			zap.L().Warn("Could not reset the test Namespace authorization",
				zap.String("namespace", name), zap.Error(err))
		}
	})

	return ns
}

func (h *H) UpdateNamespace(t *testing.T, ns *corev1.Namespace) *corev1.Namespace {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.UpdateNamespace(ctx, ns)
	if err != nil {
		t.Fatalf("Could not update the Namespace %s: %+v", ns.Metadata.Name, err)
	}

	return ret
}

func (h *H) CreateGroup(t *testing.T, grp *corev1.Group) *corev1.Group {
	t.Helper()

	if grp == nil {
		grp = &corev1.Group{}
	}
	if grp.Metadata == nil {
		grp.Metadata = &metav1.Metadata{}
	}
	if grp.Metadata.Name == "" {
		grp.Metadata.Name = h.Name()
	}
	if grp.Spec == nil {
		grp.Spec = &corev1.Group_Spec{}
	}

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.CreateGroup(ctx, grp)
	if err != nil {
		t.Fatalf("Could not create the Group %s: %+v", grp.Metadata.Name, err)
	}

	t.Cleanup(func() {
		h.deleteQuietly(t, "Group", ret.Metadata.Name, func(ctx context.Context) error {
			_, err := h.coreC.DeleteGroup(ctx, &metav1.DeleteOptions{Uid: ret.Metadata.Uid})
			return err
		})
	})

	zap.L().Debug("Created Group fixture", zap.String("name", ret.Metadata.Name))
	return ret
}

func (h *H) CreatePolicy(t *testing.T, policy *corev1.Policy) *corev1.Policy {
	t.Helper()

	if policy.Metadata == nil {
		policy.Metadata = &metav1.Metadata{}
	}
	if policy.Metadata.Name == "" {
		policy.Metadata.Name = h.Name()
	}

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Could not create the Policy %s: %+v", policy.Metadata.Name, err)
	}

	t.Cleanup(func() {
		h.deleteQuietly(t, "Policy", ret.Metadata.Name, func(ctx context.Context) error {
			_, err := h.coreC.DeletePolicy(ctx, &metav1.DeleteOptions{Uid: ret.Metadata.Uid})
			return err
		})
	})

	zap.L().Debug("Created Policy fixture", zap.String("name", ret.Metadata.Name))
	return ret
}

func (h *H) UpdatePolicy(t *testing.T, policy *corev1.Policy) *corev1.Policy {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.UpdatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("Could not update the Policy %s: %+v", policy.Metadata.Name, err)
	}

	return ret
}

func (h *H) CreateIdentityProvider(t *testing.T,
	idp *corev1.IdentityProvider) *corev1.IdentityProvider {
	t.Helper()

	if idp.Metadata == nil {
		idp.Metadata = &metav1.Metadata{}
	}
	if idp.Metadata.Name == "" {
		idp.Metadata.Name = h.Name()
	}

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.CreateIdentityProvider(ctx, idp)
	if err != nil {
		t.Fatalf("Could not create the IdentityProvider %s: %+v", idp.Metadata.Name, err)
	}

	t.Cleanup(func() {
		h.deleteQuietly(t, "IdentityProvider", ret.Metadata.Name, func(ctx context.Context) error {
			_, err := h.coreC.DeleteIdentityProvider(ctx,
				&metav1.DeleteOptions{Uid: ret.Metadata.Uid})
			return err
		})
	})

	zap.L().Debug("Created IdentityProvider fixture", zap.String("name", ret.Metadata.Name))
	return ret
}

func (h *H) UserSessions(t *testing.T, usr *corev1.User) []*corev1.Session {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	sessList, err := h.coreC.ListSession(ctx, &corev1.ListSessionOptions{
		UserRef: umetav1.GetObjectReference(usr),
		Common: &metav1.CommonListOptions{
			OrderBy: &metav1.CommonListOptions_OrderBy{
				Type: metav1.CommonListOptions_OrderBy_CREATED_AT,
				Mode: metav1.CommonListOptions_OrderBy_ASC,
			},
		},
	})
	if err != nil {
		t.Fatalf("Could not list the Sessions of the User %s: %+v", usr.Metadata.Name, err)
	}

	return sessList.Items
}

func (h *H) UpdateSession(t *testing.T, sess *corev1.Session) *corev1.Session {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.UpdateSession(ctx, sess)
	if err != nil {
		t.Fatalf("Could not update the Session %s: %+v", sess.Metadata.Name, err)
	}

	return ret
}

func (h *H) DeleteSession(t *testing.T, sess *corev1.Session) {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	_, err := h.coreC.DeleteSession(ctx, &metav1.DeleteOptions{Uid: sess.Metadata.Uid})
	if err != nil {
		t.Fatalf("Could not delete the Session %s: %+v", sess.Metadata.Name, err)
	}
}

func AllowAnyRule(name string, priority int32) *corev1.Policy_Spec_Rule {
	return &corev1.Policy_Spec_Rule{
		Name:      name,
		Priority:  priority,
		Effect:    corev1.Policy_Spec_Rule_ALLOW,
		Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
	}
}

func DenyAnyRule(name string, priority int32) *corev1.Policy_Spec_Rule {
	return &corev1.Policy_Spec_Rule{
		Name:      name,
		Priority:  priority,
		Effect:    corev1.Policy_Spec_Rule_DENY,
		Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
	}
}

func MatchRule(name string, priority int32,
	effect corev1.Policy_Spec_Rule_Effect, expr string) *corev1.Policy_Spec_Rule {
	return &corev1.Policy_Spec_Rule{
		Name:      name,
		Priority:  priority,
		Effect:    effect,
		Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: expr}},
	}
}

func InlineAllowAny(name string) []*corev1.InlinePolicy {
	return []*corev1.InlinePolicy{
		{
			Name: name,
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{AllowAnyRule("allow", 0)},
			},
		},
	}
}
