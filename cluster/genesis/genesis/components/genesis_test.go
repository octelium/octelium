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

package components

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCreateGenesisIdentity(t *testing.T) {
	installer := rbacv1.Subject{Kind: "ServiceAccount", Name: "octelium-genesis", Namespace: "octelium"}
	initial := rbacv1.Subject{Kind: "ServiceAccount", Name: "octelium-genesis", Namespace: "default"}
	external := rbacv1.Subject{Kind: "User", Name: "admin", APIGroup: "rbac.authorization.k8s.io"}
	wildcard := []rbacv1.PolicyRule{{APIGroups: []string{"*", "*.*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}

	legacyInstall := func(subjects ...rbacv1.Subject) []runtime.Object {
		return []runtime.Object{
			&k8scorev1.ServiceAccount{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-genesis", Namespace: "default"}},
			&rbacv1.ClusterRole{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-genesis"}, Rules: wildcard},
			&rbacv1.ClusterRoleBinding{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-genesis", UID: "binding"},
				RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "octelium-genesis"},
				Subjects:   subjects,
			},
		}
	}

	for _, tc := range []struct {
		name         string
		existing     []runtime.Object
		isInit       bool
		subjects     []rbacv1.Subject
		keepsInitSA  bool
		keepsBinding bool
	}{
		{
			name:         "Init",
			existing:     legacyInstall(initial),
			isInit:       true,
			subjects:     []rbacv1.Subject{initial, installer},
			keepsInitSA:  true,
			keepsBinding: true,
		},
		{
			name:         "UpgradeLegacyInstall",
			existing:     legacyInstall(initial),
			subjects:     []rbacv1.Subject{installer},
			keepsBinding: true,
		},
		{
			name:         "UpgradeKeepsExternalSubjects",
			existing:     legacyInstall(initial, external, installer),
			subjects:     []rbacv1.Subject{external, installer},
			keepsBinding: true,
		},
		{
			name:     "UpgradeWithoutBootstrapIdentity",
			subjects: []rbacv1.Subject{installer},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			client := fake.NewClientset(tc.existing...)
			opts := &CommonOpts{K8sC: client}

			for range 2 {
				require.NoError(t, CreateGenesisIdentity(ctx, opts, tc.isInit))
			}

			_, err := client.CoreV1().ServiceAccounts("octelium").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
			require.NoError(t, err)

			role, err := client.RbacV1().ClusterRoles().Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, wildcard, role.Rules)

			binding, err := client.RbacV1().ClusterRoleBindings().Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, tc.subjects, binding.Subjects)
			assert.Equal(t, rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "octelium-genesis"}, binding.RoleRef)
			if tc.keepsBinding {
				assert.Equal(t, types.UID("binding"), binding.UID)
			}

			_, err = client.CoreV1().ServiceAccounts("default").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
			if tc.keepsInitSA {
				assert.NoError(t, err)
			} else {
				assert.True(t, k8serr.IsNotFound(err))
			}

			for _, action := range client.Actions() {
				if action.GetResource().Resource == "clusterrolebindings" {
					assert.NotEqual(t, "delete", action.GetVerb())
				}
			}
		})
	}
}
