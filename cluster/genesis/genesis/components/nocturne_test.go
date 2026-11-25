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
	"slices"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newTstNocturneOpts(client *fake.Clientset) *CommonOpts {
	return &CommonOpts{
		K8sC:          client,
		ClusterConfig: &corev1.ClusterConfig{Metadata: &metav1.Metadata{Name: "default", Uid: "cluster-uid"}, Spec: &corev1.ClusterConfig_Spec{}, Status: &corev1.ClusterConfig_Status{Domain: "example.com"}},
		Region:        &corev1.Region{Metadata: &metav1.Metadata{Name: "default", Uid: "region-uid"}, Spec: &corev1.Region_Spec{}, Status: &corev1.Region_Status{}},
	}
}

func getTstActionIndex(actions []k8stesting.Action, verb, resource, name string) int {
	return slices.IndexFunc(actions, func(action k8stesting.Action) bool {
		if action.GetVerb() != verb || action.GetResource().Resource != resource {
			return false
		}
		createAction, ok := action.(k8stesting.CreateAction)
		if !ok {
			return false
		}
		obj, ok := createAction.GetObject().(k8smetav1.Object)
		return ok && obj.GetName() == name
	})
}

func TestNocturneRuntimeRBAC(t *testing.T) {
	role := getNocturneRuntimeRole()
	assert.Equal(t, "octelium-nocturne-runtime", role.Name)
	assert.Equal(t, "octelium", role.Namespace)
	assert.Equal(t, []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "create", "update", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"services", "secrets"}, Verbs: []string{"get", "list", "watch", "create", "update", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "create", "update", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps/finalizers"}, Verbs: []string{"update"}},
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list", "watch"}},
	}, role.Rules)

	clusterRole := getNocturneRuntimeClusterRole()
	assert.Equal(t, "octelium-nocturne-runtime", clusterRole.Name)
	assert.Equal(t, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get", "list", "watch", "update"}},
	}, clusterRole.Rules)

	for _, rules := range [][]rbacv1.PolicyRule{role.Rules, clusterRole.Rules} {
		for _, rule := range rules {
			assert.NotContains(t, rule.APIGroups, "*")
			assert.NotContains(t, rule.Resources, "*")
			assert.NotContains(t, rule.Verbs, "*")
			assert.Empty(t, rule.NonResourceURLs)
		}
	}

	subject := rbacv1.Subject{Kind: "ServiceAccount", Name: "octelium-nocturne-runtime", Namespace: "octelium"}

	roleBinding := getNocturneRuntimeRoleBinding()
	assert.Equal(t, "octelium", roleBinding.Namespace)
	assert.Equal(t, rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: role.Name}, roleBinding.RoleRef)
	assert.Equal(t, []rbacv1.Subject{subject}, roleBinding.Subjects)

	clusterRoleBinding := getNocturneRuntimeClusterRoleBinding()
	assert.Equal(t, rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: clusterRole.Name}, clusterRoleBinding.RoleRef)
	assert.Equal(t, []rbacv1.Subject{subject}, clusterRoleBinding.Subjects)

	assert.Equal(t, "octelium-nocturne-runtime",
		getNocturneDeployment(newTstNocturneOpts(fake.NewClientset())).Spec.Template.Spec.ServiceAccountName)
}

func TestCreateNocturne(t *testing.T) {
	legacyDeployment := getNocturneDeployment(newTstNocturneOpts(fake.NewClientset()))
	legacyDeployment.Spec.Template.Spec.ServiceAccountName = "octelium-nocturne"

	for _, tc := range []struct {
		name     string
		existing []runtime.Object
	}{
		{name: "Fresh"},
		{name: "Upgrade", existing: []runtime.Object{
			legacyDeployment,
			&k8scorev1.ServiceAccount{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-nocturne", Namespace: "octelium"}},
			&rbacv1.ClusterRole{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-nocturne"}, Rules: getNocturneLegacyRole().Rules},
			&rbacv1.ClusterRoleBinding{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-nocturne", UID: "legacy"},
				RoleRef:    getNocturneLegacyRoleBinding().RoleRef,
				Subjects:   getNocturneLegacyRoleBinding().Subjects,
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			client := fake.NewClientset(tc.existing...)
			opts := newTstNocturneOpts(client)
			for range 2 {
				require.NoError(t, CreateNocturne(ctx, opts))
			}

			deployment, err := client.AppsV1().Deployments("octelium").Get(ctx, "octelium-nocturne", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, "octelium-nocturne-runtime", deployment.Spec.Template.Spec.ServiceAccountName)

			_, err = client.CoreV1().ServiceAccounts("octelium").Get(ctx, "octelium-nocturne-runtime", k8smetav1.GetOptions{})
			require.NoError(t, err)

			role, err := client.RbacV1().Roles("octelium").Get(ctx, "octelium-nocturne-runtime", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, getNocturneRuntimeRole().Rules, role.Rules)

			roleBinding, err := client.RbacV1().RoleBindings("octelium").Get(ctx, "octelium-nocturne-runtime", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, getNocturneRuntimeRoleBinding().RoleRef, roleBinding.RoleRef)
			assert.Equal(t, getNocturneRuntimeRoleBinding().Subjects, roleBinding.Subjects)

			clusterRole, err := client.RbacV1().ClusterRoles().Get(ctx, "octelium-nocturne-runtime", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, getNocturneRuntimeClusterRole().Rules, clusterRole.Rules)

			clusterRoleBinding, err := client.RbacV1().ClusterRoleBindings().Get(ctx, "octelium-nocturne-runtime", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, getNocturneRuntimeClusterRoleBinding().RoleRef, clusterRoleBinding.RoleRef)
			assert.Equal(t, getNocturneRuntimeClusterRoleBinding().Subjects, clusterRoleBinding.Subjects)

			legacySA, err := client.CoreV1().ServiceAccounts("octelium").Get(ctx, "octelium-nocturne", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Contains(t, legacySA.Annotations, "octelium.com/deprecated")

			legacyRole, err := client.RbacV1().ClusterRoles().Get(ctx, "octelium-nocturne", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, []rbacv1.PolicyRule{{APIGroups: []string{"*", "*.*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}, legacyRole.Rules)
			assert.Contains(t, legacyRole.Annotations, "octelium.com/deprecated")

			legacyRoleBinding, err := client.RbacV1().ClusterRoleBindings().Get(ctx, "octelium-nocturne", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, []rbacv1.Subject{{Kind: "ServiceAccount", Name: "octelium-nocturne", Namespace: "octelium"}}, legacyRoleBinding.Subjects)
			assert.Equal(t, "octelium-nocturne", legacyRoleBinding.RoleRef.Name)
			if tc.name == "Upgrade" {
				assert.Equal(t, types.UID("legacy"), legacyRoleBinding.UID)
			}

			actions := client.Actions()
			deploymentIdx := getTstActionIndex(actions, "create", "deployments", "octelium-nocturne")
			require.GreaterOrEqual(t, deploymentIdx, 0)
			for _, itm := range []struct {
				resource string
				name     string
			}{
				{"serviceaccounts", "octelium-nocturne-runtime"},
				{"roles", "octelium-nocturne-runtime"},
				{"rolebindings", "octelium-nocturne-runtime"},
				{"clusterroles", "octelium-nocturne-runtime"},
				{"clusterrolebindings", "octelium-nocturne-runtime"},
				{"serviceaccounts", "octelium-nocturne"},
				{"clusterroles", "octelium-nocturne"},
				{"clusterrolebindings", "octelium-nocturne"},
			} {
				idx := getTstActionIndex(actions, "create", itm.resource, itm.name)
				require.GreaterOrEqual(t, idx, 0, "%s/%s", itm.resource, itm.name)
				assert.Less(t, idx, deploymentIdx, "%s/%s", itm.resource, itm.name)
			}
		})
	}
}

func TestGatewayAgentRole(t *testing.T) {
	assert.Equal(t, []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get", "update", "watch", "list"}},
	}, getGatewayAgentRole().Rules)
}
