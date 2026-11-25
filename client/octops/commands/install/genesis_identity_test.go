// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package install

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestEnsureGenesisServiceAccount(t *testing.T) {
	installer := getGenesisSubject("octelium")
	initial := getGenesisSubject("default")

	t.Run("Fresh", func(t *testing.T) {
		ctx := t.Context()
		c := fakek8s.NewClientset()
		for range 2 {
			name, err := EnsureGenesisServiceAccount(ctx, c)
			require.NoError(t, err)
			assert.Equal(t, "octelium-genesis", name)
		}
		_, err := c.CoreV1().ServiceAccounts("octelium").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
		require.NoError(t, err)
		role, err := c.RbacV1().ClusterRoles().Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, getGenesisRole().Rules, role.Rules)
		binding, err := c.RbacV1().ClusterRoleBindings().Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, []rbacv1.Subject{installer}, binding.Subjects)
		assert.Equal(t, rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "octelium-genesis"}, binding.RoleRef)
	})

	t.Run("LegacyInstall", func(t *testing.T) {
		ctx := t.Context()
		binding := getGenesisRoleBinding([]rbacv1.Subject{initial})
		binding.UID = "binding"
		c := fakek8s.NewClientset(binding, getGenesisRole(), getGenesisServiceAccount("default"))
		name, err := EnsureGenesisServiceAccount(ctx, c)
		require.NoError(t, err)
		assert.Equal(t, "octelium-genesis", name)
		got, err := c.RbacV1().ClusterRoleBindings().Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, []rbacv1.Subject{initial, installer}, got.Subjects)
		assert.Equal(t, binding.UID, got.UID)
		_, err = c.CoreV1().ServiceAccounts("default").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
		assert.NoError(t, err)

		c.ClearActions()
		_, err = EnsureGenesisServiceAccount(ctx, c)
		require.NoError(t, err)
		for _, action := range c.Actions() {
			assert.NotEqual(t, "update", action.GetVerb())
			assert.NotEqual(t, "delete", action.GetVerb())
		}
	})

	for _, tc := range []struct {
		verb     string
		resource string
	}{
		{"create", "serviceaccounts"},
		{"create", "clusterroles"},
		{"get", "clusterrolebindings"},
		{"create", "clusterrolebindings"},
		{"update", "clusterrolebindings"},
	} {
		t.Run("Forbidden/"+tc.verb+"/"+tc.resource, func(t *testing.T) {
			c := fakek8s.NewClientset(getGenesisRoleBinding([]rbacv1.Subject{initial}))
			if tc.verb == "create" && tc.resource == "clusterrolebindings" {
				c = fakek8s.NewClientset()
			}
			c.PrependReactor(tc.verb, tc.resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, k8serr.NewForbidden(schema.GroupResource{Resource: tc.resource}, "octelium-genesis", nil)
			})
			name, err := EnsureGenesisServiceAccount(t.Context(), c)
			require.NoError(t, err)
			assert.Equal(t, "octelium-nocturne", name)
		})
	}

	t.Run("Error", func(t *testing.T) {
		c := fakek8s.NewClientset()
		c.PrependReactor("create", "clusterroles", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, k8serr.NewBadRequest("invalid")
		})
		name, err := EnsureGenesisServiceAccount(t.Context(), c)
		assert.True(t, k8serr.IsBadRequest(err))
		assert.Empty(t, name)
	})
}

func TestRemoveInitGenesisIdentity(t *testing.T) {
	installer := getGenesisSubject("octelium")
	initial := getGenesisSubject("default")
	external := rbacv1.Subject{Kind: "User", Name: "admin", APIGroup: "rbac.authorization.k8s.io"}

	for _, tc := range []struct {
		name     string
		existing []runtime.Object
		subjects []rbacv1.Subject
	}{
		{
			name: "Installed",
			existing: []runtime.Object{
				getGenesisRoleBinding([]rbacv1.Subject{initial, external, installer}),
				getGenesisServiceAccount("default"),
				getGenesisServiceAccount("octelium"),
			},
			subjects: []rbacv1.Subject{external, installer},
		},
		{
			name: "OlderGenesis",
			existing: []runtime.Object{
				getGenesisRoleBinding([]rbacv1.Subject{initial}),
				getGenesisServiceAccount("default"),
			},
			subjects: []rbacv1.Subject{},
		},
		{
			name: "Missing",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			c := fakek8s.NewClientset(tc.existing...)
			for range 2 {
				require.NoError(t, removeInitGenesisIdentity(ctx, c))
			}
			binding, err := c.RbacV1().ClusterRoleBindings().Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
			if tc.subjects == nil {
				assert.True(t, k8serr.IsNotFound(err))
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.subjects, binding.Subjects)
			}
			_, err = c.CoreV1().ServiceAccounts("default").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
			assert.True(t, k8serr.IsNotFound(err))
		})
	}
}

func TestGenesisInitRestoresInitSubject(t *testing.T) {
	ctx := t.Context()
	c := fakek8s.NewClientset(
		getGenesisRoleBinding([]rbacv1.Subject{getGenesisSubject("octelium")}),
		getGenesisRole(),
		&k8scorev1.ServiceAccount{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-genesis", Namespace: "octelium"}},
	)
	_, err := createGenesis(ctx, &Opts{K8sC: c})
	require.NoError(t, err)
	binding, err := c.RbacV1().ClusterRoleBindings().Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, []rbacv1.Subject{getGenesisSubject("octelium"), getGenesisSubject("default")}, binding.Subjects)
	_, err = c.CoreV1().ServiceAccounts("default").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
	assert.NoError(t, err)
}
