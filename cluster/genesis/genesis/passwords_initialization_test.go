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

package genesis

import (
	"fmt"
	"testing"

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/genesisutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestInitializationPasswordErrorsBeforeMutation(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, failure := range []string{"name", "namespace", "key", "missing-key", "empty-key", "missing-defaults", "missing-secret"} {
			t.Run(storage+"/"+failure, func(t *testing.T) {
				resetPasswordEnvironment(t)
				ldflags.TestMode = "true"
				input := newInitializationInput(t)
				name, namespace, key := "credentials", "default", "custom"
				data := map[string][]byte{"custom": []byte("source-password"), "password": []byte("fallback-password")}
				switch failure {
				case "name":
					name = ""
				case "namespace":
					namespace = "bad/namespace"
				case "key":
					key = "bad/key"
				case "missing-key":
					delete(data, "custom")
				case "empty-key":
					data["custom"] = nil
				case "missing-defaults":
					key = ""
					delete(data, "password")
				}
				setPasswordReference(input.Bootstrap, storage, name, namespace, key)
				bootstrap := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "octelium-init", Namespace: "default"}, Data: map[string][]byte{"bootstrap": pbutils.MarshalMust(input.Bootstrap), "region": pbutils.MarshalMust(input.Region), "domain": []byte(input.Domain)}}
				c := fake.NewSimpleClientset(bootstrap)
				if failure != "missing-secret" {
					require.NoError(t, c.Tracker().Add(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: data}))
				}
				g := &Genesis{k8sC: c}
				require.Error(t, g.RunInit(t.Context(), nil))
				assertPasswordResolutionReadOnly(t, c)
				_, err := c.Tracker().Get(corev1.SchemeGroupVersion.WithResource("namespaces"), "", vutils.K8sNS)
				assert.True(t, k8serr.IsNotFound(err))
				for _, name := range []string{initializationSecretName, "octelium-postgres", "octelium-redis"} {
					_, err := c.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), vutils.K8sNS, name)
					assert.True(t, k8serr.IsNotFound(err))
				}
			})
		}
	}
}

func TestInitializationCarriesResolvedPasswordSnapshot(t *testing.T) {
	resetPasswordEnvironment(t)
	input := newInitializationInput(t)
	setPasswordReference(input.Bootstrap, "postgres", "credentials", "default", "pg")
	setPasswordReference(input.Bootstrap, "redis", "credentials", "", "redis")
	source := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"pg": []byte("snapshot-postgres-password"), "redis": []byte("snapshot-redis-password")}}
	c := fake.NewSimpleClientset(source)
	c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.CreateAction).GetObject().(*corev1.Secret).Name == initializationSecretName {
			rotated := source.DeepCopy()
			rotated.Data["pg"], rotated.Data["redis"] = []byte("rotated-pg"), []byte("rotated-redis")
			require.NoError(t, c.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), rotated, "default"))
		}
		return false, nil, nil
	})
	g := &Genesis{k8sC: c}
	init, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	require.NotNil(t, init.passwords)
	require.NoError(t, g.initStorageWithPasswords(t.Context(), &genesisutils.InstallCtx{Bootstrap: input.Bootstrap}, init.passwords))
	for name, key := range map[string]string{"octelium-postgres": "postgres-password", "octelium-redis": "password"} {
		secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		want := "snapshot-postgres-password"
		if name == "octelium-redis" {
			want = "snapshot-redis-password"
		}
		assert.Equal(t, want, string(secret.Data[key]))
	}
	reads := 0
	for _, action := range c.Actions() {
		if action.GetVerb() == "get" && action.GetResource().Resource == "secrets" && action.(k8stesting.GetAction).GetName() == "credentials" {
			reads++
		}
	}
	assert.Equal(t, 1, reads)
	checkpoint, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	for _, value := range checkpoint.Data {
		assert.NotContains(t, string(value), "snapshot-postgres-password")
		assert.NotContains(t, string(value), "snapshot-redis-password")
	}
}

func TestInitializationPasswordReferenceReplay(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(fmt.Sprint(complete), func(t *testing.T) {
			resetPasswordEnvironment(t)
			input := newInitializationInput(t)
			setPasswordReference(input.Bootstrap, "redis", "credentials", "default", "custom")
			source := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"custom": []byte("redis-secret"), "password": []byte("wrong-fallback")}}
			c := fake.NewSimpleClientset(source)
			g := &Genesis{k8sC: c}
			first, err := g.prepareInitialization(t.Context(), input)
			require.NoError(t, err)
			if complete {
				require.NoError(t, g.completeInitialization(t.Context(), first))
			}
			require.NoError(t, c.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("secrets"), "default", source.Name))
			c.ClearActions()
			replayed, err := g.prepareInitialization(t.Context(), input)
			if complete {
				require.NoError(t, err)
				assert.Equal(t, first.id, replayed.id)
				assert.Nil(t, replayed.passwords)
				for _, action := range c.Actions() {
					if action.GetResource().Resource == "secrets" && action.GetVerb() == "get" {
						assert.NotEqual(t, source.Name, action.(k8stesting.GetAction).GetName())
					}
				}
			} else {
				require.True(t, k8serr.IsNotFound(err))
			}
			assertPasswordResolutionReadOnly(t, c)
			if !complete {
				require.NoError(t, c.Tracker().Add(source))
				recovered, err := g.prepareInitialization(t.Context(), input)
				require.NoError(t, err)
				assert.Equal(t, first.id, recovered.id)
				assert.Equal(t, first.aesKeyName, recovered.aesKeyName)
				assert.Equal(t, first.passwords, recovered.passwords)
			}
		})
	}
}
