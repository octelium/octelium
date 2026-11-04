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
	"testing"

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func savePasswordBootstrap(t *testing.T, f *initializationFixture) {
	t.Helper()
	input, err := f.client.K8sC.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	input.Data["bootstrap"] = pbutils.MarshalMust(f.input.Bootstrap)
	_, err = f.client.K8sC.CoreV1().Secrets("default").Update(t.Context(), input, metav1.UpdateOptions{})
	require.NoError(t, err)
}

func TestPasswordReferenceFailureBeforeStorageE2E(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, failure := range []string{"missing-key", "empty-key"} {
			t.Run(storage+"/"+failure, func(t *testing.T) {
				f := newInitializationFixture(t)
				setPasswordReference(f.input.Bootstrap, storage, "credentials", "default", "custom")
				savePasswordBootstrap(t, f)
				source := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"password": []byte("private-wrong-fallback")}}
				if failure == "empty-key" {
					source.Data["custom"] = nil
				}
				c := f.client.K8sC.(*fake.Clientset)
				require.NoError(t, c.Tracker().Add(source))
				require.NoError(t, f.redis.Set(t.Context(), "unrelated-sentinel", "preserved", 0).Err())
				c.ClearActions()
				err := f.genesis.RunInit(t.Context(), nil)
				require.ErrorContains(t, err, "missing or empty")
				assert.NotContains(t, err.Error(), "private-wrong-fallback")
				for _, action := range c.Actions() {
					assert.Contains(t, []string{"get", "list"}, action.GetVerb())
				}
				var exists bool
				require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT to_regclass('octelium_resources') IS NOT NULL`).Scan(&exists))
				assert.False(t, exists)
				marker, err := f.redis.Exists(t.Context(), initializationRedisKey).Result()
				require.NoError(t, err)
				assert.Zero(t, marker)
				for _, name := range []string{initializationSecretName, "octelium-postgres", "octelium-redis", "init-token"} {
					_, err := c.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), vutils.K8sNS, name)
					assert.True(t, k8serr.IsNotFound(err))
				}
				f.checkPreserved(t)
				value, err := f.redis.Get(t.Context(), "unrelated-sentinel").Result()
				require.NoError(t, err)
				assert.Equal(t, "preserved", value)
				password := "postgres"
				if storage == "redis" {
					password = "secret"
				}
				source.Data["custom"] = []byte(password)
				require.NoError(t, c.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), source, "default"))
				require.NoError(t, f.genesis.RunInit(t.Context(), nil))
				name, key := "octelium-postgres", "postgres-password"
				if storage == "redis" {
					name, key = "octelium-redis", "password"
				}
				derived, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, password, string(derived.Data[key]))
			})
		}
	}
}

func TestCompletedPasswordReferencesAreNotRequiredForReplayOrUpgradeE2E(t *testing.T) {
	f := newInitializationFixture(t)
	setPasswordReference(f.input.Bootstrap, "postgres", "credentials", "default", "pg")
	setPasswordReference(f.input.Bootstrap, "redis", "credentials", "default", "redis")
	savePasswordBootstrap(t, f)
	c := f.client.K8sC.(*fake.Clientset)
	require.NoError(t, c.Tracker().Add(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: "default"}, Data: map[string][]byte{"pg": []byte("postgres"), "redis": []byte("secret")}}))
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	keys := initializationSecrets(t, f.db)
	rows := initializationRows(t, f.db)
	storage := make(map[string]*corev1.Secret)
	for _, name := range []string{"octelium-postgres", "octelium-redis"} {
		secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		storage[name] = secret
	}
	require.NoError(t, c.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("secrets"), "default", "credentials"))
	c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.GetAction).GetName() == "credentials" {
			t.Error("An existing Cluster tried to resolve the original password reference")
			return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), "credentials")
		}
		return false, nil, nil
	})
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	assert.Equal(t, rows, initializationRows(t, f.db))
	require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	require.NoError(t, c.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("secrets"), vutils.K8sNS, initializationSecretName))
	require.NoError(t, f.redis.Del(t.Context(), initializationRedisKey).Err())
	require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	for name, before := range storage {
		after, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, before.UID, after.UID)
		assert.Equal(t, before.Data, after.Data)
	}
	f.checkPreserved(t)
}
