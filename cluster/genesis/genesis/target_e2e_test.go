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
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakek8s "k8s.io/client-go/kubernetes/fake"
)

func TestUpgradeTargetMismatchPreservesClusterE2E(t *testing.T) {
	for _, fault := range []string{"requested-domain", "bootstrap-domain", "bootstrap-region", "checkpoint-id", "checkpoint-namespace", "cluster-binding", "region-binding", "namespace-binding", "postgres-target", "redis-target", "submitted-cluster", "submitted-region", "submitted-namespace"} {
		t.Run(fault, func(t *testing.T) {
			f := newInitializationFixture(t)
			require.NoError(t, f.genesis.RunInit(t.Context(), nil))
			c := f.client.K8sC.(*fakek8s.Clientset)
			switch fault {
			case "requested-domain":
				t.Setenv("OCTELIUM_DOMAIN", "another.example")
			case "bootstrap-domain", "bootstrap-region":
				secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
				require.NoError(t, err)
				if fault == "bootstrap-domain" {
					secret.Data["domain"] = []byte("another.example")
				} else {
					secret.Data["region"] = pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: "default", Uid: "another-region"}})
				}
				require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
			case "checkpoint-id", "checkpoint-namespace":
				secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
				require.NoError(t, err)
				key := "id"
				if fault == "checkpoint-namespace" {
					key = "namespace-uid"
				}
				secret.Data[key] = []byte("another-target")
				require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
			case "cluster-binding", "region-binding", "namespace-binding":
				cm, err := c.CoreV1().ConfigMaps(vutils.K8sNS).Get(t.Context(), installationConfigMapName, k8smetav1.GetOptions{})
				require.NoError(t, err)
				key := targetClusterUID
				if fault == "region-binding" {
					key = targetRegionUID
				} else if fault == "namespace-binding" {
					key = targetNamespaceUID
				}
				cm.Annotations[key] = "another-target"
				require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("configmaps"), cm, vutils.K8sNS))
			case "postgres-target", "redis-target":
				name := "octelium-postgres"
				if fault == "redis-target" {
					name = "octelium-redis"
				}
				secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
				require.NoError(t, err)
				secret.Data["host"] = []byte("another-storage.example")
				require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
			case "submitted-cluster":
				t.Setenv("OCTELIUM_GENESIS_CLUSTER_UID", "another-cluster")
			case "submitted-region":
				t.Setenv("OCTELIUM_GENESIS_REGION_UID", "another-region")
			case "submitted-namespace":
				t.Setenv("OCTELIUM_GENESIS_NAMESPACE_UID", "another-namespace")
			}
			before := initializationRows(t, f.db)
			keys := initializationSecrets(t, f.db)
			owner, err := f.redis.Get(t.Context(), initializationRedisKey).Result()
			require.NoError(t, err)
			c.ClearActions()
			require.Error(t, f.genesis.RunUpgrade(t.Context(), nil))
			assertTargetReadOnly(t, c)
			assert.Equal(t, before, initializationRows(t, f.db))
			assert.Equal(t, keys, initializationSecrets(t, f.db))
			currentOwner, err := f.redis.Get(t.Context(), initializationRedisKey).Result()
			require.NoError(t, err)
			assert.Equal(t, owner, currentOwner)
		})
	}
}

func TestCopiedKubernetesInstallationRejectedE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	c := newFakeClient()
	_, err := c.K8sC.CoreV1().Namespaces().Create(t.Context(), &k8scorev1.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS}}, k8smetav1.CreateOptions{})
	require.NoError(t, err)
	secrets, err := f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).List(t.Context(), k8smetav1.ListOptions{})
	require.NoError(t, err)
	for _, secret := range secrets.Items {
		require.NoError(t, c.K8sC.(*fakek8s.Clientset).Tracker().Add(secret.DeepCopy()))
	}
	cm, err := f.client.K8sC.CoreV1().ConfigMaps(vutils.K8sNS).Get(t.Context(), installationConfigMapName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	require.NoError(t, c.K8sC.(*fakek8s.Clientset).Tracker().Add(cm))
	g := &Genesis{k8sC: c.K8sC, nadC: c.NadC}
	before := initializationRows(t, f.db)
	c.K8sC.(*fakek8s.Clientset).ClearActions()
	require.ErrorContains(t, g.RunUpgrade(t.Context(), nil), "another Kubernetes namespace")
	require.ErrorContains(t, g.RunInit(t.Context(), nil), "another Kubernetes namespace")
	assertTargetReadOnly(t, c.K8sC.(*fakek8s.Clientset))
	assert.Equal(t, before, initializationRows(t, f.db))
}

func TestLegacyTargetMigrationAndRotationE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	c := f.client.K8sC.(*fakek8s.Clientset)
	require.NoError(t, c.CoreV1().Secrets(vutils.K8sNS).Delete(t.Context(), initializationSecretName, k8smetav1.DeleteOptions{}))
	cm, err := c.CoreV1().ConfigMaps(vutils.K8sNS).Get(t.Context(), installationConfigMapName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	cm.Annotations = map[string]string{"customer": "preserved"}
	cm.Data["customer"] = "preserved"
	configuration := cm.Data[installationConfigMapKey]
	require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("configmaps"), cm, vutils.K8sNS))
	for _, name := range []string{"octelium-postgres", "octelium-redis"} {
		secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
		require.NoError(t, err)
		secret.Annotations = nil
		require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
	}
	cc, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.NoError(t, err)
	keys := initializationSecrets(t, f.db)
	for pass := 0; pass < 2; pass++ {
		if pass == 1 {
			for _, name := range []string{"octelium-postgres", "octelium-redis"} {
				secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
				require.NoError(t, err)
				secret.Data["password"] = []byte("rotated")
				secret.Data["postgres-password"] = []byte("rotated")
				require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
			}
		}
		require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
		current, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
		require.NoError(t, err)
		assert.True(t, proto.Equal(cc, current))
		assert.Equal(t, keys, initializationSecrets(t, f.db))
		cm, err = c.CoreV1().ConfigMaps(vutils.K8sNS).Get(t.Context(), installationConfigMapName, k8smetav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, configuration, cm.Data[installationConfigMapKey])
		assert.Equal(t, "preserved", cm.Data["customer"])
		assert.Equal(t, "preserved", cm.Annotations["customer"])
		assert.Equal(t, cc.Metadata.Uid, cm.Annotations[targetClusterUID])
	}
}

func TestLegacyJoinedRegionTargetE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	region, err := f.genesis.octeliumC.CoreC().CreateRegion(t.Context(), &corev1.Region{
		Metadata: &metav1.Metadata{Name: "west", IsSystem: true}, Spec: &corev1.Region_Spec{}, Status: &corev1.Region_Status{Index: 1},
	})
	require.NoError(t, err)
	c := newFakeClient()
	_, err = c.K8sC.CoreV1().Namespaces().Create(t.Context(), &k8scorev1.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS}}, k8smetav1.CreateOptions{})
	require.NoError(t, err)
	_, err = c.K8sC.CoreV1().Secrets(vutils.K8sNS).Create(t.Context(), &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: vutils.K8sNS},
		Data:       map[string][]byte{"bootstrap": pbutils.MarshalMust(f.input.Bootstrap), "region": pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: "west"}})},
	}, k8smetav1.CreateOptions{})
	require.NoError(t, err)
	keys := initializationSecrets(t, f.db)
	t.Setenv("OCTELIUM_REGION_NAME", "default")
	g := &Genesis{k8sC: c.K8sC, nadC: c.NadC}
	require.NoError(t, g.RunUpgrade(t.Context(), nil))
	cm, err := c.K8sC.CoreV1().ConfigMaps(vutils.K8sNS).Get(t.Context(), installationConfigMapName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "west", cm.Annotations[targetRegionName])
	assert.Equal(t, region.Metadata.Uid, cm.Annotations[targetRegionUID])
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	_, err = g.octeliumC.CoreC().GetRegion(context.Background(), &rmetav1.GetOptions{Name: "default"})
	require.NoError(t, err)
}
