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
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	corev1k8s "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newTargetFixture(t *testing.T) (*Genesis, *corev1.ClusterConfig, *corev1.Region, *LoadedClusterResource) {
	t.Helper()
	for _, key := range []string{"OCTELIUM_DOMAIN", "OCTELIUM_REGION_NAME", "OCTELIUM_GENESIS_CLUSTER_UID", "OCTELIUM_GENESIS_REGION_UID", "OCTELIUM_GENESIS_NAMESPACE_UID"} {
		t.Setenv(key, "")
	}
	c := fake.NewSimpleClientset(
		&corev1k8s.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS, UID: "namespace-uid"}},
		&corev1k8s.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: installationConfigMapName, Namespace: vutils.K8sNS, Labels: map[string]string{"custom": "preserved"}, Annotations: map[string]string{"custom": "preserved"}}, Data: map[string]string{installationConfigMapKey: "{}", "custom": "preserved"}},
		&corev1k8s.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-postgres", Namespace: vutils.K8sNS}, Data: map[string][]byte{"host": []byte("postgres"), "database": []byte("octelium"), "postgres-password": []byte("password")}},
		&corev1k8s.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-redis", Namespace: vutils.K8sNS}, Data: map[string][]byte{"host": []byte("redis"), "database": []byte("1"), "password": []byte("password")}},
	)
	cc := &corev1.ClusterConfig{Metadata: &metav1.Metadata{Name: "default", Uid: "cluster-uid"}, Status: &corev1.ClusterConfig_Status{Domain: "example.com"}}
	region := &corev1.Region{Metadata: &metav1.Metadata{Name: "default", Uid: "region-uid"}, Status: &corev1.Region_Status{}}
	input := &LoadedClusterResource{Domain: cc.Status.Domain, Region: &corev1.Region{Metadata: &metav1.Metadata{Name: region.Metadata.Name}}}
	return &Genesis{k8sC: c}, cc, region, input
}

func assertTargetReadOnly(t *testing.T, c *fake.Clientset) {
	t.Helper()
	for _, action := range c.Actions() {
		assert.Contains(t, []string{"get", "list"}, action.GetVerb())
	}
}

func TestUpgradeTargetIdentity(t *testing.T) {
	for _, change := range []string{"none", "requested-domain", "bootstrap-domain", "cluster-uid", "region-name", "region-uid", "requested-region", "old-default-region", "legacy-domain", "canonical-domain", "submitted-cluster", "submitted-region", "submitted-namespace"} {
		t.Run(change, func(t *testing.T) {
			g, cc, region, input := newTargetFixture(t)
			valid := false
			switch change {
			case "none":
				valid = true
			case "requested-domain":
				t.Setenv("OCTELIUM_DOMAIN", "another.example")
			case "bootstrap-domain":
				input.Domain = "another.example"
			case "cluster-uid":
				cc.Metadata.Uid = ""
			case "region-name":
				input.Region.Metadata.Name = "west"
			case "region-uid":
				input.Region.Metadata.Uid = "another-region"
			case "requested-region":
				t.Setenv("OCTELIUM_REGION_NAME", "west")
			case "old-default-region":
				input.Region.Metadata.Name, region.Metadata.Name = "west", "west"
				t.Setenv("OCTELIUM_REGION_NAME", "default")
				valid = true
			case "legacy-domain":
				input.Domain = ""
				valid = true
			case "canonical-domain":
				input.Domain = "Example.COM."
				t.Setenv("OCTELIUM_DOMAIN", "EXAMPLE.com")
				valid = true
			case "submitted-cluster":
				t.Setenv("OCTELIUM_GENESIS_CLUSTER_UID", "another-cluster")
			case "submitted-region":
				t.Setenv("OCTELIUM_GENESIS_REGION_UID", "another-region")
			case "submitted-namespace":
				t.Setenv("OCTELIUM_GENESIS_NAMESPACE_UID", "another-namespace")
			}
			err := g.validateUpgradeTarget(t.Context(), input, cc, region)
			if valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			assertTargetReadOnly(t, g.k8sC.(*fake.Clientset))
		})
	}
}

func TestUpgradeRejectsStoredTargetMismatch(t *testing.T) {
	for _, object := range []string{"configmaps", "octelium-postgres", "octelium-redis"} {
		for _, key := range []string{targetClusterUID, targetDomain, targetRegionUID, targetRegionName, targetNamespaceUID} {
			for _, missing := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/missing=%t", object, key, missing), func(t *testing.T) {
					g, cc, region, input := newTargetFixture(t)
					require.NoError(t, g.reconcileInstallationTarget(t.Context(), cc, region, true))
					c := g.k8sC.(*fake.Clientset)
					var stored runtime.Object
					var err error
					resource := corev1k8s.SchemeGroupVersion.WithResource("secrets")
					if object == "configmaps" {
						resource = corev1k8s.SchemeGroupVersion.WithResource("configmaps")
						stored, err = c.Tracker().Get(resource, vutils.K8sNS, installationConfigMapName)
					} else {
						stored, err = c.Tracker().Get(resource, vutils.K8sNS, object)
					}
					require.NoError(t, err)
					annotations := stored.(k8smetav1.Object).GetAnnotations()
					if missing {
						delete(annotations, key)
					} else {
						annotations[key] = "another-target"
					}
					require.NoError(t, c.Tracker().Update(resource, stored, vutils.K8sNS))
					c.ClearActions()
					require.Error(t, g.validateUpgradeTarget(t.Context(), input, cc, region))
					assertTargetReadOnly(t, c)
				})
			}
		}
	}
}

func TestStorageTargetChangeAndCredentialRotation(t *testing.T) {
	for _, name := range []string{"octelium-postgres", "octelium-redis"} {
		for _, field := range []string{"host", "port", "database", "password", "postgres-password", "username", "no_ssl", "use_tls"} {
			t.Run(name+"/"+field, func(t *testing.T) {
				g, cc, region, input := newTargetFixture(t)
				require.NoError(t, g.reconcileInstallationTarget(t.Context(), cc, region, true))
				c := g.k8sC.(*fake.Clientset)
				secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
				require.NoError(t, err)
				secret.Data[field] = []byte("changed")
				require.NoError(t, c.Tracker().Update(corev1k8s.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
				c.ClearActions()
				err = g.validateUpgradeTarget(t.Context(), input, cc, region)
				if field == "host" || field == "port" || field == "database" {
					require.ErrorContains(t, err, "storage target changed")
				} else {
					require.NoError(t, err)
				}
				assertTargetReadOnly(t, c)
			})
		}
	}
	pg := &corev1k8s.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-postgres"}, Data: map[string][]byte{"username": []byte("one")}}
	before := storageTargetHash(pg)
	pg.Data["username"] = []byte("two")
	assert.NotEqual(t, before, storageTargetHash(pg))
	pg.Data["database"] = []byte("two")
	assert.Equal(t, storageTargetHash(pg), storageTargetHash(&corev1k8s.Secret{ObjectMeta: pg.ObjectMeta, Data: map[string][]byte{"database": []byte("two"), "port": []byte("5432")}}))
}

func TestTargetMigrationRecoversAndPreservesConfiguration(t *testing.T) {
	for _, name := range []string{installationConfigMapName, "octelium-postgres", "octelium-redis"} {
		for _, failure := range []string{"before", "after", "conflict"} {
			t.Run(name+"/"+failure, func(t *testing.T) {
				g, cc, region, _ := newTargetFixture(t)
				c := g.k8sC.(*fake.Clientset)
				failed, updates := false, 0
				c.PrependReactor("update", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
					object := action.(k8stesting.UpdateAction).GetObject()
					if object.(k8smetav1.Object).GetName() != name {
						return false, nil, nil
					}
					updates++
					if failed {
						return false, nil, nil
					}
					failed = true
					if failure == "after" {
						require.NoError(t, c.Tracker().Update(action.GetResource(), object, action.GetNamespace()))
					}
					if failure == "conflict" {
						current, err := c.Tracker().Get(action.GetResource(), action.GetNamespace(), name)
						require.NoError(t, err)
						current.(k8smetav1.Object).SetResourceVersion("2")
						require.NoError(t, c.Tracker().Update(action.GetResource(), current, action.GetNamespace()))
						return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), name, io.EOF)
					}
					return true, nil, io.ErrUnexpectedEOF
				})
				require.NoError(t, g.reconcileInstallationTarget(t.Context(), cc, region, true))
				require.True(t, failed)
				if failure == "after" {
					assert.Equal(t, 1, updates)
				}
				cm, err := c.CoreV1().ConfigMaps(vutils.K8sNS).Get(t.Context(), installationConfigMapName, k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, "{}", cm.Data[installationConfigMapKey])
				assert.Equal(t, "preserved", cm.Data["custom"])
				assert.Equal(t, "preserved", cm.Annotations["custom"])
				assert.Equal(t, "preserved", cm.Labels["custom"])
				c.ClearActions()
				require.NoError(t, g.reconcileInstallationTarget(t.Context(), cc, region, true))
				assertTargetReadOnly(t, c)
			})
		}
	}
}

func TestTargetReadErrorsAndCancellation(t *testing.T) {
	for _, transient := range []bool{false, true} {
		g, cc, region, input := newTargetFixture(t)
		c := g.k8sC.(*fake.Clientset)
		reads := 0
		c.PrependReactor("get", "namespaces", func(action k8stesting.Action) (bool, runtime.Object, error) {
			reads++
			if transient && reads > 1 {
				return false, nil, nil
			}
			if transient {
				return true, nil, io.EOF
			}
			return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), vutils.K8sNS, fmt.Errorf("forbidden"))
		})
		err := g.validateUpgradeTarget(t.Context(), input, cc, region)
		if transient {
			require.NoError(t, err)
			assert.Equal(t, 2, reads)
		} else {
			require.True(t, k8serr.IsForbidden(err))
			assert.Equal(t, 1, reads)
		}
		assertTargetReadOnly(t, c)
	}
	g, cc, region, input := newTargetFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, g.validateUpgradeTarget(ctx, input, cc, region), context.Canceled)
	assert.Empty(t, g.k8sC.(*fake.Clientset).Actions())
	g.k8sC.(*fake.Clientset).PrependReactor("get", "namespaces", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, io.EOF })
	ctx, cancel = context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, g.validateUpgradeTarget(ctx, input, cc, region), context.DeadlineExceeded)
}

func TestInitializationNamespaceBinding(t *testing.T) {
	for _, change := range []string{"same", "copied", "deleted", "terminating", "legacy"} {
		t.Run(change, func(t *testing.T) {
			c := fake.NewSimpleClientset(&corev1k8s.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS, UID: "original-namespace"}})
			g := &Genesis{k8sC: c}
			input := newInitializationInput(t)
			first, err := g.prepareInitialization(t.Context(), input)
			require.NoError(t, err)
			state, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, "original-namespace", string(state.Data["namespace-uid"]))
			if change == "legacy" {
				delete(state.Data, "namespace-uid")
				require.NoError(t, c.Tracker().Update(corev1k8s.SchemeGroupVersion.WithResource("secrets"), state, vutils.K8sNS))
			}
			if change != "same" {
				namespace := &corev1k8s.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS, UID: "another-namespace"}}
				if change == "terminating" {
					namespace.UID = "original-namespace"
					namespace.DeletionTimestamp = new(k8smetav1.Now())
				}
				if change == "deleted" {
					require.NoError(t, c.Tracker().Delete(corev1k8s.SchemeGroupVersion.WithResource("namespaces"), "", vutils.K8sNS))
				} else {
					require.NoError(t, c.Tracker().Update(corev1k8s.SchemeGroupVersion.WithResource("namespaces"), namespace, ""))
				}
			}
			c.ClearActions()
			resumed, err := g.prepareInitialization(t.Context(), input)
			if change == "same" || change == "legacy" {
				require.NoError(t, err)
				assert.Equal(t, first.id, resumed.id)
				assert.Equal(t, first.aesKeyName, resumed.aesKeyName)
			} else {
				require.Error(t, err)
			}
			assertTargetReadOnly(t, c)
		})
	}
}

func TestInitializationRequestedDomainBeforeWrites(t *testing.T) {
	c := fake.NewSimpleClientset()
	g := &Genesis{k8sC: c}
	input := newInitializationInput(t)
	t.Setenv("OCTELIUM_DOMAIN", "another.example")
	_, err := g.prepareInitialization(t.Context(), input)
	require.ErrorContains(t, err, "requested domain")
	assert.Empty(t, c.Actions())
}

func TestUpgradeTargetMismatchPreservesClusterE2E(t *testing.T) {
	for _, fault := range []string{"requested-domain", "bootstrap-domain", "bootstrap-region", "checkpoint-id", "checkpoint-namespace", "cluster-binding", "region-binding", "namespace-binding", "postgres-target", "redis-target", "submitted-cluster", "submitted-region", "submitted-namespace"} {
		t.Run(fault, func(t *testing.T) {
			f := newInitializationFixture(t)
			require.NoError(t, f.genesis.RunInit(t.Context(), nil))
			c := f.client.K8sC.(*fake.Clientset)
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
				require.NoError(t, c.Tracker().Update(corev1k8s.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
			case "checkpoint-id", "checkpoint-namespace":
				secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
				require.NoError(t, err)
				key := "id"
				if fault == "checkpoint-namespace" {
					key = "namespace-uid"
				}
				secret.Data[key] = []byte("another-target")
				require.NoError(t, c.Tracker().Update(corev1k8s.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
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
				require.NoError(t, c.Tracker().Update(corev1k8s.SchemeGroupVersion.WithResource("configmaps"), cm, vutils.K8sNS))
			case "postgres-target", "redis-target":
				name := "octelium-postgres"
				if fault == "redis-target" {
					name = "octelium-redis"
				}
				secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
				require.NoError(t, err)
				secret.Data["host"] = []byte("another-storage.example")
				require.NoError(t, c.Tracker().Update(corev1k8s.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
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

func TestClusterConfigRoundTripPreservesInitializationE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	srv := admin.NewServer(&admin.Opts{OcteliumC: f.genesis.octeliumC, IsEmbedded: true})
	cc, err := srv.GetClusterConfig(t.Context(), &corev1.GetClusterConfigRequest{})
	require.NoError(t, err)
	id := cc.Metadata.Annotations[initializationIDKey]
	require.NotEmpty(t, id)
	checkpoint, err := f.genesis.getK8sSecret(t.Context(), vutils.K8sNS, initializationSecretName)
	require.NoError(t, err)
	assert.Equal(t, id, string(checkpoint.Data["id"]))
	token, err := f.genesis.getInitAuthenticationToken(t.Context())
	require.NoError(t, err)
	keys := initializationSecrets(t, f.db)
	credential, err := f.genesis.octeliumC.CoreC().GetCredential(t.Context(), &rmetav1.GetOptions{Name: "root-init"})
	require.NoError(t, err)
	owner, err := f.redis.Get(t.Context(), initializationRedisKey).Result()
	require.NoError(t, err)

	cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{UseForwardedForHeader: true, XffNumTrustedHops: 2}
	cc.Metadata.Annotations["operator"] = "preserved"
	cc.Metadata.Annotations["operator.example.com/owner"] = "platform"
	before := proto.Clone(cc)
	updated, err := srv.UpdateClusterConfig(t.Context(), cc)
	require.NoError(t, err)
	assert.True(t, proto.Equal(before, cc))
	assert.Equal(t, cc.Metadata.Annotations, updated.Metadata.Annotations)
	assert.True(t, proto.Equal(cc.Spec, updated.Spec))
	assert.Equal(t, cc.Metadata.Uid, updated.Metadata.Uid)

	restarted := &Genesis{k8sC: f.client.K8sC, nadC: f.client.NadC}
	require.NoError(t, restarted.RunInit(t.Context(), nil))
	assert.Equal(t, id, restarted.initializationID)
	for range 2 {
		require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
	}
	current, err := srv.GetClusterConfig(t.Context(), &corev1.GetClusterConfigRequest{})
	require.NoError(t, err)
	assert.Equal(t, updated.Metadata.Uid, current.Metadata.Uid)
	assert.Equal(t, updated.Metadata.Annotations, current.Metadata.Annotations)
	assert.True(t, proto.Equal(updated.Spec, current.Spec))
	assert.True(t, proto.Equal(updated.Status.Network, current.Status.Network))
	region, err := f.genesis.octeliumC.CoreC().GetRegion(t.Context(), &rmetav1.GetOptions{Name: "default"})
	require.NoError(t, err)
	assert.Equal(t, id, region.Metadata.Annotations[initializationIDKey])
	stored, err := f.genesis.getK8sSecret(t.Context(), vutils.K8sNS, initializationSecretName)
	require.NoError(t, err)
	assert.Equal(t, checkpoint.Data, stored.Data)
	assert.Equal(t, checkpoint.Annotations, stored.Annotations)
	storedToken, err := f.genesis.getInitAuthenticationToken(t.Context())
	require.NoError(t, err)
	assert.Equal(t, token.Data, storedToken.Data)
	assert.Equal(t, token.Annotations, storedToken.Annotations)
	currentCredential, err := f.genesis.octeliumC.CoreC().GetCredential(t.Context(), &rmetav1.GetOptions{Name: "root-init"})
	require.NoError(t, err)
	assert.True(t, proto.Equal(credential, currentCredential))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	currentOwner, err := f.redis.Get(t.Context(), initializationRedisKey).Result()
	require.NoError(t, err)
	assert.Equal(t, owner, currentOwner)
	f.checkPreserved(t)
}

func TestUpgradeRejectsChangedInitializationAnnotationE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	srv := admin.NewServer(&admin.Opts{OcteliumC: f.genesis.octeliumC, IsEmbedded: true})
	cc, err := srv.GetClusterConfig(t.Context(), &corev1.GetClusterConfigRequest{})
	require.NoError(t, err)
	cc.Metadata.Annotations[initializationIDKey] = vutils.UUIDv4()
	_, err = srv.UpdateClusterConfig(t.Context(), cc)
	require.NoError(t, err)
	before := initializationRows(t, f.db)
	keys := initializationSecrets(t, f.db)
	c := f.client.K8sC.(*fake.Clientset)
	c.ClearActions()
	require.ErrorContains(t, f.genesis.RunUpgrade(t.Context(), nil), "another Cluster initialization")
	assertTargetReadOnly(t, c)
	assert.Equal(t, before, initializationRows(t, f.db))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
}

func TestUpgradeAfterClusterConfigAppliedWithoutAnnotationsE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	cc, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, cc.Metadata.Annotations[initializationIDKey])
	_, err = admin.NewServer(&admin.Opts{OcteliumC: f.genesis.octeliumC, IsEmbedded: true}).UpdateClusterConfig(t.Context(), &corev1.ClusterConfig{
		Kind:       cc.Kind,
		ApiVersion: cc.ApiVersion,
		Metadata:   &metav1.Metadata{Name: "default"},
		Spec:       cc.Spec,
	})
	require.NoError(t, err)
	cc, err = f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.NoError(t, err)
	require.Empty(t, cc.Metadata.Annotations[initializationIDKey])
	require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
}

func TestCopiedKubernetesInstallationRejectedE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	c := newFakeClient()
	_, err := c.K8sC.CoreV1().Namespaces().Create(t.Context(), &corev1k8s.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS}}, k8smetav1.CreateOptions{})
	require.NoError(t, err)
	secrets, err := f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).List(t.Context(), k8smetav1.ListOptions{})
	require.NoError(t, err)
	for _, secret := range secrets.Items {
		require.NoError(t, c.K8sC.(*fake.Clientset).Tracker().Add(secret.DeepCopy()))
	}
	cm, err := f.client.K8sC.CoreV1().ConfigMaps(vutils.K8sNS).Get(t.Context(), installationConfigMapName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	require.NoError(t, c.K8sC.(*fake.Clientset).Tracker().Add(cm))
	g := &Genesis{k8sC: c.K8sC, nadC: c.NadC}
	before := initializationRows(t, f.db)
	c.K8sC.(*fake.Clientset).ClearActions()
	require.ErrorContains(t, g.RunUpgrade(t.Context(), nil), "another Kubernetes namespace")
	require.ErrorContains(t, g.RunInit(t.Context(), nil), "another Kubernetes namespace")
	assertTargetReadOnly(t, c.K8sC.(*fake.Clientset))
	assert.Equal(t, before, initializationRows(t, f.db))
}

func TestLegacyTargetMigrationAndRotationE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	c := f.client.K8sC.(*fake.Clientset)
	require.NoError(t, c.CoreV1().Secrets(vutils.K8sNS).Delete(t.Context(), initializationSecretName, k8smetav1.DeleteOptions{}))
	cm, err := c.CoreV1().ConfigMaps(vutils.K8sNS).Get(t.Context(), installationConfigMapName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	cm.Annotations = map[string]string{"customer": "preserved"}
	cm.Data["customer"] = "preserved"
	configuration := cm.Data[installationConfigMapKey]
	require.NoError(t, c.Tracker().Update(corev1k8s.SchemeGroupVersion.WithResource("configmaps"), cm, vutils.K8sNS))
	for _, name := range []string{"octelium-postgres", "octelium-redis"} {
		secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
		require.NoError(t, err)
		secret.Annotations = nil
		require.NoError(t, c.Tracker().Update(corev1k8s.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
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
				require.NoError(t, c.Tracker().Update(corev1k8s.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
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
	_, err = c.K8sC.CoreV1().Namespaces().Create(t.Context(), &corev1k8s.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS}}, k8smetav1.CreateOptions{})
	require.NoError(t, err)
	_, err = c.K8sC.CoreV1().Secrets(vutils.K8sNS).Create(t.Context(), &corev1k8s.Secret{
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
