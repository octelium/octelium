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
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
