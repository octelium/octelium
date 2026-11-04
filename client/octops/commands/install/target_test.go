package install

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func testTargetAnnotations() map[string]string {
	return map[string]string{targetClusterUID: "cluster-uid", targetDomain: "example.com", targetRegionUID: "region-uid", targetRegionName: "west", targetNamespaceUID: "namespace-uid"}
}

func TestGenesisJobTargetBinding(t *testing.T) {
	for _, state := range []string{"bound", "legacy-bootstrap", "legacy-map", "legacy-missing", "secret-forbidden", "bound-secret-forbidden", "canonical-domain", "domain-mismatch", "bootstrap-domain-mismatch", "region-mismatch", "bootstrap-region-mismatch", "bootstrap-region-uid-mismatch", "corrupt-region", "submitted-identity-mismatch"} {
		t.Run(state, func(t *testing.T) {
			c := fake.NewSimpleClientset()
			cm := &k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: installationConfigMapName, Namespace: octeliumNS}, Data: map[string]string{installationConfigMapKey: "{}"}}
			if state != "legacy-bootstrap" && state != "legacy-map" && state != "legacy-missing" && state != "secret-forbidden" {
				cm.Annotations = testTargetAnnotations()
			}
			if state != "legacy-bootstrap" && state != "legacy-missing" && state != "secret-forbidden" {
				require.NoError(t, c.Tracker().Add(cm))
			}
			bootstrap := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: octeliumNS}, Data: map[string][]byte{"domain": []byte("example.com"), "region": pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: "west", Uid: "region-uid"}})}}
			if state == "bootstrap-domain-mismatch" {
				bootstrap.Data["domain"] = []byte("another.example")
			}
			if state == "bootstrap-region-mismatch" {
				bootstrap.Data["region"] = pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: "east"}})
			}
			if state == "bootstrap-region-uid-mismatch" {
				bootstrap.Data["region"] = pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: "west", Uid: "another-uid"}})
			}
			if state == "corrupt-region" {
				bootstrap.Data["region"] = []byte{0xff}
			}
			if state != "legacy-map" && state != "legacy-missing" {
				require.NoError(t, c.Tracker().Add(bootstrap))
			}
			if state == "secret-forbidden" || state == "bound-secret-forbidden" {
				c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "octelium-init", fmt.Errorf("read is not permitted"))
				})
			}
			job := testSubmissionJob("1.2.3")
			job.Spec.Template.Spec.Containers[0].Env = []k8scorev1.EnvVar{{Name: "OCTELIUM_DOMAIN", Value: "example.com"}, {Name: "OCTELIUM_REGION_NAME", Value: "default"}}
			if state == "canonical-domain" {
				job.Spec.Template.Spec.Containers[0].Env[0].Value = "Example.COM."
			}
			if state == "domain-mismatch" {
				job.Spec.Template.Spec.Containers[0].Env[0].Value = "another.example"
			}
			if state == "region-mismatch" {
				job.Spec.Template.Spec.Containers[0].Env[1].Value = "east"
			}
			if state == "submitted-identity-mismatch" {
				job.Spec.Template.Spec.Containers[0].Env = append(job.Spec.Template.Spec.Containers[0].Env, k8scorev1.EnvVar{Name: "OCTELIUM_GENESIS_CLUSTER_UID", Value: "another-cluster"})
			}
			original := job.DeepCopy()
			accepted, err := BindGenesisJobTarget(t.Context(), c, job)
			if state == "domain-mismatch" || state == "bootstrap-domain-mismatch" || state == "region-mismatch" || state == "bootstrap-region-mismatch" || state == "bootstrap-region-uid-mismatch" || state == "corrupt-region" || state == "submitted-identity-mismatch" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				env := map[string]string{}
				for _, value := range accepted.Spec.Template.Spec.Containers[0].Env {
					env[value.Name] = value.Value
				}
				if cm.Annotations != nil {
					assert.Equal(t, "cluster-uid", env["OCTELIUM_GENESIS_CLUSTER_UID"])
					assert.Equal(t, "region-uid", env["OCTELIUM_GENESIS_REGION_UID"])
					assert.Equal(t, "namespace-uid", env["OCTELIUM_GENESIS_NAMESPACE_UID"])
				} else {
					assert.NotContains(t, env, "OCTELIUM_GENESIS_CLUSTER_UID")
				}
				if state != "legacy-map" && state != "legacy-missing" && state != "secret-forbidden" {
					assert.Equal(t, "west", env["OCTELIUM_REGION_NAME"])
				}
			}
			assert.Equal(t, original, job)
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
				assert.NotEqual(t, "namespaces", action.GetResource().Resource)
			}
		})
	}
}

func TestGenesisTargetRejectsIncompleteIdentity(t *testing.T) {
	for _, key := range []string{targetClusterUID, targetDomain, targetRegionUID, targetRegionName, targetNamespaceUID} {
		c := fake.NewSimpleClientset()
		annotations := testTargetAnnotations()
		delete(annotations, key)
		require.NoError(t, c.Tracker().Add(&k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: installationConfigMapName, Namespace: octeliumNS, Annotations: annotations}}))
		_, err := BindGenesisJobTarget(t.Context(), c, testSubmissionJob("1.2.3"))
		require.ErrorContains(t, err, "identity is incomplete")
		for _, action := range c.Actions() {
			assert.Equal(t, "get", action.GetVerb())
		}
	}
}

func TestLegacyJobSubmissionDoesNotRequireTargetReads(t *testing.T) {
	c := newGenesisJobClient(t)
	c.PrependReactor("get", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), installationConfigMapName, fmt.Errorf("legacy Job-only role"))
	})
	require.NoError(t, SubmitGenesisJob(t.Context(), c, testSubmissionJob("1.2.3"), nil))
	for _, action := range c.Actions() {
		assert.NotEqual(t, "configmaps", action.GetResource().Resource)
		assert.NotEqual(t, "secrets", action.GetResource().Resource)
		assert.NotEqual(t, "namespaces", action.GetResource().Resource)
	}
}

func TestGenesisTargetReadFailures(t *testing.T) {
	for _, resource := range []string{"configmaps", "secrets"} {
		for _, failure := range []string{"transient", "forbidden", "cancelled", "persistent"} {
			t.Run(resource+"/"+failure, func(t *testing.T) {
				c := fake.NewSimpleClientset()
				reads := 0
				c.PrependReactor("get", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
					reads++
					if failure == "transient" && reads > 1 {
						return false, nil, nil
					}
					if failure == "forbidden" {
						return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "target", fmt.Errorf("forbidden"))
					}
					return true, nil, io.ErrUnexpectedEOF
				})
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if failure == "cancelled" {
					cancel()
				}
				if failure == "persistent" {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 50*time.Millisecond)
					defer stop()
				}
				_, err := BindGenesisJobTarget(ctx, c, testSubmissionJob("1.2.3"))
				switch {
				case failure == "transient", failure == "forbidden" && resource == "secrets":
					require.NoError(t, err)
				case failure == "forbidden":
					require.True(t, k8serr.IsForbidden(err))
				case failure == "cancelled":
					require.ErrorIs(t, err, context.Canceled)
					assert.Empty(t, c.Actions())
				case failure == "persistent":
					require.ErrorIs(t, err, context.DeadlineExceeded)
				}
			})
		}
	}
}
