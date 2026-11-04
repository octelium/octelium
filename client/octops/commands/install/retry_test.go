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
	"context"
	"io"
	"testing"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestPreflightReadRecoveryPreservesInstalledGuard(t *testing.T) {
	for _, name := range []string{"init-token", initializationSecretName, "octelium-init", installationConfigMapName} {
		t.Run(name, func(t *testing.T) {
			var existing runtime.Object = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: octeliumNS, Annotations: map[string]string{initializationCompleteKey: "true"}}}
			if name == installationConfigMapName {
				existing = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: octeliumNS}}
			}
			c := fake.NewSimpleClientset(existing)
			failed := false
			c.PrependReactor("get", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if action.(k8stesting.GetAction).GetName() == name && !failed {
					failed = true
					return true, nil, io.ErrUnexpectedEOF
				}
				return false, nil, nil
			})
			require.ErrorContains(t, DoInstall(t.Context(), &Opts{K8sC: c}), "octops upgrade")
			require.True(t, failed)
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
			}
		})
	}
}

func TestBootstrapCreateReadbackRecovery(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		c := fake.NewSimpleClientset()
		created, readFailed := false, false
		creates := 0
		c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			creates++
			created = true
			secret := action.(k8stesting.CreateAction).GetObject().(*corev1.Secret).DeepCopy()
			if foreign {
				secret.Data["domain"] = []byte("another.example")
			}
			require.NoError(t, c.Tracker().Create(action.GetResource(), secret, action.GetNamespace()))
			return true, nil, io.ErrUnexpectedEOF
		})
		c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			if created && !readFailed {
				readFailed = true
				return true, nil, k8serr.NewServiceUnavailable("readback is temporarily unavailable")
			}
			return false, nil, nil
		})
		err := setClusterResources(t.Context(), &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: &cbootstrapv1.Config{}})
		if foreign {
			require.ErrorContains(t, err, "bootstrap differs")
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, 1, creates)
		assert.True(t, readFailed)
		for _, action := range c.Actions() {
			assert.NotEqual(t, "update", action.GetVerb())
			assert.NotEqual(t, "delete", action.GetVerb())
		}
	}
}

func TestJobSubmissionRecoversEachKubernetesBoundary(t *testing.T) {
	for _, stage := range []string{"lookup", "list-jobs", "list-pods", "create-readback", "start-read", "start-write", "start-ack", "delete-before", "delete-ack", "delete-readback", "deletion-wait"} {
		t.Run(stage, func(t *testing.T) {
			c := newGenesisJobClient(t)
			desired := testSubmissionJob("1.2.3")
			if stage == "delete-before" || stage == "delete-ack" || stage == "delete-readback" || stage == "deletion-wait" {
				previous, err := SubmitGenesisJobWithResult(t.Context(), c, desired, testGenesisPreparation)
				require.NoError(t, err)
				previous.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
				require.NoError(t, c.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), previous, previous.Namespace))
			}
			failed, prepared, created, deleted := false, false, false, false
			readFailed := false
			updates, removes := 0, 0
			c.PrependReactor("*", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
				resource := action.GetResource().Resource
				switch action.GetVerb() {
				case "list":
					if !failed && (stage == "list-jobs" && resource == "jobs" || stage == "list-pods" && resource == "pods") {
						failed = true
						return true, nil, k8serr.NewServiceUnavailable("list outage")
					}
				case "get":
					if resource != "jobs" {
						break
					}
					if !failed && (stage == "lookup" || stage == "start-read" && prepared || stage == "deletion-wait" && deleted) {
						failed = true
						return true, nil, io.ErrUnexpectedEOF
					}
					if !readFailed && (stage == "create-readback" && created || stage == "delete-readback" && deleted) {
						readFailed = true
						return true, nil, k8serr.NewServiceUnavailable("readback outage")
					}
				case "create":
					if resource == "jobs" && stage == "create-readback" && !failed {
						failed, created = true, true
						job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
						job.UID, job.ResourceVersion = types.UID("committed-job"), "1"
						require.NoError(t, c.Tracker().Create(action.GetResource(), job, action.GetNamespace()))
						return true, nil, io.ErrUnexpectedEOF
					}
				case "update":
					if resource == "jobs" {
						updates++
						if !failed && (stage == "start-write" || stage == "start-ack") {
							failed = true
							if stage == "start-ack" {
								job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job).DeepCopy()
								job.ResourceVersion = "2"
								require.NoError(t, c.Tracker().Update(action.GetResource(), job, job.Namespace))
							}
							return true, nil, io.ErrUnexpectedEOF
						}
					}
				case "delete":
					if resource == "jobs" {
						removes++
						if !failed && (stage == "delete-before" || stage == "delete-ack" || stage == "delete-readback") {
							failed = true
							if stage != "delete-before" {
								deleted = true
								require.NoError(t, c.Tracker().Delete(action.GetResource(), action.GetNamespace(), action.(k8stesting.DeleteAction).GetName()))
							}
							return true, nil, io.ErrUnexpectedEOF
						}
						if stage == "deletion-wait" {
							deleted = true
						}
					}
				}
				return false, nil, nil
			})
			accepted, err := SubmitGenesisJobWithResult(t.Context(), c, desired, func(context.Context) error { prepared = true; return nil })
			require.NoError(t, err)
			require.True(t, failed)
			assert.NotEmpty(t, accepted.UID)
			require.NotNil(t, accepted.Spec.Suspend)
			assert.False(t, *accepted.Spec.Suspend)
			if stage == "start-ack" {
				assert.Equal(t, 1, updates)
			}
			if stage == "delete-ack" || stage == "delete-readback" {
				assert.Equal(t, 1, removes)
			}
		})
	}
}

func TestGeneratedJobCreationIsNotReplayed(t *testing.T) {
	c := fake.NewSimpleClientset()
	job := testSubmissionJob("1.2.3")
	job.Name, job.GenerateName = "", "genesis-generated-"
	creates := 0
	c.PrependReactor("create", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		creates++
		return true, nil, io.ErrUnexpectedEOF
	})
	_, err := SubmitGenesisJobWithResult(t.Context(), c, job, nil)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Equal(t, 1, creates)
}
