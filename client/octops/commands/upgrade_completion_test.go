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

package commands

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestUpgradeCompletionE2E(t *testing.T) {
	for _, state := range []string{"already-complete", "same-version", "secondary-region", "legacy-cluster", "lost-create-response", "list-only-role", "failed-job", "failed-with-target-version", "pending-with-unrelated-version", "replaced-job", "deleted-job", "deleting-job", "cancelled", "retrying-pod"} {
		t.Run(state, func(t *testing.T) {
			var publicCalls atomic.Int32
			ctx := newTestCoreServer(t, func(_ context.Context, _ *metav1.GetOptions) (*corev1.Region, error) {
				n := publicCalls.Add(1)
				version := "1.2.3"
				if state == "pending-with-unrelated-version" {
					version = "1.0.0"
					if n > 1 {
						version = "1.1.0"
					}
				}
				return &corev1.Region{Status: &corev1.Region_Status{Version: version}}, nil
			})
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if state == "pending-with-unrelated-version" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 3*time.Second)
				defer deadlineCancel()
			}
			c, config := newTestKubernetes(t)
			if state == "secondary-region" || state == "legacy-cluster" {
				region := "default"
				if state == "secondary-region" {
					region = "europe"
				}
				require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{
					ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "octelium"},
					Data:       map[string][]byte{"region": pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: region}})},
				}))
			}
			var submitted atomic.Pointer[batchv1.Job]
			var reads atomic.Int32
			c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
				switch state {
				case "failed-job", "failed-with-target-version":
					job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
				case "pending-with-unrelated-version", "retrying-pod":
					job.Status = batchv1.JobStatus{Failed: 1}
				}
				submitted.Store(job.DeepCopy())
				if state == "lost-create-response" {
					assert.NoError(t, c.Tracker().Create(action.GetResource(), job, job.Namespace))
					return true, nil, k8serr.NewServiceUnavailable("Response lost after persisting Job")
				}
				return false, nil, nil
			})
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				n := reads.Add(1)
				accepted := submitted.Load()
				if accepted == nil {
					return false, nil, nil
				}
				assert.Equal(t, accepted.Namespace, action.GetNamespace())
				assert.Equal(t, accepted.Name, action.(k8stesting.GetAction).GetName())
				job := accepted.DeepCopy()
				switch state {
				case "list-only-role":
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), job.Name, fmt.Errorf("only list is permitted"))
				case "replaced-job":
					job.UID = "replacement"
					return true, job, nil
				case "deleted-job":
					return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), job.Name)
				case "deleting-job":
					job.DeletionTimestamp = new(k8smetav1.Now())
					return true, job, nil
				case "cancelled":
					cancel()
					return true, nil, context.Canceled
				case "retrying-pod":
					if n > 1 {
						job.Status = batchv1.JobStatus{Succeeded: 1, Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}}
					}
					return true, job, nil
				}
				return false, nil, nil
			})
			out, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--version=1.2.3", "--wait")
			switch state {
			case "failed-job", "failed-with-target-version", "pending-with-unrelated-version", "replaced-job", "deleted-job", "deleting-job", "cancelled":
				require.Error(t, err)
				assert.NotContains(t, out, "Cluster has been upgraded")
				if state == "cancelled" {
					assert.ErrorIs(t, err, context.Canceled)
				}
				if state == "pending-with-unrelated-version" {
					assert.ErrorIs(t, err, context.DeadlineExceeded)
				}
			default:
				require.NoError(t, err, out)
				assert.Contains(t, out, "Cluster has been upgraded")
			}
			assert.Zero(t, publicCalls.Load())
			accepted := submitted.Load()
			require.NotNil(t, accepted)
			assert.NotEmpty(t, accepted.UID)
			assert.Regexp(t, "^octelium-genesis-upgrade-[a-z0-9]{6}$", accepted.Name)
			assert.Nil(t, accepted.Spec.Suspend)
			assert.Equal(t, []string{"upgrade"}, accepted.Spec.Template.Spec.Containers[0].Args)
			assert.Contains(t, accepted.Spec.Template.Spec.Containers[0].Image, "octelium-genesis:1.2.3")
			for _, action := range c.Actions() {
				assert.NotEqual(t, "update", action.GetVerb())
				assert.NotEqual(t, "delete", action.GetVerb())
			}
		})
	}
}

func TestUpgradeWaitKubernetesAuthorizationFailureE2E(t *testing.T) {
	c, config := newTestKubernetes(t)
	c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "test", fmt.Errorf("permission denied"))
	})
	c.PrependReactor("list", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.ListAction).GetListRestrictions().Fields.String() != "" {
			return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "test", fmt.Errorf("permission denied"))
		}
		return false, nil, nil
	})
	out, err := executeTestCommand(t, t.Context(), "upgrade", "example.invalid", "--kubeconfig="+config, "--wait")
	require.True(t, k8serr.IsForbidden(err), "%v", err)
	assert.NotContains(t, out, "Cluster has been upgraded")
}

func TestUpgradeWaitWithoutPublicAPIE2E(t *testing.T) {
	var publicCalls atomic.Int32
	ctx := newTestCoreServer(t, func(context.Context, *metav1.GetOptions) (*corev1.Region, error) {
		publicCalls.Add(1)
		return nil, status.Error(codes.Unavailable, "Public API is temporarily unavailable during rollout")
	})
	c, config := newTestKubernetes(t)
	c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
		return false, nil, nil
	})
	out, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--wait")
	require.NoError(t, err)
	assert.Contains(t, out, "Cluster has been upgraded")
	assert.Zero(t, publicCalls.Load())
}

func TestUpgradeWithoutWaitDoesNotObserveJobE2E(t *testing.T) {
	c, config := newTestKubernetes(t)
	c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue}}
		return false, nil, nil
	})
	out, err := executeTestCommand(t, t.Context(), "upgrade", "example.invalid", "--kubeconfig="+config)
	require.NoError(t, err)
	assert.Contains(t, out, "Upgrading the Cluster has started")
	assert.NotContains(t, out, "Cluster has been upgraded")
	for _, action := range c.Actions() {
		assert.False(t, action.Matches("get", "jobs"))
		assert.NotEqual(t, "delete", action.GetVerb())
	}
}

func TestUpgradeCancelledBeforeSubmissionE2E(t *testing.T) {
	c, config := newTestKubernetes(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--wait")
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, c.Actions())
	assert.NotContains(t, out, "Upgrading the Cluster has started")
	assert.NotContains(t, out, "Cluster has been upgraded")
}
