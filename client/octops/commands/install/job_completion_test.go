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
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestWaitGenesisJobOutcomes(t *testing.T) {
	for _, state := range []string{"complete", "pending", "failed", "replaced", "deleting", "missing", "counter-only", "active", "terminating", "complete-false", "complete-unknown", "failure-target", "success-criteria", "failure-after-complete"} {
		t.Run(state, func(t *testing.T) {
			expected, job := completedInstallationJob(), completedInstallationJob()
			expected.Namespace, job.Namespace = octeliumNS, octeliumNS
			switch state {
			case "pending":
				job.Status = batchv1.JobStatus{}
			case "failed":
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
			case "replaced":
				job.UID = "replacement"
			case "deleting":
				job.DeletionTimestamp = new(metav1.Now())
			case "counter-only":
				job.Status.Conditions = nil
			case "active":
				job.Status.Active = 1
			case "terminating":
				job.Status.Terminating = new(int32(1))
			case "complete-false":
				job.Status.Conditions[0].Status = corev1.ConditionFalse
			case "complete-unknown":
				job.Status.Conditions[0].Status = corev1.ConditionUnknown
			case "failure-target":
				job.Status.Conditions[0].Type = batchv1.JobFailureTarget
			case "success-criteria":
				job.Status.Conditions[0].Type = batchv1.JobSuccessCriteriaMet
			case "failure-after-complete":
				job.Status.Conditions = append(job.Status.Conditions, batchv1.JobCondition{Type: batchv1.JobFailed, Status: corev1.ConditionTrue})
			}
			c := fake.NewSimpleClientset(legacyInitialToken())
			if state != "missing" {
				require.NoError(t, c.Tracker().Add(job))
			}
			timeout := time.Second
			switch state {
			case "pending", "counter-only", "active", "terminating", "complete-false", "complete-unknown", "failure-target", "success-criteria":
				timeout = 20 * time.Millisecond
			}
			err := WaitGenesisJob(t.Context(), c, expected, time.Millisecond, timeout)
			switch state {
			case "complete":
				require.NoError(t, err)
			case "failed":
				require.ErrorContains(t, err, "BackoffLimitExceeded")
			case "failure-after-complete":
				require.ErrorContains(t, err, "failed")
			case "replaced":
				require.ErrorContains(t, err, "replaced")
			case "deleting":
				require.ErrorContains(t, err, "being deleted")
			case "missing":
				require.True(t, k8serr.IsNotFound(err), "%v", err)
			default:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			for _, action := range c.Actions() {
				assert.Contains(t, []string{"get", "list"}, action.GetVerb())
				assert.Contains(t, []string{"jobs", "pods"}, action.GetResource().Resource)
				assert.Equal(t, expected.Namespace, action.GetNamespace())
			}
		})
	}
}

func TestWaitGenesisJobRetriesTemporaryReads(t *testing.T) {
	for _, failure := range []error{
		io.EOF, io.ErrUnexpectedEOF, context.DeadlineExceeded,
		k8serr.NewServiceUnavailable("API unavailable"), k8serr.NewInternalError(errors.New("temporary storage failure")),
		k8serr.NewTooManyRequests("throttled", 1), k8serr.NewTimeoutError("timed out", 1),
		k8serr.NewServerTimeout(schema.GroupResource{Resource: "jobs"}, "get", 1),
		&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNRESET},
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			job := completedInstallationJob()
			c := fake.NewSimpleClientset(job)
			gets := 0
			c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
				gets++
				if gets <= 2 {
					return true, nil, failure
				}
				return false, nil, nil
			})
			require.NoError(t, WaitGenesisJob(t.Context(), c, job, time.Millisecond, 4*time.Second))
			assert.Equal(t, 3, gets)
		})
	}
}

func TestWaitGenesisJobRejectsPermanentReadErrors(t *testing.T) {
	for _, failure := range []error{
		k8serr.NewForbidden(schema.GroupResource{Resource: "jobs"}, "test", errors.New("permission denied")),
		k8serr.NewUnauthorized("expired credentials"), k8serr.NewBadRequest("invalid request"), errors.New("invalid response"),
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			job := completedInstallationJob()
			c := fake.NewSimpleClientset(job)
			gets := 0
			c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
				gets++
				return true, nil, failure
			})
			c.PrependReactor("list", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, failure
			})
			require.ErrorIs(t, WaitGenesisJob(t.Context(), c, job, time.Millisecond, time.Second), failure)
			assert.Equal(t, 1, gets)
		})
	}
}

func TestWaitGenesisJobIgnoresOtherOperations(t *testing.T) {
	job := completedInstallationJob()
	job.Namespace = octeliumNS
	job.Status = batchv1.JobStatus{Active: 1}
	otherNamespace := completedInstallationJob()
	otherJob := completedInstallationJob()
	otherJob.Namespace, otherJob.Name, otherJob.UID = octeliumNS, "another-upgrade", "another-job"
	c := fake.NewSimpleClientset(job, otherNamespace, otherJob, legacyInitialToken())
	err := WaitGenesisJob(t.Context(), c, job, time.Millisecond, 20*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	for _, action := range c.Actions() {
		if action.GetResource().Resource == "jobs" {
			assert.Equal(t, job.Namespace, action.GetNamespace())
			assert.Equal(t, job.Name, action.(k8stesting.GetAction).GetName())
		}
		assert.NotEqual(t, "secrets", action.GetResource().Resource)
	}
}

func TestWaitGenesisJobCancellationAndOutage(t *testing.T) {
	for _, state := range []string{"cancelled-before-read", "cancelled-during-read", "cancelled-after-successful-read", "deadline", "api-outage"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			c := fake.NewSimpleClientset(job)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if state == "cancelled-before-read" {
				cancel()
			}
			c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
				switch state {
				case "cancelled-during-read":
					cancel()
					return true, nil, context.Canceled
				case "cancelled-after-successful-read":
					cancel()
					return true, job, nil
				case "deadline":
					current := job.DeepCopy()
					current.Status = batchv1.JobStatus{Active: 1}
					return true, current, nil
				case "api-outage":
					return true, nil, k8serr.NewServiceUnavailable("API outage")
				}
				return false, nil, nil
			})
			timeout := time.Second
			if state == "deadline" || state == "api-outage" {
				timeout = 20 * time.Millisecond
			}
			err := WaitGenesisJob(ctx, c, job, time.Millisecond, timeout)
			if state == "deadline" || state == "api-outage" {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			} else {
				require.ErrorIs(t, err, context.Canceled)
			}
			if state == "cancelled-before-read" {
				assert.Empty(t, c.Actions())
			}
			if state == "api-outage" {
				assert.Contains(t, err.Error(), "API outage")
			}
			assert.Contains(t, err.Error(), string(job.UID))
		})
	}
}

func TestWaitGenesisJobPodFailuresCanRecover(t *testing.T) {
	for _, state := range []string{"Unschedulable", "ImagePullBackOff", "Failed"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			pod := initializationPod(job)
			switch state {
			case "Unschedulable":
				pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: state, Message: "Insufficient memory"}}
			case "ImagePullBackOff":
				pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "genesis", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: state}}}}
			case "Failed":
				pod.Status.Phase = corev1.PodFailed
				pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "genesis", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 1}}}}
			}
			c := fake.NewSimpleClientset(job, pod)
			gets := 0
			c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
				gets++
				if gets == 1 {
					current := job.DeepCopy()
					current.Status = batchv1.JobStatus{Failed: 1}
					return true, current, nil
				}
				return false, nil, nil
			})
			require.NoError(t, WaitGenesisJob(t.Context(), c, job, time.Millisecond, time.Second))
			assert.Equal(t, 2, gets)
			assert.Contains(t, genesisPodStatus(t.Context(), c, job), state)
		})
	}
}

func TestWaitGenesisJobDiagnosticOutage(t *testing.T) {
	for _, failed := range []bool{false, true} {
		job := completedInstallationJob()
		job.Status = batchv1.JobStatus{}
		if failed {
			job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
		}
		c := fake.NewSimpleClientset(job)
		c.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, k8serr.NewServiceUnavailable("Pod API unavailable")
		})
		timeout := 20 * time.Millisecond
		if failed {
			timeout = time.Second
		}
		err := WaitGenesisJob(t.Context(), c, job, time.Millisecond, timeout)
		if failed {
			require.ErrorContains(t, err, "BackoffLimitExceeded")
		} else {
			require.ErrorIs(t, err, context.DeadlineExceeded)
		}
		assert.Contains(t, err.Error(), "Pod API unavailable")
	}
}

func TestWaitGenesisJobWithoutGetPermission(t *testing.T) {
	for _, state := range []string{"complete", "pending", "failed", "replaced", "missing", "wrong-namespace", "transient-list-error", "forbidden-list"} {
		t.Run(state, func(t *testing.T) {
			expected, job := completedInstallationJob(), completedInstallationJob()
			expected.Namespace, job.Namespace = octeliumNS, octeliumNS
			switch state {
			case "pending":
				job.Status = batchv1.JobStatus{Active: 1}
			case "failed":
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
			case "replaced":
				job.UID = "replacement"
			}
			other := completedInstallationJob()
			other.Namespace, other.Name = octeliumNS, "another-job"
			c := fake.NewSimpleClientset(other)
			if state != "missing" {
				require.NoError(t, c.Tracker().Add(job))
			}
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), job.Name, errors.New("get is not permitted"))
			})
			lists := 0
			c.PrependReactor("list", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				lists++
				assert.Equal(t, "metadata.name="+job.Name, action.(k8stesting.ListAction).GetListRestrictions().Fields.String())
				switch state {
				case "wrong-namespace":
					foreign := job.DeepCopy()
					foreign.Namespace = "default"
					return true, &batchv1.JobList{Items: []batchv1.Job{*foreign}}, nil
				case "transient-list-error":
					if lists == 1 {
						return true, nil, k8serr.NewServiceUnavailable("Temporary list outage")
					}
				case "forbidden-list":
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), job.Name, errors.New("list is not permitted"))
				}
				return false, nil, nil
			})
			timeout := time.Second
			if state == "pending" {
				timeout = 20 * time.Millisecond
			}
			err := WaitGenesisJob(t.Context(), c, expected, time.Millisecond, timeout)
			switch state {
			case "complete", "transient-list-error":
				require.NoError(t, err)
			case "pending":
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case "failed":
				require.ErrorContains(t, err, "BackoffLimitExceeded")
			case "replaced":
				require.ErrorContains(t, err, "replaced")
			case "missing", "wrong-namespace":
				require.True(t, k8serr.IsNotFound(err), "%v", err)
			case "forbidden-list":
				require.True(t, k8serr.IsForbidden(err), "%v", err)
			}
			assert.Positive(t, lists)
		})
	}
}
