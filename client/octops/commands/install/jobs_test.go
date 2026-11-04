package install

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
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

const submissionJobName = "genesis-submission-test"

func newGenesisJobClient(t *testing.T) *fake.Clientset {
	t.Helper()
	c := fake.NewSimpleClientset()
	c.PrependReactor("*", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		switch action.GetVerb() {
		case "create":
			job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
			job.UID, job.ResourceVersion = types.UID(uuid.NewString()), "1"
			err := c.Tracker().Create(action.GetResource(), job, action.GetNamespace())
			return true, job, err
		case "update":
			job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job).DeepCopy()
			object, err := c.Tracker().Get(action.GetResource(), action.GetNamespace(), job.Name)
			if err != nil {
				return true, nil, err
			}
			current := object.(*batchv1.Job)
			if job.UID != current.UID || job.ResourceVersion != current.ResourceVersion {
				return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), job.Name, errors.New("stale Job"))
			}
			version, err := strconv.Atoi(current.ResourceVersion)
			require.NoError(t, err)
			job.ResourceVersion = strconv.Itoa(version + 1)
			err = c.Tracker().Update(action.GetResource(), job, action.GetNamespace())
			return true, job, err
		case "delete":
			a := action.(k8stesting.DeleteAction)
			object, err := c.Tracker().Get(action.GetResource(), action.GetNamespace(), a.GetName())
			if err != nil {
				return true, nil, err
			}
			current := object.(*batchv1.Job)
			pre := a.GetDeleteOptions().Preconditions
			if pre == nil || pre.UID == nil || pre.ResourceVersion == nil || *pre.UID != current.UID || *pre.ResourceVersion != current.ResourceVersion {
				return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), a.GetName(), errors.New("stale deletion"))
			}
			return true, nil, c.Tracker().Delete(action.GetResource(), action.GetNamespace(), a.GetName())
		}
		return false, nil, nil
	})
	return c
}

func testGenesisPreparation(context.Context) error {
	return nil
}

func testSubmissionJob(version string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: submissionJobName, Namespace: "octelium", Labels: map[string]string{"octelium.com/component": "genesis"}},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "genesis", Image: "genesis:" + version, Args: []string{"upgrade"}}},
		}}},
	}
}

func TestGenesisSubmissionWithoutPreparation(t *testing.T) {
	for _, state := range []string{"success", "create-failed", "response-lost", "readback-failed"} {
		t.Run(state, func(t *testing.T) {
			c := newGenesisJobClient(t)
			desired := testSubmissionJob("1.2.3")
			if state != "success" {
				c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if state != "create-failed" {
						require.NoError(t, c.Tracker().Create(action.GetResource(), action.(k8stesting.CreateAction).GetObject(), action.GetNamespace()))
					}
					return true, nil, io.ErrUnexpectedEOF
				})
			}
			if state == "readback-failed" {
				c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, k8serr.NewServiceUnavailable("temporary outage")
				})
			}
			err := SubmitGenesisJob(t.Context(), c, desired, nil)
			if state == "create-failed" || state == "readback-failed" {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			} else {
				require.NoError(t, err)
			}
			jobs, err := c.BatchV1().Jobs(desired.Namespace).List(t.Context(), metav1.ListOptions{})
			require.NoError(t, err)
			if state == "create-failed" {
				assert.Empty(t, jobs.Items)
			} else {
				require.Len(t, jobs.Items, 1)
				assert.Nil(t, jobs.Items[0].Spec.Suspend)
			}
			assert.Empty(t, desired.Annotations)
			for _, action := range c.Actions() {
				assert.NotEqual(t, "update", action.GetVerb())
				assert.NotEqual(t, "delete", action.GetVerb())
			}
		})
	}
}

func TestGenesisSubmissionAfterLegacyCompletion(t *testing.T) {
	for _, namespace := range []string{"default", "octelium"} {
		for _, phase := range []corev1.PodPhase{corev1.PodSucceeded, corev1.PodRunning} {
			t.Run(namespace+"/"+string(phase), func(t *testing.T) {
				c := newGenesisJobClient(t)
				previous := &batchv1.Job{
					ObjectMeta: metav1.ObjectMeta{Name: "octelium-genesis-upgrade-cordium-abcdef", Namespace: namespace, Labels: map[string]string{"octelium.com/component": "genesis"}},
					Status:     batchv1.JobStatus{Succeeded: 1},
				}
				require.NoError(t, c.Tracker().Add(previous))
				require.NoError(t, c.Tracker().Add(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: previous.Name, Namespace: namespace, Labels: previous.Labels}, Status: corev1.PodStatus{Phase: phase}}))
				err := SubmitGenesisJob(t.Context(), c, testSubmissionJob("1.2.3"), nil)
				if phase == corev1.PodRunning {
					require.ErrorContains(t, err, "may still be running")
				} else {
					require.NoError(t, err)
				}
				current, err := c.BatchV1().Jobs(namespace).Get(t.Context(), previous.Name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, previous, current)
			})
		}
	}
}

func TestGenesisSubmissionPreparesBeforeStarting(t *testing.T) {
	c := newGenesisJobClient(t)
	desired := testSubmissionJob("1.2.3")
	prepared := 0
	prepare := func(ctx context.Context) error {
		job, err := c.BatchV1().Jobs(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, job.Spec.Suspend)
		if prepared == 0 {
			assert.True(t, *job.Spec.Suspend)
		} else {
			assert.False(t, *job.Spec.Suspend)
		}
		prepared++
		return nil
	}
	require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, prepare))
	first, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.False(t, *first.Spec.Suspend)
	require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, prepare))
	second, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, first.UID, second.UID)
	assert.Equal(t, 2, prepared)
	assert.Nil(t, desired.Spec.Suspend)
	assert.Empty(t, desired.Annotations)
	for _, version := range []string{"2.0.0", "3.0.0"} {
		require.ErrorContains(t, SubmitGenesisJob(t.Context(), c, testSubmissionJob(version), prepare), "different request")
	}
	assert.Equal(t, 2, prepared)
	current, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, first, current)
}

func TestGenesisSubmissionConcurrentRequests(t *testing.T) {
	c := newGenesisJobClient(t)
	var wg sync.WaitGroup
	var started atomic.Int32
	start := make(chan struct{})
	for i := range 8 {
		wg.Go(func() {
			<-start
			if SubmitGenesisJob(t.Context(), c, testSubmissionJob(fmt.Sprint(i)), testGenesisPreparation) == nil {
				started.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	assert.Equal(t, int32(1), started.Load())
	jobs, err := c.BatchV1().Jobs("octelium").List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, jobs.Items, 1)
	assert.False(t, *jobs.Items[0].Spec.Suspend)
}

func TestGenesisSubmissionAmbiguousResponses(t *testing.T) {
	for _, verb := range []string{"create", "update"} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/committed=%t", verb, committed), func(t *testing.T) {
				c := newGenesisJobClient(t)
				failed := false
				c.PrependReactor(verb, "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if failed {
						return false, nil, nil
					}
					failed = true
					if committed {
						if verb == "create" {
							job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
							job.UID, job.ResourceVersion = types.UID(uuid.NewString()), "1"
							require.NoError(t, c.Tracker().Create(action.GetResource(), job, action.GetNamespace()))
						} else {
							require.NoError(t, c.Tracker().Update(action.GetResource(), action.(k8stesting.UpdateAction).GetObject(), action.GetNamespace()))
						}
					}
					return true, nil, io.ErrUnexpectedEOF
				})
				desired := testSubmissionJob("1.2.3")
				err := SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation)
				if committed {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				}
				require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation))
				jobs, err := c.BatchV1().Jobs("octelium").List(t.Context(), metav1.ListOptions{})
				require.NoError(t, err)
				require.Len(t, jobs.Items, 1)
				assert.False(t, *jobs.Items[0].Spec.Suspend)
			})
		}
	}
}

func TestGenesisSubmissionLegacyJobsAndPods(t *testing.T) {
	for _, namespace := range []string{"default", "octelium"} {
		for _, state := range []string{"pending-job", "running", "unknown", "terminating", "terminal"} {
			t.Run(namespace+"/"+state, func(t *testing.T) {
				c := newGenesisJobClient(t)
				legacy := testSubmissionJob("legacy")
				legacy.Name, legacy.Namespace = "octelium-genesis-legacy", namespace
				if state != "pending-job" {
					legacy.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
				}
				require.NoError(t, c.Tracker().Add(legacy))
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "legacy-worker", Namespace: namespace, Labels: legacy.Labels}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
				switch state {
				case "unknown":
					pod.Status.Phase = corev1.PodUnknown
				case "terminating":
					pod.DeletionTimestamp = new(metav1.Now())
				case "terminal":
					pod.Status.Phase = corev1.PodFailed
				}
				if state != "pending-job" {
					require.NoError(t, c.Tracker().Add(pod))
				}
				prepared := false
				err := SubmitGenesisJob(t.Context(), c, testSubmissionJob("1.2.3"), func(context.Context) error { prepared = true; return nil })
				if state == "terminal" {
					require.NoError(t, err)
					assert.True(t, prepared)
				} else {
					require.Error(t, err)
					assert.False(t, prepared)
				}
			})
		}
	}
}

func TestGenesisSubmissionCompletedJobReplacement(t *testing.T) {
	c := newGenesisJobClient(t)
	desired := testSubmissionJob("1.2.3")
	require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation))
	first, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, metav1.GetOptions{})
	require.NoError(t, err)
	first.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	_, err = c.BatchV1().Jobs(first.Namespace).Update(t.Context(), first, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation))
	second, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.NotEqual(t, first.UID, second.UID)
	assert.False(t, *second.Spec.Suspend)
}

func TestGenesisSubmissionConflictsAndLookupFailures(t *testing.T) {
	for _, resource := range []string{"jobs", "pods"} {
		t.Run(resource, func(t *testing.T) {
			c := newGenesisJobClient(t)
			want := k8serr.NewServiceUnavailable("temporary outage")
			c.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
			prepared := false
			assert.ErrorIs(t, SubmitGenesisJob(t.Context(), c, testSubmissionJob("1.2.3"), func(context.Context) error { prepared = true; return nil }), want)
			assert.False(t, prepared)
			for _, action := range c.Actions() {
				assert.False(t, action.Matches("create", "jobs"))
			}
		})
	}
	c := newGenesisJobClient(t)
	conflicted := false
	c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if conflicted {
			return false, nil, nil
		}
		conflicted = true
		return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), submissionJobName, errors.New("controller status changed"))
	})
	require.NoError(t, SubmitGenesisJob(t.Context(), c, testSubmissionJob("1.2.3"), testGenesisPreparation))
	assert.True(t, conflicted)
}

func TestGenesisSubmissionChecksAfterRegistration(t *testing.T) {
	c := newGenesisJobClient(t)
	err := SubmitGenesisJob(t.Context(), c, testSubmissionJob("1.2.3"), func(context.Context) error {
		other := testSubmissionJob("2.0.0")
		other.Name, other.Namespace = "octelium-genesis", "default"
		return c.Tracker().Add(other)
	})
	require.ErrorContains(t, err, "still active")
	jobs, err := c.BatchV1().Jobs("octelium").List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, jobs.Items)
}

func TestGenesisSubmissionCleanupPreservesStartedJob(t *testing.T) {
	c := newGenesisJobClient(t)
	desired := testSubmissionJob("1.2.3")
	want := errors.New("preparer stopped")
	err := SubmitGenesisJob(t.Context(), c, desired, func(ctx context.Context) error {
		job, err := c.BatchV1().Jobs(desired.Namespace).Get(ctx, desired.Name, metav1.GetOptions{})
		require.NoError(t, err)
		job.Spec.Suspend = new(false)
		_, err = c.BatchV1().Jobs(job.Namespace).Update(ctx, job, metav1.UpdateOptions{})
		require.NoError(t, err)
		return want
	})
	require.ErrorIs(t, err, want)
	job, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.False(t, *job.Spec.Suspend)
}

func TestGenesisSubmissionDeletionRace(t *testing.T) {
	c := newGenesisJobClient(t)
	desired := testSubmissionJob("1.2.3")
	require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation))
	old, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, metav1.GetOptions{})
	require.NoError(t, err)
	old.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
	_, err = c.BatchV1().Jobs(old.Namespace).Update(t.Context(), old, metav1.UpdateOptions{})
	require.NoError(t, err)
	newUID := types.UID(uuid.NewString())
	c.PrependReactor("delete", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		current := desired.DeepCopy()
		current.UID, current.ResourceVersion = newUID, "1"
		require.NoError(t, c.Tracker().Update(action.GetResource(), current, current.Namespace))
		return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), current.Name, errors.New("replaced"))
	})
	require.Error(t, SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation))
	current, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, newUID, current.UID)
}

func TestBootstrapReplacementIsRefused(t *testing.T) {
	c := newGenesisJobClient(t)
	o := &Opts{K8sC: c, ClusterDomain: "original.example"}
	require.NoError(t, setClusterResources(t.Context(), o))
	before, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	o.ClusterDomain = "replacement.example"
	require.ErrorContains(t, setClusterResources(t.Context(), o), "bootstrap differs")
	after, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestActiveInitializationRejectsDifferentBootstrap(t *testing.T) {
	c := newGenesisJobClient(t)
	bootstrap := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: localhost, password: original}}}"), bootstrap))
	o := &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap}
	_, err := createGenesis(t.Context(), o)
	require.NoError(t, err)
	beforeJob, err := c.BatchV1().Jobs("default").Get(t.Context(), genesisJobName, metav1.GetOptions{})
	require.NoError(t, err)
	beforeSecret, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	replacement := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: localhost, password: replacement}}}"), replacement))
	o.Bootstrap = replacement
	_, err = createGenesis(t.Context(), o)
	require.ErrorContains(t, err, "bootstrap differs")
	afterJob, err := c.BatchV1().Jobs("default").Get(t.Context(), genesisJobName, metav1.GetOptions{})
	require.NoError(t, err)
	afterSecret, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, beforeJob, afterJob)
	assert.Equal(t, beforeSecret, afterSecret)
}

func TestConcurrentMatchingInitializations(t *testing.T) {
	c := newGenesisJobClient(t)
	var wg sync.WaitGroup
	var succeeded atomic.Int32
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			if _, err := createGenesis(t.Context(), &Opts{K8sC: c, ClusterDomain: "example.com"}); err == nil {
				succeeded.Add(1)
			} else {
				t.Errorf("Matching initialization retry failed: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	assert.Equal(t, int32(8), succeeded.Load())
	jobs, err := c.BatchV1().Jobs("default").List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, jobs.Items, 1)
	assert.False(t, *jobs.Items[0].Spec.Suspend)
}

func TestGenesisSubmissionReturnsAcceptedJobIdentity(t *testing.T) {
	for _, state := range []string{"created", "create-response-lost", "update-response-lost", "resumed", "replaced-completed"} {
		t.Run(state, func(t *testing.T) {
			c := newGenesisJobClient(t)
			if state == "create-response-lost" || state == "update-response-lost" {
				verb := "create"
				if state == "update-response-lost" {
					verb = "update"
				}
				c.PrependReactor(verb, "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
					var job *batchv1.Job
					var err error
					if verb == "create" {
						job = action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
						job.UID, job.ResourceVersion = types.UID(uuid.NewString()), "1"
						err = c.Tracker().Create(action.GetResource(), job, action.GetNamespace())
					} else {
						job = action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job).DeepCopy()
						err = c.Tracker().Update(action.GetResource(), job, action.GetNamespace())
					}
					require.NoError(t, err)
					return true, nil, io.ErrUnexpectedEOF
				})
			}
			o := &Opts{K8sC: c, ClusterDomain: "example.com"}
			accepted, err := createGenesis(t.Context(), o)
			require.NoError(t, err)
			require.NotEmpty(t, accepted.UID)
			if state == "resumed" || state == "replaced-completed" {
				previousUID := accepted.UID
				if state == "replaced-completed" {
					accepted.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
					_, err = c.BatchV1().Jobs(accepted.Namespace).Update(t.Context(), accepted, metav1.UpdateOptions{})
					require.NoError(t, err)
				}
				accepted, err = createGenesis(t.Context(), o)
				require.NoError(t, err)
				if state == "resumed" {
					assert.Equal(t, previousUID, accepted.UID)
				} else {
					assert.NotEqual(t, previousUID, accepted.UID)
				}
			}
			current, err := c.BatchV1().Jobs(accepted.Namespace).Get(t.Context(), accepted.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, current, accepted)
			require.NotNil(t, accepted.Spec.Suspend)
			assert.False(t, *accepted.Spec.Suspend)
		})
	}
}
