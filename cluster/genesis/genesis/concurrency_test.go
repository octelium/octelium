package genesis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func concurrentGenesisFixture(t *testing.T) (*Genesis, *fake.Clientset) {
	t.Helper()
	labels := map[string]string{"octelium.com/component": "genesis"}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "own-job", Namespace: "octelium", UID: "own-job-uid", Labels: labels}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "own-pod", Namespace: job.Namespace, UID: "own-pod-uid", Labels: labels,
			OwnerReferences: []metav1.OwnerReference{{Kind: "Job", Name: job.Name, UID: job.UID, Controller: new(true)}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	c := fake.NewSimpleClientset(job, pod)
	return &Genesis{k8sC: c, pod: pod.DeepCopy()}, c
}

func TestGenesisRejectsOtherWorkers(t *testing.T) {
	for _, namespace := range []string{"default", "octelium"} {
		for _, phase := range []corev1.PodPhase{corev1.PodPending, corev1.PodRunning, corev1.PodUnknown, corev1.PodSucceeded, corev1.PodFailed} {
			t.Run(namespace+"/"+string(phase), func(t *testing.T) {
				g, c := concurrentGenesisFixture(t)
				pod := g.pod.DeepCopy()
				pod.Name, pod.Namespace, pod.UID, pod.Status.Phase = "other-worker", namespace, "other-uid", phase
				require.NoError(t, c.Tracker().Add(pod))
				err := g.checkConcurrentGenesis(t.Context())
				if phase == corev1.PodSucceeded || phase == corev1.PodFailed {
					require.NoError(t, err)
				} else {
					require.ErrorContains(t, err, "may still be running")
				}
			})
		}
	}
}

func TestGenesisRejectsOtherJobs(t *testing.T) {
	for _, state := range []string{"pending", "running", "terminating", "complete", "failed", "suspended"} {
		t.Run(state, func(t *testing.T) {
			g, c := concurrentGenesisFixture(t)
			job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "package-job", Namespace: "default", UID: "package-uid", Labels: g.pod.Labels}}
			switch state {
			case "terminating":
				job.DeletionTimestamp = new(metav1.Now())
			case "complete":
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
			case "failed":
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
			case "suspended":
				job.Spec.Suspend = new(true)
			}
			require.NoError(t, c.Tracker().Add(job))
			err := g.checkConcurrentGenesis(t.Context())
			if state == "complete" || state == "failed" || state == "suspended" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "still active")
			}
		})
	}
}

func TestGenesisRejectsStalePodIdentity(t *testing.T) {
	for _, state := range []string{"deleted", "replaced", "terminating", "failed", "orphan", "job-replaced", "job-complete"} {
		t.Run(state, func(t *testing.T) {
			g, c := concurrentGenesisFixture(t)
			pod := g.pod.DeepCopy()
			switch state {
			case "deleted":
				require.NoError(t, c.CoreV1().Pods(pod.Namespace).Delete(t.Context(), pod.Name, metav1.DeleteOptions{}))
			case "replaced":
				pod.UID = "new-identity"
			case "terminating":
				pod.DeletionTimestamp = new(metav1.Now())
			case "failed":
				pod.Status.Phase = corev1.PodFailed
			case "orphan":
				pod.OwnerReferences = nil
			case "job-replaced", "job-complete":
				job, err := c.BatchV1().Jobs(pod.Namespace).Get(t.Context(), "own-job", metav1.GetOptions{})
				require.NoError(t, err)
				if state == "job-replaced" {
					job.UID = "replacement"
				} else {
					job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
				}
				_, err = c.BatchV1().Jobs(job.Namespace).Update(t.Context(), job, metav1.UpdateOptions{})
				require.NoError(t, err)
			}
			if state != "deleted" {
				_, err := c.CoreV1().Pods(pod.Namespace).Update(t.Context(), pod, metav1.UpdateOptions{})
				require.NoError(t, err)
			}
			require.Error(t, g.checkConcurrentGenesis(t.Context()))
		})
	}
}

func TestGenesisConcurrencyLookupFailure(t *testing.T) {
	for _, resource := range []string{"pods", "jobs"} {
		for _, verb := range []string{"get", "list"} {
			t.Run(verb+"/"+resource, func(t *testing.T) {
				g, c := concurrentGenesisFixture(t)
				want := k8serr.NewServiceUnavailable("temporary failure")
				c.PrependReactor(verb, resource, func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
				assert.ErrorIs(t, g.checkConcurrentGenesis(t.Context()), want)
				for _, action := range c.Actions() {
					assert.NotEqual(t, "delete", action.GetVerb())
					assert.NotEqual(t, "update", action.GetVerb())
				}
			})
		}
	}
}
