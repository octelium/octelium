package genesis

import (
	"context"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

func TestGenesisLegacyJobNames(t *testing.T) {
	for _, name := range []string{"octelium-genesis", "octelium-genesis-upgrade-abcdef", "octelium-genesis-upgrade-octelium-abcdef"} {
		for _, namespace := range []string{"default", "octelium"} {
			t.Run(namespace+"/"+name, func(t *testing.T) {
				g, c := concurrentGenesisFixture(t)
				job, err := c.BatchV1().Jobs(g.pod.Namespace).Get(t.Context(), "own-job", metav1.GetOptions{})
				require.NoError(t, err)
				require.NoError(t, c.Tracker().Delete(batchv1.SchemeGroupVersion.WithResource("jobs"), job.Namespace, job.Name))
				job.Name, job.Namespace = name, namespace
				require.NoError(t, c.Tracker().Add(job))
				require.NoError(t, c.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), g.pod.Namespace, g.pod.Name))
				g.pod.Namespace = namespace
				g.pod.OwnerReferences[0].Name = name
				require.NoError(t, c.Tracker().Add(g.pod))
				require.Empty(t, job.Annotations)
				require.Nil(t, job.Spec.Suspend)
				require.Empty(t, g.pod.Spec.Containers)
				require.NoError(t, g.waitForConcurrentGenesis(t.Context()))
			})
		}
	}
}

func TestGenesisLegacyJobCompletion(t *testing.T) {
	for _, tc := range []struct {
		name        string
		succeeded   int32
		active      int32
		completions *int32
		phase       corev1.PodPhase
		busy        bool
	}{
		{"successful", 1, 0, nil, corev1.PodSucceeded, false},
		{"pods-collected", 1, 0, nil, "", false},
		{"fully-completed", 2, 0, new(int32(2)), corev1.PodSucceeded, false},
		{"incomplete", 1, 0, new(int32(2)), corev1.PodSucceeded, true},
		{"active-counter", 1, 1, nil, corev1.PodSucceeded, true},
		{"live-pod", 1, 0, nil, corev1.PodRunning, true},
		{"terminating-pod", 1, 0, nil, corev1.PodUnknown, true},
		{"failed-attempt", 0, 0, nil, corev1.PodFailed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, c := concurrentGenesisFixture(t)
			for _, name := range []string{"octelium-genesis-init-octeliumee-abcdef", "octelium-genesis-upgrade-cordium-abcdef"} {
				job := &batchv1.Job{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "octelium", Labels: g.pod.Labels},
					Spec:       batchv1.JobSpec{Completions: tc.completions},
					Status:     batchv1.JobStatus{Succeeded: tc.succeeded, Active: tc.active},
				}
				require.NoError(t, c.Tracker().Add(job))
				if tc.phase != "" {
					pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: job.Namespace, Labels: job.Labels}, Status: corev1.PodStatus{Phase: tc.phase}}
					require.NoError(t, c.Tracker().Add(pod))
				}
			}
			err := g.checkConcurrentGenesis(t.Context())
			if tc.busy {
				require.ErrorIs(t, err, errGenesisBusy)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGenesisPodIdentityCompatibility(t *testing.T) {
	hostname, err := os.Hostname()
	require.NoError(t, err)
	for _, tc := range []struct {
		name, podName, explicitName string
		customHostname              bool
	}{
		{"old-manifest", hostname, "", false},
		{"old-custom-hostname", "actual-pod", "", true},
		{"downward-api", "actual-pod", "actual-pod", true},
		{"invalid-downward-api", "actual-pod", "missing-pod", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OCTELIUM_GENESIS_POD_NAME", tc.explicitName)
			t.Setenv("OCTELIUM_GENESIS_POD_NAMESPACE", "octelium")
			namespace, err := genesisPodNamespace()
			require.NoError(t, err)
			g, c := concurrentGenesisFixture(t)
			pod := g.pod.DeepCopy()
			require.NoError(t, c.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), pod.Namespace, pod.Name))
			pod.Name = tc.podName
			if tc.customHostname {
				pod.Spec.Hostname = hostname
			}
			require.NoError(t, c.Tracker().Add(pod))
			g.pod, g.podNamespace = nil, namespace
			err = g.waitForConcurrentGenesis(t.Context())
			if tc.name == "invalid-downward-api" || tc.name == "old-custom-hostname" {
				require.True(t, k8serr.IsNotFound(err))
				assert.Nil(t, g.pod)
			} else {
				require.NoError(t, err)
				assert.Equal(t, pod.UID, g.pod.UID)
				assert.Equal(t, pod.Name, g.pod.Name)
			}
		})
	}
}

func TestGenesisPodIdentityRejectsAmbiguousHostname(t *testing.T) {
	t.Setenv("OCTELIUM_GENESIS_POD_NAME", "")
	g, c := concurrentGenesisFixture(t)
	hostname, err := os.Hostname()
	require.NoError(t, err)
	require.NoError(t, c.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), g.pod.Namespace, g.pod.Name))
	for _, name := range []string{hostname + "-first", hostname + "-second"} {
		pod := g.pod.DeepCopy()
		pod.Name, pod.Spec.Hostname = name, hostname
		require.NoError(t, c.Tracker().Add(pod))
	}
	g.pod, g.podNamespace = nil, "octelium"
	require.True(t, k8serr.IsNotFound(g.waitForConcurrentGenesis(t.Context())))
	assert.Nil(t, g.pod)
}

func TestGenesisWaitsForLegacyPodTermination(t *testing.T) {
	g, c := concurrentGenesisFixture(t)
	previous := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "previous-package", Namespace: "octelium", Labels: g.pod.Labels}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	require.NoError(t, c.Tracker().Add(previous))
	require.NoError(t, c.Tracker().Add(&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: previous.Name, Namespace: previous.Namespace, Labels: previous.Labels}, Status: batchv1.JobStatus{Succeeded: 1}}))
	lists := 0
	c.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetNamespace() == previous.Namespace {
			lists++
			if lists == 2 {
				previous.Status.Phase = corev1.PodSucceeded
				require.NoError(t, c.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), previous, previous.Namespace))
			}
		}
		return false, nil, nil
	})
	require.NoError(t, g.waitForConcurrentGenesis(t.Context()))
	assert.Equal(t, 2, lists)
}

func TestGenesisStartupRetriesTransientErrors(t *testing.T) {
	for _, want := range []error{
		k8serr.NewServiceUnavailable("temporary outage"), k8serr.NewInternalError(io.EOF),
		k8serr.NewTimeoutError("timeout", 1), k8serr.NewTooManyRequests("busy", 1),
		io.EOF, io.ErrUnexpectedEOF, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET},
		&net.DNSError{Err: "temporary DNS failure", IsTemporary: true},
	} {
		t.Run(want.Error(), func(t *testing.T) {
			g, c := concurrentGenesisFixture(t)
			calls := 0
			c.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				if calls == 1 {
					return true, nil, want
				}
				return false, nil, nil
			})
			require.NoError(t, g.waitForConcurrentGenesis(t.Context()))
			assert.Equal(t, 2, calls)
		})
	}
}

func TestGenesisStartupFailsClosed(t *testing.T) {
	for _, want := range []error{
		k8serr.NewForbidden(schema.GroupResource{Resource: "pods"}, "own-pod", io.EOF),
		k8serr.NewUnauthorized("invalid credentials"),
	} {
		t.Run(want.Error(), func(t *testing.T) {
			g, c := concurrentGenesisFixture(t)
			calls := 0
			c.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				return true, nil, want
			})
			require.ErrorIs(t, g.waitForConcurrentGenesis(t.Context()), want)
			assert.Equal(t, 1, calls)
		})
	}
	g, c := concurrentGenesisFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, g.waitForConcurrentGenesis(ctx), context.Canceled)
	assert.Empty(t, c.Actions())
	c.PrependReactor("list", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serr.NewServiceUnavailable("still unavailable")
	})
	ctx, cancel = context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, g.waitForConcurrentGenesis(ctx), context.DeadlineExceeded)
	for _, action := range c.Actions() {
		assert.NotEqual(t, "delete", action.GetVerb())
		assert.NotEqual(t, "update", action.GetVerb())
	}
}
