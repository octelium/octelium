package k8sutils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func readyDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "namespace", Generation: 4},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(4)), MinReadySeconds: 30,
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{MaxUnavailable: new(intstr.FromInt(1))}},
		},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 4, Replicas: 4, UpdatedReplicas: 4, ReadyReplicas: 4, AvailableReplicas: 4},
	}
}

func readyDaemonSet() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "namespace", Generation: 4},
		Spec:       appsv1.DaemonSetSpec{MinReadySeconds: 30, UpdateStrategy: appsv1.DaemonSetUpdateStrategy{Type: appsv1.RollingUpdateDaemonSetStrategyType}},
		Status:     appsv1.DaemonSetStatus{ObservedGeneration: 4, CurrentNumberScheduled: 2, DesiredNumberScheduled: 2, UpdatedNumberScheduled: 2, NumberReady: 2, NumberAvailable: 2},
	}
}

func TestDeploymentReadiness(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*appsv1.Deployment)
		ready  bool
	}{
		{"complete", func(*appsv1.Deployment) {}, true},
		{"unobserved", func(d *appsv1.Deployment) { d.Status.ObservedGeneration = 0 }, false},
		{"previous-generation", func(d *appsv1.Deployment) { d.Status.ObservedGeneration-- }, false},
		{"newer-observation", func(d *appsv1.Deployment) { d.Status.ObservedGeneration++ }, true},
		{"partial-rollout", func(d *appsv1.Deployment) {
			d.Status.UpdatedReplicas = 3
			d.Status.ReadyReplicas = 3
			d.Status.AvailableReplicas = 3
		}, false},
		{"not-available-yet", func(d *appsv1.Deployment) { d.Status.AvailableReplicas = 3 }, false},
		{"old-replicas", func(d *appsv1.Deployment) { d.Status.Replicas = 5 }, false},
		{"missing-replica", func(d *appsv1.Deployment) { d.Status.Replicas = 3 }, false},
		{"scale-up", func(d *appsv1.Deployment) { d.Spec.Replicas = new(int32(5)) }, false},
		{"scale-down", func(d *appsv1.Deployment) { d.Spec.Replicas = new(int32(3)) }, false},
		{"recreate", func(d *appsv1.Deployment) {
			d.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
		}, true},
		{"default-strategy", func(d *appsv1.Deployment) { d.Spec.Strategy = appsv1.DeploymentStrategy{} }, true},
		{"paused-complete", func(d *appsv1.Deployment) { d.Spec.Paused = true }, true},
		{"deleting", func(d *appsv1.Deployment) { d.DeletionTimestamp = new(metav1.Now()) }, false},
		{"zero-replicas", func(d *appsv1.Deployment) {
			d.Spec.Replicas = new(int32(0))
			d.Status = appsv1.DeploymentStatus{ObservedGeneration: 4}
		}, true},
		{"zero-replicas-stale", func(d *appsv1.Deployment) {
			d.Spec.Replicas = new(int32(0))
			d.Status = appsv1.DeploymentStatus{ObservedGeneration: 3}
		}, false},
		{"default-replicas", func(d *appsv1.Deployment) {
			d.Spec.Replicas = nil
			d.Status = appsv1.DeploymentStatus{ObservedGeneration: 4, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}
		}, true},
		{"default-replicas-pending", func(d *appsv1.Deployment) {
			d.Spec.Replicas = nil
			d.Status = appsv1.DeploymentStatus{ObservedGeneration: 4}
		}, false},
		{"availability-budget-is-not-completion", func(d *appsv1.Deployment) {
			d.Spec.Strategy.RollingUpdate.MaxUnavailable = new(intstr.FromInt(4))
			d.Status.UpdatedReplicas = 0
			d.Status.AvailableReplicas = 0
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			deployment := readyDeployment()
			test.change(deployment)
			before := deployment.DeepCopy()
			ready, err := deploymentReadiness(deployment)
			require.NoError(t, err)
			assert.Equal(t, test.ready, ready)
			assert.Equal(t, before, deployment)
		})
	}
	ready, err := deploymentReadiness(nil)
	require.NoError(t, err)
	assert.False(t, ready)
}

func TestDeploymentReadinessConditions(t *testing.T) {
	for _, state := range []string{"deadline", "old-deadline", "recovered", "paused", "unknown", "true", "replica-failure", "available-is-not-complete"} {
		t.Run(state, func(t *testing.T) {
			d := readyDeployment()
			d.Status.AvailableReplicas = 3
			condition := appsv1.DeploymentCondition{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", Message: "the new replicas did not become available"}
			switch state {
			case "old-deadline":
				d.Status.ObservedGeneration--
			case "recovered":
				d.Status.AvailableReplicas = 4
			case "paused":
				d.Spec.Paused = true
			case "unknown":
				condition.Status = corev1.ConditionUnknown
			case "true":
				condition.Status = corev1.ConditionTrue
			case "replica-failure":
				condition.Type, condition.Status, condition.Reason = appsv1.DeploymentReplicaFailure, corev1.ConditionTrue, "FailedCreate"
			case "available-is-not-complete":
				condition.Type, condition.Status, condition.Reason = appsv1.DeploymentAvailable, corev1.ConditionTrue, "MinimumReplicasAvailable"
			}
			d.Status.Conditions = []appsv1.DeploymentCondition{condition}
			ready, err := deploymentReadiness(d)
			if state == "deadline" {
				require.ErrorContains(t, err, "namespace/test exceeded its progress deadline")
				assert.Contains(t, err.Error(), condition.Message)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, state == "recovered", ready)
		})
	}
}

func TestDaemonSetReadiness(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*appsv1.DaemonSet)
		ready  bool
	}{
		{"complete", func(*appsv1.DaemonSet) {}, true},
		{"unobserved", func(d *appsv1.DaemonSet) { d.Status.ObservedGeneration = 0 }, false},
		{"previous-generation", func(d *appsv1.DaemonSet) { d.Status.ObservedGeneration-- }, false},
		{"newer-observation", func(d *appsv1.DaemonSet) { d.Status.ObservedGeneration++ }, true},
		{"old-pods", func(d *appsv1.DaemonSet) { d.Status.UpdatedNumberScheduled = 1 }, false},
		{"not-ready", func(d *appsv1.DaemonSet) { d.Status.NumberReady = 1 }, false},
		{"not-available-yet", func(d *appsv1.DaemonSet) { d.Status.NumberAvailable = 1 }, false},
		{"deleting", func(d *appsv1.DaemonSet) { d.DeletionTimestamp = new(metav1.Now()) }, false},
		{"default-strategy", func(d *appsv1.DaemonSet) { d.Spec.UpdateStrategy = appsv1.DaemonSetUpdateStrategy{} }, true},
		{"default-strategy-old-pods", func(d *appsv1.DaemonSet) {
			d.Spec.UpdateStrategy = appsv1.DaemonSetUpdateStrategy{}
			d.Status.UpdatedNumberScheduled = 1
		}, false},
		{"on-delete-ready", func(d *appsv1.DaemonSet) {
			d.Spec.UpdateStrategy.Type = appsv1.OnDeleteDaemonSetStrategyType
			d.Status.UpdatedNumberScheduled = 0
		}, true},
		{"on-delete-unavailable", func(d *appsv1.DaemonSet) {
			d.Spec.UpdateStrategy.Type = appsv1.OnDeleteDaemonSetStrategyType
			d.Status.NumberAvailable = 1
		}, false},
		{"on-delete-unobserved", func(d *appsv1.DaemonSet) {
			d.Spec.UpdateStrategy.Type = appsv1.OnDeleteDaemonSetStrategyType
			d.Status.ObservedGeneration--
		}, false},
		{"observed-empty-node-set", func(d *appsv1.DaemonSet) { d.Status = appsv1.DaemonSetStatus{ObservedGeneration: 4} }, true},
		{"empty-status", func(d *appsv1.DaemonSet) { d.Status = appsv1.DaemonSetStatus{} }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ds := readyDaemonSet()
			test.change(ds)
			before := ds.DeepCopy()
			assert.Equal(t, test.ready, IsDaemonSetReady(ds))
			assert.Equal(t, before, ds)
		})
	}
	assert.False(t, IsDaemonSetReady(nil))
	assert.False(t, IsDaemonSetReady(&appsv1.DaemonSet{}))
}

func TestReadinessCompatibility(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, state := range []string{"zero-deployment", "default-replicas", "progress-deadline", "old-progress-deadline", "paused-progress-deadline", "zero-daemonset", "on-delete-daemonset"} {
		t.Run(state, func(t *testing.T) {
			deployment := readyDeployment()
			ds := readyDaemonSet()
			switch state {
			case "zero-deployment":
				deployment.Spec.Replicas = new(int32(0))
				deployment.Status = appsv1.DeploymentStatus{ObservedGeneration: 4}
			case "default-replicas":
				deployment.Spec.Replicas = nil
				deployment.Status = appsv1.DeploymentStatus{ObservedGeneration: 4, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}
			case "progress-deadline", "old-progress-deadline", "paused-progress-deadline":
				deployment.Status.AvailableReplicas = 3
				deployment.Status.Conditions = []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded"}}
				if state == "old-progress-deadline" {
					deployment.Status.ObservedGeneration--
				}
				deployment.Spec.Paused = state == "paused-progress-deadline"
			case "zero-daemonset":
				ds.Status = appsv1.DaemonSetStatus{ObservedGeneration: 4}
			case "on-delete-daemonset":
				ds.Spec.UpdateStrategy.Type = appsv1.OnDeleteDaemonSetStrategyType
				ds.Status.UpdatedNumberScheduled = 0
			}
			c := fake.NewSimpleClientset(deployment, ds)
			ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
			defer cancel()
			var err error
			if state == "zero-daemonset" || state == "on-delete-daemonset" {
				err = WaitReadinessDaemonsetWithNS(ctx, c, "test", "namespace")
			} else {
				err = WaitReadinessDeploymentWithNS(ctx, c, "test", "namespace")
			}
			switch state {
			case "progress-deadline":
				require.ErrorContains(t, err, "exceeded its progress deadline")
				assert.NotErrorIs(t, err, context.DeadlineExceeded)
			case "old-progress-deadline", "paused-progress-deadline":
				require.ErrorIs(t, err, context.DeadlineExceeded)
			default:
				require.NoError(t, err)
			}
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
				assert.Contains(t, []string{"deployments", "daemonsets"}, action.GetResource().Resource)
			}
		})
	}
}

func TestReadinessHTTP(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, kind := range []string{"deployments", "daemonsets"} {
		for _, state := range []string{"stale", "partial", "availability", "unavailable", "missing", "forbidden", "stalled"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				var reads atomic.Int32
				finished := make(chan struct{})
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, http.MethodGet, r.Method)
					assert.Equal(t, "/apis/apps/v1/namespaces/namespace/"+kind+"/test", r.URL.Path)
					n := reads.Add(1)
					w.Header().Set("Content-Type", "application/json")
					if state == "stalled" {
						<-r.Context().Done()
						close(finished)
						return
					}
					if state == "forbidden" || (n == 1 && (state == "unavailable" || state == "missing")) {
						code, reason := http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable
						if state == "forbidden" {
							code, reason = http.StatusForbidden, metav1.StatusReasonForbidden
						} else if state == "missing" {
							code, reason = http.StatusNotFound, metav1.StatusReasonNotFound
						}
						w.WriteHeader(code)
						assert.NoError(t, json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: reason, Code: int32(code), Message: "injected read error"}))
						return
					}
					if kind == "deployments" {
						d := readyDeployment()
						if n == 1 {
							switch state {
							case "stale":
								d.Status.ObservedGeneration--
							case "partial":
								d.Status.UpdatedReplicas = 3
							case "availability":
								d.Status.AvailableReplicas = 3
							}
						}
						assert.NoError(t, json.NewEncoder(w).Encode(d))
					} else {
						d := readyDaemonSet()
						if n == 1 {
							switch state {
							case "stale":
								d.Status.ObservedGeneration--
							case "partial":
								d.Status.UpdatedNumberScheduled = 1
							case "availability":
								d.Status.NumberAvailable = 1
							}
						}
						assert.NoError(t, json.NewEncoder(w).Encode(d))
					}
				}))
				defer server.Close()
				c, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
				require.NoError(t, err)
				timeout := 7 * time.Second
				if state == "stalled" {
					timeout = 80 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(t.Context(), timeout)
				defer cancel()
				if kind == "deployments" {
					err = WaitReadinessDeploymentWithNS(ctx, c, "test", "namespace")
				} else {
					err = WaitReadinessDaemonsetWithNS(ctx, c, "test", "namespace")
				}
				switch state {
				case "forbidden":
					require.Error(t, err)
					assert.Contains(t, err.Error(), "injected read error")
					assert.Equal(t, int32(1), reads.Load())
				case "stalled":
					require.ErrorIs(t, err, context.DeadlineExceeded)
					select {
					case <-finished:
					case <-time.After(time.Second):
						t.Fatal("The API request did not observe cancellation")
					}
				default:
					require.NoError(t, err)
					assert.GreaterOrEqual(t, reads.Load(), int32(2), fmt.Sprintf("%s/%s completed before recovery", kind, state))
				}
			})
		}
	}
}
