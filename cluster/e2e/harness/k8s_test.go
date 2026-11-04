package harness

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestWaitWorkloadReadiness(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, kind := range []string{"deployments", "daemonsets"} {
		for _, state := range []string{"stale", "partial", "availability", "zero"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				c := fake.NewSimpleClientset()
				reads := 0
				c.PrependReactor("get", kind, func(k8stesting.Action) (bool, runtime.Object, error) {
					reads++
					if kind == "deployments" {
						d := testDeployment("test", nil, 4, rolledOut(4))
						if state == "zero" {
							d.Spec.Replicas = new(int32(0))
							d.Status = appsv1.DeploymentStatus{ObservedGeneration: 4}
						} else if reads == 1 {
							switch state {
							case "stale":
								d.Status.ObservedGeneration--
							case "partial":
								d.Status.Replicas = 2
							case "availability":
								d.Status.AvailableReplicas = 0
							}
						}
						return true, d, nil
					}
					ds := &appsv1.DaemonSet{
						ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: vutils.K8sNS, Generation: 4},
						Status:     appsv1.DaemonSetStatus{ObservedGeneration: 4, DesiredNumberScheduled: 1, UpdatedNumberScheduled: 1, NumberReady: 1, NumberAvailable: 1},
					}
					if state == "zero" {
						ds.Status = appsv1.DaemonSetStatus{ObservedGeneration: 4}
					} else if reads == 1 {
						switch state {
						case "stale":
							ds.Status.ObservedGeneration--
						case "partial":
							ds.Status.UpdatedNumberScheduled = 0
						case "availability":
							ds.Status.NumberAvailable = 0
						}
					}
					return true, ds, nil
				})
				h := &H{k8sC: c}
				timeout := 7 * time.Second
				if state == "zero" && kind == "daemonsets" {
					timeout = 80 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(t.Context(), timeout)
				defer cancel()
				var err error
				if kind == "deployments" {
					err = h.WaitDeployment(ctx, "test")
				} else {
					err = h.WaitDaemonSet(ctx, "test")
				}
				if state == "zero" && kind == "daemonsets" {
					require.ErrorContains(t, err, "no scheduled pods")
				} else {
					require.NoError(t, err)
					if state != "zero" {
						assert.GreaterOrEqual(t, reads, 2)
					}
				}
				for _, action := range c.Actions() {
					assert.Equal(t, "get", action.GetVerb())
					assert.Equal(t, kind, action.GetResource().Resource)
				}
			})
		}
	}
}
