package genesis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func readyGatewayDaemonSet() *appsv1.DaemonSet {
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "octelium-gwagent", Namespace: vutils.K8sNS, UID: "gateway-daemonset", Generation: 2},
		Spec: appsv1.DaemonSetSpec{
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{Type: appsv1.RollingUpdateDaemonSetStrategyType},
			Template:       corev1.PodTemplateSpec{Spec: corev1.PodSpec{NodeSelector: map[string]string{vutils.NodeLabelDataPlane: ""}}},
		},
		Status: appsv1.DaemonSetStatus{ObservedGeneration: 2, CurrentNumberScheduled: 2, DesiredNumberScheduled: 2, UpdatedNumberScheduled: 2, NumberReady: 2, NumberAvailable: 2},
	}
}

func registeredGatewayNode(name string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{vutils.NodeLabelDataPlane: "", vutils.NodeLabelGatewayRegistered: "true"}}}
}

func TestGatewayReadinessDoesNotTrustOldRegistration(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, state := range []string{"complete", "empty", "unobserved", "stale", "old-pods", "unavailable", "unregistered", "missing-label", "wrong-label-value"} {
		t.Run(state, func(t *testing.T) {
			ds := readyGatewayDaemonSet()
			node := registeredGatewayNode("node")
			switch state {
			case "empty":
				ds.Status = appsv1.DaemonSetStatus{ObservedGeneration: 2}
			case "unobserved":
				ds.Status = appsv1.DaemonSetStatus{}
			case "stale":
				ds.Status.ObservedGeneration--
			case "old-pods":
				ds.Status.UpdatedNumberScheduled = 1
			case "unavailable":
				ds.Status.NumberAvailable = 1
			case "unregistered":
				node.Labels[vutils.NodeLabelGatewayRegistered] = "false"
			case "missing-label":
				delete(node.Labels, vutils.NodeLabelGatewayRegistered)
			case "wrong-label-value":
				node.Labels[vutils.NodeLabelDataPlane] = "true"
			}
			c := fake.NewSimpleClientset(ds, node)
			ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
			defer cancel()
			err := waitGatewayAgentsRegistered(ctx, c)
			if state == "complete" {
				require.NoError(t, err)
			} else if state == "wrong-label-value" {
				require.ErrorContains(t, err, "No Kubernetes node is labeled")
			} else {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			for _, action := range c.Actions() {
				assert.Contains(t, []string{"get", "list"}, action.GetVerb())
				if action.GetResource().Resource == "nodes" {
					assert.Contains(t, []string{"complete", "unregistered", "missing-label", "wrong-label-value"}, state)
					assert.Equal(t, vutils.NodeLabelDataPlane+"=", action.(k8stesting.ListAction).GetListRestrictions().Labels.String())
				}
			}
		})
	}
}

func TestGatewayReadinessErrorsAndCancellation(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, check := range []func(context.Context, kubernetes.Interface) error{waitGatewayAgentReady, waitGatewayAgentsRegistered} {
		c := fake.NewSimpleClientset()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		require.ErrorIs(t, check(ctx, c), context.Canceled)
		assert.Empty(t, c.Actions())
		want := k8serr.NewForbidden(appsv1.Resource("daemonsets"), "octelium-gwagent", fmt.Errorf("denied"))
		c.PrependReactor("get", "daemonsets", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
		require.ErrorIs(t, check(t.Context(), c), want)
		assert.Len(t, c.Actions(), 1)
	}
	c := fake.NewSimpleClientset(readyGatewayDaemonSet(), registeredGatewayNode("node"))
	want := k8serr.NewForbidden(corev1.Resource("nodes"), "", fmt.Errorf("denied"))
	c.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
	require.ErrorIs(t, waitGatewayAgentsRegistered(t.Context(), c), want)
	ldflags.TestMode = "true"
	c.ClearActions()
	require.NoError(t, waitGatewayAgentReady(t.Context(), c))
	require.NoError(t, waitGatewayAgentsRegistered(t.Context(), c))
	assert.Empty(t, c.Actions())
}

func TestGatewayReadinessHTTP(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, state := range []string{"empty", "stale", "old-pods", "unavailable", "missing", "daemonset-outage", "node-outage", "registration", "stalled"} {
		t.Run(state, func(t *testing.T) {
			var reads, nodeReads atomic.Int32
			finished := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodGet, r.Method)
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/apis/apps/v1/namespaces/octelium/daemonsets/octelium-gwagent":
					n := reads.Add(1)
					if state == "stalled" {
						<-r.Context().Done()
						close(finished)
						return
					}
					if n == 1 && (state == "daemonset-outage" || state == "missing") {
						code, reason := http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable
						if state == "missing" {
							code, reason = http.StatusNotFound, metav1.StatusReasonNotFound
						}
						w.WriteHeader(code)
						assert.NoError(t, json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: reason, Code: int32(code)}))
						return
					}
					ds := readyGatewayDaemonSet()
					if n == 1 {
						switch state {
						case "empty":
							ds.Status = appsv1.DaemonSetStatus{ObservedGeneration: 2}
						case "stale":
							ds.Status.ObservedGeneration--
						case "old-pods":
							ds.Status.UpdatedNumberScheduled = 1
						case "unavailable":
							ds.Status.NumberAvailable = 1
						}
					}
					assert.NoError(t, json.NewEncoder(w).Encode(ds))
				case "/api/v1/nodes":
					n := nodeReads.Add(1)
					assert.Equal(t, vutils.NodeLabelDataPlane+"=", r.URL.Query().Get("labelSelector"))
					if state == "node-outage" && n == 1 {
						w.WriteHeader(http.StatusServiceUnavailable)
						assert.NoError(t, json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonServiceUnavailable, Code: http.StatusServiceUnavailable}))
						return
					}
					node := registeredGatewayNode("node")
					if state == "registration" && n == 1 {
						node.Labels[vutils.NodeLabelGatewayRegistered] = "false"
					}
					assert.NoError(t, json.NewEncoder(w).Encode(&corev1.NodeList{Items: []corev1.Node{*node, *registeredGatewayNode("second-node")}}))
				default:
					t.Errorf("Unexpected Kubernetes request: %s", r.URL.Path)
					w.WriteHeader(http.StatusForbidden)
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
			if state == "empty" {
				err = waitGatewayAgentReady(ctx, c)
			} else {
				err = waitGatewayAgentsRegistered(ctx, c)
			}
			if state == "stalled" {
				require.ErrorIs(t, err, context.DeadlineExceeded)
				select {
				case <-finished:
				case <-time.After(time.Second):
					t.Fatal("The gateway readiness request did not observe cancellation")
				}
			} else {
				require.NoError(t, err)
				assert.GreaterOrEqual(t, reads.Load(), int32(2))
				if state != "empty" {
					assert.GreaterOrEqual(t, nodeReads.Load(), int32(1))
				}
			}
		})
	}
}
