/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package harness

import (
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func testPod(name string, labels map[string]string, restarts map[string]int32, reason string) k8scorev1.Pod {
	ret := k8scorev1.Pod{ObjectMeta: k8smetav1.ObjectMeta{Name: name, Labels: labels}}

	for container, n := range restarts {
		cs := k8scorev1.ContainerStatus{Name: container, RestartCount: n}
		if reason != "" {
			cs.LastTerminationState.Terminated = &k8scorev1.ContainerStateTerminated{
				Reason:   reason,
				ExitCode: 137,
			}
		}
		ret.Status.ContainerStatuses = append(ret.Status.ContainerStatuses, cs)
	}

	return ret
}

func TestPodOwner(t *testing.T) {
	assert.Equal(t, "svc/default.octelium-api", PodOwner(&k8scorev1.Pod{ObjectMeta: k8smetav1.ObjectMeta{
		Name:   "svc-default-octelium-api-7d9c-x1",
		Labels: map[string]string{"octelium.com/svc": "default.octelium-api", "octelium.com/component": "svc"},
	}}))
	assert.Equal(t, "component/gwagent", PodOwner(&k8scorev1.Pod{ObjectMeta: k8smetav1.ObjectMeta{
		Name:   "octelium-gwagent-abcde",
		Labels: map[string]string{"octelium.com/component": "gwagent"},
	}}))
	assert.Equal(t, "pod/octelium-ingress-dataplane", PodOwner(&k8scorev1.Pod{ObjectMeta: k8smetav1.ObjectMeta{
		Name: "octelium-ingress-dataplane-5f7d8-9xk2p",
	}}))
}

func TestRestartsSince(t *testing.T) {
	api := map[string]string{"octelium.com/svc": "default.octelium-api"}
	gw := map[string]string{"octelium.com/component": "gwagent"}

	before := HealthOf([]k8scorev1.Pod{
		testPod("api-1", api, map[string]int32{"vigil": 0, "managed": 1}, ""),
		testPod("gw-1", gw, map[string]int32{"gwagent": 0}, ""),
	})

	after := HealthOf([]k8scorev1.Pod{
		testPod("api-1", api, map[string]int32{"vigil": 2, "managed": 1}, "OOMKilled"),
		testPod("gw-2", gw, map[string]int32{"gwagent": 1}, "Error"),
	})

	got := RestartsSince(before, after)
	require.Len(t, got, 2)

	assert.Equal(t, "component/gwagent/gwagent", got[0].Key)
	assert.Equal(t, "svc/default.octelium-api/vigil", got[1].Key)
	assert.Equal(t, int32(2), got[1].Restarts)
	assert.Equal(t, "OOMKilled", got[1].LastReason)
	assert.Contains(t, got[1].String(), "OOMKilled")

	assert.Len(t, RestartsSince(before, after, "component/gwagent"), 1)
}

func TestGatewayHealth(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*k8scorev1.Pod, *appsv1.DaemonSet)
		ok     bool
	}{
		{name: "healthy", ok: true},
		{name: "recovered restart", ok: true, change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			pod.Status.ContainerStatuses[0].RestartCount = 3
			pod.Status.ContainerStatuses[0].LastTerminationState.Terminated = &k8scorev1.ContainerStateTerminated{
				Reason: "Error", ExitCode: 1,
			}
		}},
		{name: "recent restart", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			pod.Status.ContainerStatuses[0].RestartCount = 1
			pod.Status.ContainerStatuses[0].State.Running.StartedAt = k8smetav1.Now()
		}},
		{name: "crash loop", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			pod.Status.ContainerStatuses[0].State = k8scorev1.ContainerState{
				Waiting: &k8scorev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"},
			}
		}},
		{name: "container not ready", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			pod.Status.ContainerStatuses[0].Ready = false
		}},
		{name: "pod not ready", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			pod.Status.Conditions[0].Status = k8scorev1.ConditionFalse
		}},
		{name: "pod pending", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			pod.Status.Phase = k8scorev1.PodPending
		}},
		{name: "pod terminating", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			now := k8smetav1.Now()
			pod.DeletionTimestamp = &now
		}},
		{name: "container status missing", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			pod.Status.ContainerStatuses = nil
		}},
		{name: "container start time missing", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			pod.Status.ContainerStatuses[0].State.Running.StartedAt = k8smetav1.Time{}
		}},
		{name: "missing pod", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			ds.Status.DesiredNumberScheduled = 2
			ds.Status.UpdatedNumberScheduled = 2
			ds.Status.NumberAvailable = 2
		}},
		{name: "no scheduled pods", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			ds.Status.DesiredNumberScheduled = 0
		}},
		{name: "rollout not observed", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			ds.Status.ObservedGeneration = 1
		}},
		{name: "old pod", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			ds.Status.UpdatedNumberScheduled = 0
		}},
		{name: "pod not available", change: func(pod *k8scorev1.Pod, ds *appsv1.DaemonSet) {
			ds.Status.NumberAvailable = 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &k8scorev1.Pod{
				ObjectMeta: k8smetav1.ObjectMeta{
					Name: "octelium-gwagent-1", Namespace: vutils.K8sNS,
					Labels: map[string]string{"octelium.com/component": "gwagent"},
				},
				Spec: k8scorev1.PodSpec{Containers: []k8scorev1.Container{{Name: "gwagent"}}},
				Status: k8scorev1.PodStatus{
					Phase:      k8scorev1.PodRunning,
					Conditions: []k8scorev1.PodCondition{{Type: k8scorev1.PodReady, Status: k8scorev1.ConditionTrue}},
					ContainerStatuses: []k8scorev1.ContainerStatus{{
						Name: "gwagent", Ready: true,
						State: k8scorev1.ContainerState{Running: &k8scorev1.ContainerStateRunning{
							StartedAt: k8smetav1.NewTime(time.Now().Add(-time.Minute)),
						}},
					}},
				},
			}
			ds := &appsv1.DaemonSet{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-gwagent", Namespace: vutils.K8sNS, Generation: 2},
				Status: appsv1.DaemonSetStatus{
					ObservedGeneration: 2, DesiredNumberScheduled: 1, UpdatedNumberScheduled: 1, NumberAvailable: 1,
				},
			}
			if tc.change != nil {
				tc.change(pod, ds)
			}
			h := &H{k8sC: fake.NewSimpleClientset(pod, ds)}
			err := h.GatewayHealth(t.Context(), 30*time.Second)
			assert.Equal(t, tc.ok, err == nil, "%+v", err)
		})
	}
}

func TestParseTopContainers(t *testing.T) {
	got := ParseTopContainers(`
svc-default-octelium-api-6d5f4b7c8-abcde   vigil       120m   310Mi
svc-default-octelium-api-6d5f4b7c8-abcde   managed     80m    150Mi
octelium-ingress-dataplane-5f7d8-9xk2p     envoy       200m   512Mi
garbage line
`)

	require.Len(t, got, 3)
	assert.Equal(t, "envoy", got[0].Container, "the heaviest container comes first")
	assert.Equal(t, int64(512), got[0].MemoryMiB)
	assert.Equal(t, int64(200), got[0].MilliCPU)
}

func TestHealthIncludesTheStorage(t *testing.T) {
	sc, err := scenario.Get("k3s-flannel")
	require.NoError(t, err)

	inNS := func(ns string, pod k8scorev1.Pod) *k8scorev1.Pod {
		pod.Namespace = ns
		return &pod
	}

	h := &H{
		Scenario: sc,
		k8sC: fake.NewSimpleClientset(
			inNS(vutils.K8sNS, testPod("octelium-rscserver-5f7d8-9xk2p",
				map[string]string{"octelium.com/component": "rscserver"},
				map[string]int32{"rscserver": 0}, "")),
			inNS(scenario.StorageNamespace, testPod("octelium-redis-master-0",
				map[string]string{"app.kubernetes.io/instance": sc.Storage.Redis.ReleaseName},
				map[string]int32{"redis": 3}, "OOMKilled")),
			inNS(scenario.StorageNamespace, testPod("octelium-pg-postgresql-0",
				map[string]string{"app.kubernetes.io/instance": sc.Storage.Postgres.ReleaseName},
				map[string]int32{"postgresql": 0}, "")),
			inNS(scenario.StorageNamespace, testPod("unrelated-7d9c-x1",
				map[string]string{"app.kubernetes.io/instance": "unrelated"},
				map[string]int32{"main": 5}, "Error")),
		),
	}

	got, err := h.Health(t.Context())
	require.NoError(t, err)

	assert.Len(t, got, 3)
	require.Contains(t, got, "component/rscserver/rscserver")
	require.Contains(t, got, "pod/octelium-pg/postgresql")
	require.Contains(t, got, "pod/octelium-redis/redis")
	assert.Equal(t, int32(3), got["pod/octelium-redis/redis"].Restarts)
	assert.Equal(t, "OOMKilled", got["pod/octelium-redis/redis"].LastReason)
}
