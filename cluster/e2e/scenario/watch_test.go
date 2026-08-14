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

package scenario

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func runningPod(ns, name string) *k8scorev1.Pod {
	return &k8scorev1.Pod{
		ObjectMeta: k8smetav1.ObjectMeta{Namespace: ns, Name: name},
		Status: k8scorev1.PodStatus{
			Phase: k8scorev1.PodRunning,
			ContainerStatuses: []k8scorev1.ContainerStatus{
				{Name: "main", Ready: true},
			},
		},
	}
}

func TestPodNotReady(t *testing.T) {
	t.Run("a Running pod with every container ready is quiet", func(t *testing.T) {
		assert.Empty(t, podNotReady(runningPod("octelium", "svc-default-octelium-api-1")))
	})

	t.Run("a completed pod is not pending", func(t *testing.T) {
		pod := runningPod("default", "octelium-genesis")
		pod.Status.Phase = k8scorev1.PodSucceeded
		assert.Empty(t, podNotReady(pod))
	})

	t.Run("a sandbox that Multus could not set up names the plugin", func(t *testing.T) {
		pod := &k8scorev1.Pod{
			ObjectMeta: k8smetav1.ObjectMeta{Namespace: "octelium", Name: "svc-demo-nginx-1"},
			Status: k8scorev1.PodStatus{
				Phase: k8scorev1.PodPending,
				ContainerStatuses: []k8scorev1.ContainerStatus{{
					Name: "vigil",
					State: k8scorev1.ContainerState{
						Waiting: &k8scorev1.ContainerStateWaiting{
							Reason: "ContainerCreating",
							Message: "failed to create pod sandbox: plugin type=multus " +
								"name=multus-cni-network failed",
						},
					},
				}},
			},
		}

		got := podNotReady(pod)
		assert.Contains(t, got, "octelium/svc-demo-nginx-1")
		assert.Contains(t, got, "Pending")
		assert.Contains(t, got, "ContainerCreating")
		assert.Contains(t, got, "multus")
	})

	t.Run("a crash loop reports the exit code and the restarts", func(t *testing.T) {
		pod := &k8scorev1.Pod{
			ObjectMeta: k8smetav1.ObjectMeta{Namespace: "octelium", Name: "octelium-rscserver-1"},
			Status: k8scorev1.PodStatus{
				Phase: k8scorev1.PodRunning,
				ContainerStatuses: []k8scorev1.ContainerStatus{{
					Name:         "rscserver",
					RestartCount: 7,
					State: k8scorev1.ContainerState{
						Terminated: &k8scorev1.ContainerStateTerminated{
							ExitCode: 1, Reason: "Error",
						},
					},
				}},
			},
		}

		got := podNotReady(pod)
		assert.Contains(t, got, "exited 1")
		assert.Contains(t, got, "restarted 7 times")
	})

	t.Run("an unschedulable pod says so", func(t *testing.T) {
		pod := &k8scorev1.Pod{
			ObjectMeta: k8smetav1.ObjectMeta{Namespace: "octelium", Name: "octelium-gwagent-1"},
			Status: k8scorev1.PodStatus{
				Phase: k8scorev1.PodPending,
				Conditions: []k8scorev1.PodCondition{{
					Type:    k8scorev1.PodScheduled,
					Status:  k8scorev1.ConditionFalse,
					Reason:  "Unschedulable",
					Message: "0/1 nodes are available: 1 node(s) had untolerated taint",
				}},
			},
		}

		got := podNotReady(pod)
		assert.Contains(t, got, "unscheduled")
		assert.Contains(t, got, "untolerated taint")
	})
}

func TestRecentWarnings(t *testing.T) {
	now := time.Now()

	mk := func(name, reason, msg string, at time.Time) *k8scorev1.Event {
		return &k8scorev1.Event{
			ObjectMeta:     k8smetav1.ObjectMeta{Namespace: "octelium", Name: name},
			InvolvedObject: k8scorev1.ObjectReference{Name: name},
			Type:           k8scorev1.EventTypeWarning,
			Reason:         reason,
			Message:        msg,
			LastTimestamp:  k8smetav1.NewTime(at),
		}
	}

	k8sC := fake.NewSimpleClientset(
		mk("old", "FailedScheduling", "no nodes", now.Add(-time.Hour)),
		mk("recent", "FailedCreatePodSandBox", "plugin type=multus failed", now),
	)

	got := recentWarnings(context.Background(), k8sC)

	assert.Contains(t, got, "FailedCreatePodSandBox")
	assert.Contains(t, got, "plugin type=multus failed")
	assert.Contains(t, got, "no nodes")
}

func TestRecentWarningsKeepsOnlyTheLatest(t *testing.T) {
	k8sC := fake.NewSimpleClientset()

	for i := 0; i < watchEventCount+10; i++ {
		name := fmt.Sprintf("evt-%02d", i)
		_, err := k8sC.CoreV1().Events("octelium").Create(context.Background(),
			&k8scorev1.Event{
				ObjectMeta:     k8smetav1.ObjectMeta{Namespace: "octelium", Name: name},
				InvolvedObject: k8scorev1.ObjectReference{Name: name},
				Type:           k8scorev1.EventTypeWarning,
				Reason:         "BackOff",
				Message:        "restarting",
				LastTimestamp:  k8smetav1.NewTime(time.Now().Add(time.Duration(i) * time.Minute)),
			}, k8smetav1.CreateOptions{})
		require.NoError(t, err)
	}

	got := recentWarnings(context.Background(), k8sC)

	assert.Len(t, strings.Split(got, "\n"), watchEventCount)
	assert.Contains(t, got, fmt.Sprintf("evt-%02d", watchEventCount+9))
	assert.NotContains(t, got, "evt-00")
}

func TestWatchInterval(t *testing.T) {
	t.Run("the default", func(t *testing.T) {
		t.Setenv(WatchIntervalEnv, "")
		assert.Equal(t, watchIntervalDefault, watchInterval())
	})

	t.Run("an override", func(t *testing.T) {
		t.Setenv(WatchIntervalEnv, "5s")
		assert.Equal(t, 5*time.Second, watchInterval())
	})

	t.Run("a bad value falls back", func(t *testing.T) {
		t.Setenv(WatchIntervalEnv, "not-a-duration")
		assert.Equal(t, watchIntervalDefault, watchInterval())
	})
}

func TestReportClusterDoesNotPanicOnAnEmptyCluster(t *testing.T) {
	reportCluster(context.Background(), fake.NewSimpleClientset(), "install")
}
