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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
