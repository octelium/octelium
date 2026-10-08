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
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/octelium/octelium/cluster/common/vutils"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ContainerHealth struct {
	Owner      string `json:"owner"`
	Container  string `json:"container"`
	Restarts   int32  `json:"restarts"`
	LastReason string `json:"lastReason,omitempty"`
	ExitCode   int32  `json:"exitCode,omitempty"`
	Pods       int    `json:"pods"`
}

type HealthSnapshot map[string]*ContainerHealth

func PodOwner(pod *k8scorev1.Pod) string {
	if svc := pod.Labels["octelium.com/svc"]; svc != "" {
		return "svc/" + svc
	}
	if c := pod.Labels["octelium.com/component"]; c != "" {
		return "component/" + c
	}

	name := pod.Name
	for range 2 {
		if idx := strings.LastIndex(name, "-"); idx > 0 {
			name = name[:idx]
		}
	}
	return "pod/" + name
}

func HealthOf(pods []k8scorev1.Pod) HealthSnapshot {
	ret := HealthSnapshot{}

	for i := range pods {
		pod := &pods[i]
		owner := PodOwner(pod)

		for _, cs := range pod.Status.ContainerStatuses {
			key := owner + "/" + cs.Name
			cur, ok := ret[key]
			if !ok {
				cur = &ContainerHealth{Owner: owner, Container: cs.Name}
				ret[key] = cur
			}

			cur.Pods++
			cur.Restarts += cs.RestartCount
			if term := cs.LastTerminationState.Terminated; term != nil {
				cur.LastReason = term.Reason
				cur.ExitCode = term.ExitCode
			}
		}
	}

	return ret
}

func (h *H) Health(ctx context.Context) (HealthSnapshot, error) {
	pods, err := h.k8sC.CoreV1().Pods(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	return HealthOf(pods.Items), nil
}

type RestartDelta struct {
	Key        string `json:"key"`
	Restarts   int32  `json:"restarts"`
	LastReason string `json:"lastReason,omitempty"`
	ExitCode   int32  `json:"exitCode,omitempty"`
}

func (d RestartDelta) String() string {
	ret := fmt.Sprintf("%s restarted %d time(s)", d.Key, d.Restarts)
	if d.LastReason != "" {
		ret += fmt.Sprintf(" (last: %s, exit %d)", d.LastReason, d.ExitCode)
	}
	return ret
}

func RestartsSince(before, after HealthSnapshot, ignoreOwners ...string) []RestartDelta {
	var ret []RestartDelta

	for key, cur := range after {
		ignored := false
		for _, owner := range ignoreOwners {
			if cur.Owner == owner {
				ignored = true
			}
		}
		if ignored {
			continue
		}

		var prev int32
		if b, ok := before[key]; ok {
			prev = b.Restarts
		}

		if cur.Restarts > prev {
			ret = append(ret, RestartDelta{
				Key:        key,
				Restarts:   cur.Restarts - prev,
				LastReason: cur.LastReason,
				ExitCode:   cur.ExitCode,
			})
		}
	}

	sort.Slice(ret, func(i, j int) bool { return ret[i].Key < ret[j].Key })
	return ret
}

type ContainerUsage struct {
	Pod        string `json:"pod"`
	Container  string `json:"container"`
	MilliCPU   int64  `json:"milliCPU"`
	MemoryMiB  int64  `json:"memoryMiB"`
	OwnerGuess string `json:"owner"`
}

func ParseTopContainers(out string) []ContainerUsage {
	var ret []ContainerUsage

	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 4 || fields[0] == "POD" {
			continue
		}

		cpu, err := strconv.ParseInt(strings.TrimSuffix(fields[2], "m"), 10, 64)
		if err != nil {
			continue
		}
		mem, err := strconv.ParseInt(strings.TrimSuffix(fields[3], "Mi"), 10, 64)
		if err != nil {
			continue
		}

		ret = append(ret, ContainerUsage{
			Pod:        fields[0],
			Container:  fields[1],
			MilliCPU:   cpu,
			MemoryMiB:  mem,
			OwnerGuess: PodOwner(&k8scorev1.Pod{ObjectMeta: k8smetav1.ObjectMeta{Name: fields[0]}}),
		})
	}

	sort.Slice(ret, func(i, j int) bool { return ret[i].MemoryMiB > ret[j].MemoryMiB })
	return ret
}

func (h *H) TopContainers(ctx context.Context) ([]ContainerUsage, error) {
	out, err := h.Output(ctx, fmt.Sprintf(
		"kubectl top pods -n %s --containers --no-headers", vutils.K8sNS))
	if err != nil {
		return nil, fmt.Errorf("kubectl top failed: %w: %s", err, out)
	}

	return ParseTopContainers(string(out)), nil
}
