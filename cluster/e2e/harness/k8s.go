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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/pkg/errors"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const DeploymentBudget = 10 * time.Minute

func (h *H) WaitDeployment(ctx context.Context, name string) error {
	return h.EventuallyErr(ctx, fmt.Sprintf("deployment %s", name), DeploymentBudget,
		func(ctx context.Context) error {
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			return k8sutils.WaitReadinessDeploymentWithNS(ctx, h.k8sC, name, vutils.K8sNS)
		})
}

func (h *H) MustWaitDeployment(t *testing.T, name string) {
	t.Helper()
	if err := h.WaitDeployment(t.Context(), name); err != nil {
		t.Fatalf("%+v", err)
	}
}

func svcRef(name string) *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: vutils.GetServiceFullNameFromName(name),
		},
	}
}

func (h *H) WaitService(ctx context.Context, name string) error {
	return h.WaitDeployment(ctx, k8sutils.GetSvcHostname(svcRef(name)))
}

func (h *H) MustWaitService(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := h.WaitService(t.Context(), name); err != nil {
			t.Fatalf("%+v", err)
		}
	}
}

func (h *H) WaitServiceUpstream(ctx context.Context, name string) error {
	return h.WaitDeployment(ctx, k8sutils.GetSvcK8sUpstreamHostname(svcRef(name), ""))
}

func (h *H) MustWaitServiceUpstream(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := h.WaitServiceUpstream(t.Context(), name); err != nil {
			t.Fatalf("%+v", err)
		}
	}
}

func (h *H) WaitDaemonSet(ctx context.Context, name string) error {
	return h.EventuallyErr(ctx, fmt.Sprintf("daemonset %s", name), DeploymentBudget,
		func(ctx context.Context) error {
			ds, err := h.k8sC.AppsV1().DaemonSets(vutils.K8sNS).
				Get(ctx, name, k8smetav1.GetOptions{})
			if err != nil {
				return err
			}
			if ds.Status.DesiredNumberScheduled == 0 {
				return errors.Errorf("daemonset %s has no scheduled pods yet", name)
			}
			if ds.Status.NumberReady != ds.Status.DesiredNumberScheduled {
				return errors.Errorf("daemonset %s: %d/%d pods ready",
					name, ds.Status.NumberReady, ds.Status.DesiredNumberScheduled)
			}
			return nil
		})
}

func (h *H) ComponentPods(ctx context.Context, component string) ([]k8scorev1.Pod, error) {
	podList, err := h.k8sC.CoreV1().Pods(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{
		LabelSelector: fmt.Sprintf("octelium.com/component=%s", component),
	})
	if err != nil {
		return nil, err
	}

	if len(podList.Items) < 1 {
		return nil, errors.Errorf("No pods found for the component %q", component)
	}

	return podList.Items, nil
}

func (h *H) ServicePods(ctx context.Context, service string) ([]k8scorev1.Pod, error) {
	podList, err := h.k8sC.CoreV1().Pods(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{
		LabelSelector: fmt.Sprintf("octelium.com/svc=%s", service),
	})
	if err != nil {
		return nil, err
	}

	if len(podList.Items) < 1 {
		return nil, errors.Errorf("No pods found for the Service %q", service)
	}

	return podList.Items, nil
}

func (h *H) CheckComponentRestarts(t *testing.T, component string) {
	t.Helper()

	pods, err := h.ComponentPods(t.Context(), component)
	if err != nil {
		t.Errorf("%+v", err)
		return
	}

	for _, pod := range pods {
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.RestartCount > 0 {
				reason := ""
				if cs.LastTerminationState.Terminated != nil {
					reason = cs.LastTerminationState.Terminated.Reason
				}
				t.Errorf("Component %s: container %s of pod %s restarted %d time(s) (last reason: %q)",
					component, cs.Name, pod.Name, cs.RestartCount, reason)
			}
		}
	}
}
