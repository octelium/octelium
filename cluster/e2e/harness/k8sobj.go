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
	appsv1 "k8s.io/api/apps/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const K8sGCBudget = 3 * time.Minute

func (h *H) SvcHostname(svc *corev1.Service) string {
	return k8sutils.GetSvcHostname(svc)
}

func (h *H) K8sDeployment(ctx context.Context, name string) (*appsv1.Deployment, error) {
	return h.k8sC.AppsV1().Deployments(vutils.K8sNS).Get(ctx, name, k8smetav1.GetOptions{})
}

func (h *H) MustK8sDeployment(t *testing.T, name string) *appsv1.Deployment {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.K8sDeployment(ctx, name)
	if err != nil {
		t.Fatalf("Could not get the Deployment %s: %+v", name, err)
	}

	return ret
}

func (h *H) k8sObjectExists(ctx context.Context, name string) (bool, error) {
	if _, err := h.k8sC.CoreV1().ConfigMaps(vutils.K8sNS).
		Get(ctx, name, k8smetav1.GetOptions{}); err == nil {
		return true, nil
	} else if !k8serr.IsNotFound(err) {
		return false, err
	}

	if _, err := h.k8sC.AppsV1().Deployments(vutils.K8sNS).
		Get(ctx, name, k8smetav1.GetOptions{}); err == nil {
		return true, nil
	} else if !k8serr.IsNotFound(err) {
		return false, err
	}

	if _, err := h.k8sC.CoreV1().Services(vutils.K8sNS).
		Get(ctx, name, k8smetav1.GetOptions{}); err == nil {
		return true, nil
	} else if !k8serr.IsNotFound(err) {
		return false, err
	}

	return false, nil
}

func (h *H) WaitK8sObjectsPresent(t *testing.T, name string) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("the Kubernetes resources of %s to be created", name),
		DeploymentBudget, func(ctx context.Context) error {
			for _, fn := range []func() error{
				func() error {
					_, err := h.k8sC.CoreV1().ConfigMaps(vutils.K8sNS).
						Get(ctx, name, k8smetav1.GetOptions{})
					return err
				},
				func() error {
					_, err := h.k8sC.AppsV1().Deployments(vutils.K8sNS).
						Get(ctx, name, k8smetav1.GetOptions{})
					return err
				},
				func() error {
					_, err := h.k8sC.CoreV1().Services(vutils.K8sNS).
						Get(ctx, name, k8smetav1.GetOptions{})
					return err
				},
			} {
				if err := fn(); err != nil {
					return err
				}
			}
			return nil
		})
}

func (h *H) WaitK8sObjectsGone(t *testing.T, name string) time.Duration {
	t.Helper()

	return h.Within(t, fmt.Sprintf("the Kubernetes resources of %s to be collected", name),
		K8sGCBudget, func(ctx context.Context) error {
			exists, err := h.k8sObjectExists(ctx, name)
			if err != nil {
				return err
			}
			if exists {
				return errors.Errorf("the Kubernetes resources of %s still exist", name)
			}
			return nil
		})
}

func (h *H) GetService(t *testing.T, name string) *corev1.Service {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.GetService(ctx, &metav1.GetOptions{Name: name})
	if err != nil {
		t.Fatalf("Could not get the Service %s: %+v", name, err)
	}

	return ret
}

func (h *H) DeleteService(t *testing.T, svc *corev1.Service) {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	if _, err := h.coreC.DeleteService(ctx,
		&metav1.DeleteOptions{Uid: svc.Metadata.Uid}); err != nil {
		t.Fatalf("Could not delete the Service %s: %+v", svc.Metadata.Name, err)
	}
}

func (h *H) GetSession(t *testing.T, name string) *corev1.Session {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.GetSession(ctx, &metav1.GetOptions{Name: name})
	if err != nil {
		t.Fatalf("Could not get the Session %s: %+v", name, err)
	}

	return ret
}

func (h *H) Gateways(t *testing.T) []*corev1.Gateway {
	t.Helper()

	ctx, cancel := h.opCtx(t)
	defer cancel()

	ret, err := h.coreC.ListGateway(ctx, &corev1.ListGatewayOptions{})
	if err != nil {
		t.Fatalf("Could not list the Gateways: %+v", err)
	}

	return ret.Items
}

func (h *H) RestartComponent(t *testing.T, component string) time.Duration {
	t.Helper()

	before, err := h.ComponentPods(t.Context(), component)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	old := map[string]struct{}{}
	for _, pod := range before {
		old[pod.Name] = struct{}{}
	}

	ctx, cancel := h.opCtx(t)
	defer cancel()

	for _, pod := range before {
		if err := h.k8sC.CoreV1().Pods(vutils.K8sNS).
			Delete(ctx, pod.Name, k8smetav1.DeleteOptions{}); err != nil {
			t.Fatalf("Could not delete the pod %s: %+v", pod.Name, err)
		}
	}

	return h.Within(t, fmt.Sprintf("the %s pods to be replaced", component),
		DeploymentBudget, func(ctx context.Context) error {
			pods, err := h.ComponentPods(ctx, component)
			if err != nil {
				return err
			}

			for _, pod := range pods {
				if _, ok := old[pod.Name]; ok {
					return errors.Errorf("the pod %s is still present", pod.Name)
				}
				if pod.Status.Phase != "Running" {
					return errors.Errorf("the pod %s is %s", pod.Name, pod.Status.Phase)
				}
				for _, cs := range pod.Status.ContainerStatuses {
					if !cs.Ready {
						return errors.Errorf("the container %s of the pod %s is not ready",
							cs.Name, pod.Name)
					}
				}
			}

			return nil
		})
}

func (h *H) ComponentRestarts(t *testing.T, component string) int32 {
	t.Helper()

	pods, err := h.ComponentPods(t.Context(), component)
	if err != nil {
		return 0
	}

	var ret int32
	for _, pod := range pods {
		for _, cs := range pod.Status.ContainerStatuses {
			ret += cs.RestartCount
		}
	}

	return ret
}
