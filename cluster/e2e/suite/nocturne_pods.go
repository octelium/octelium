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

package suite

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/utilnet"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type podNetworkStatus struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips,omitempty"`
}

func podOcteliumIP(pod *k8scorev1.Pod) *metav1.DualStackIP {
	netStatusStr, ok := pod.Annotations["k8s.v1.cni.cncf.io/network-status"]
	if !ok {
		return nil
	}

	var netStatuses []podNetworkStatus
	if err := json.Unmarshal([]byte(netStatusStr), &netStatuses); err != nil {
		return nil
	}

	for _, itm := range netStatuses {
		if itm.Name != "octelium/octelium" {
			continue
		}

		ret := &metav1.DualStackIP{}
		for _, ipStr := range itm.IPs {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if utilnet.IsIPv6(ip) {
				ret.Ipv6 = ipStr
			} else {
				ret.Ipv4 = ipStr
			}
		}

		return ret
	}

	return nil
}

func servicePodList(ctx context.Context, h *harness.H, name string) ([]k8scorev1.Pod, error) {
	podList, err := h.K8sC().CoreV1().Pods(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{
		LabelSelector: fmt.Sprintf("octelium.com/svc=%s,octelium.com/component=svc", name),
	})
	if err != nil {
		return nil, err
	}

	return podList.Items, nil
}

func servicePodAddresses(ctx context.Context, h *harness.H,
	name string) (map[string]*metav1.DualStackIP, error) {
	pods, err := servicePodList(ctx, h, name)
	if err != nil {
		return nil, err
	}

	ret := map[string]*metav1.DualStackIP{}
	for _, pod := range pods {
		if pod.DeletionTimestamp != nil {
			continue
		}
		ip := podOcteliumIP(&pod)
		if ip == nil {
			continue
		}
		ret[string(pod.UID)] = ip
	}

	return ret, nil
}

func matchServiceAddresses(ctx context.Context, h *harness.H, name string) error {
	svc, err := h.CoreC().GetService(ctx, &metav1.GetOptions{Name: name})
	if err != nil {
		return err
	}
	if svc.Status == nil {
		return errors.Errorf("the Service has no status")
	}

	live, err := servicePodAddresses(ctx, h, name)
	if err != nil {
		return err
	}

	seen := map[string]struct{}{}
	for _, address := range svc.Status.Addresses {
		if address.PodRef == nil || address.PodRef.Uid == "" {
			return errors.Errorf("a Service address has no Pod reference")
		}
		if _, ok := seen[address.PodRef.Uid]; ok {
			return errors.Errorf("the Service reports the Pod %s more than once",
				address.PodRef.Name)
		}
		seen[address.PodRef.Uid] = struct{}{}

		want, ok := live[address.PodRef.Uid]
		if !ok {
			return errors.Errorf("the Service reports the address of the Pod %s which no longer exists",
				address.PodRef.Name)
		}
		if address.DualStackIP == nil {
			return errors.Errorf("the Pod %s has no Service IP address", address.PodRef.Name)
		}
		if address.DualStackIP.Ipv4 != want.Ipv4 || address.DualStackIP.Ipv6 != want.Ipv6 {
			return errors.Errorf("the Service reports %q/%q for the Pod %s, want %q/%q",
				address.DualStackIP.Ipv4, address.DualStackIP.Ipv6,
				address.PodRef.Name, want.Ipv4, want.Ipv6)
		}
	}

	if len(seen) != len(live) {
		return errors.Errorf("the Service reports %d addresses, want %d",
			len(seen), len(live))
	}

	return nil
}

func waitServiceAddressesMatchPods(t *testing.T, h *harness.H,
	name string) []*corev1.Service_Status_Address {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("the Service %s to report the addresses of its live Pods", name),
		harness.DeploymentBudget, func(ctx context.Context) error {
			return matchServiceAddresses(ctx, h, name)
		})

	return h.GetService(t, name).Status.Addresses
}

func waitServiceDropsPod(t *testing.T, h *harness.H, name string,
	podRef *metav1.ObjectReference) time.Duration {
	t.Helper()

	return h.Within(t, fmt.Sprintf("the Service to drop the address of the Pod %s", podRef.Name),
		harness.DeploymentBudget, func(ctx context.Context) error {
			svc, err := h.CoreC().GetService(ctx, &metav1.GetOptions{Name: name})
			if err != nil {
				return err
			}
			for _, address := range svc.Status.Addresses {
				if address.PodRef.Uid == podRef.Uid {
					return errors.Errorf("the Service still reports the Pod %s", podRef.Name)
				}
			}
			return nil
		})
}

func waitPodGone(t *testing.T, h *harness.H, name string) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("the Pod %s to be drained", name),
		harness.DeploymentBudget, func(ctx context.Context) error {
			_, err := h.K8sC().CoreV1().Pods(vutils.K8sNS).
				Get(ctx, name, k8smetav1.GetOptions{})
			if err == nil {
				return errors.Errorf("the Pod %s is still present", name)
			}
			if !k8serr.IsNotFound(err) {
				return err
			}
			return nil
		})
}

func scaleServiceDeployment(t *testing.T, h *harness.H, hostname string, replicas int32) {
	t.Helper()

	dep := h.MustK8sDeployment(t, hostname)
	dep.Spec.Replicas = &replicas

	if _, err := h.K8sC().AppsV1().Deployments(vutils.K8sNS).
		Update(t.Context(), dep, k8smetav1.UpdateOptions{}); err != nil {
		t.Fatalf("Could not scale the Deployment %s to %d replicas: %+v",
			hostname, replicas, err)
	}
}

func stopComponent(t *testing.T, h *harness.H, component string) {
	t.Helper()

	pods, err := h.ComponentPods(t.Context(), component)
	require.Nil(t, err, "could not list the %s pods", component)

	for _, pod := range pods {
		if err := h.K8sC().CoreV1().Pods(vutils.K8sNS).
			Delete(t.Context(), pod.Name, k8smetav1.DeleteOptions{}); err != nil {
			t.Fatalf("Could not delete the %s pod %s: %+v", component, pod.Name, err)
		}
	}
}

func waitComponentRunning(t *testing.T, h *harness.H, component string) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("the %s pods to be running again", component),
		harness.DeploymentBudget, func(ctx context.Context) error {
			pods, err := h.ComponentPods(ctx, component)
			if err != nil {
				return err
			}
			for _, pod := range pods {
				if pod.Status.Phase != "Running" {
					return errors.Errorf("the %s pod %s is %s",
						component, pod.Name, pod.Status.Phase)
				}
				for _, cs := range pod.Status.ContainerStatuses {
					if !cs.Ready {
						return errors.Errorf("the container %s of the %s pod %s is not ready",
							cs.Name, component, pod.Name)
					}
				}
			}
			return nil
		})
}

func testNocturnePodReconciliation(t *testing.T, h *harness.H) {
	t.Run("AddressIntegrity", func(t *testing.T) {
		svc := newManagedService(t, h, "nginx", 80)

		h.MustWaitService(t, svc.Metadata.Name)

		svc.Spec.Deployment = &corev1.Service_Spec_Deployment{Replicas: 2}
		svc = h.UpdateService(t, svc)

		waitServiceAddressesMatchPods(t, h, svc.Metadata.Name)
		addresses := waitServiceAddresses(t, h, svc.Metadata.Name, 2)

		pods := map[string]struct{}{}
		ips := map[string]struct{}{}
		for _, address := range addresses {
			require.NotNil(t, address.DualStackIP)

			_, ok := pods[address.PodRef.Uid]
			assert.False(t, ok, "the Service reports the Pod %s more than once",
				address.PodRef.Name)
			pods[address.PodRef.Uid] = struct{}{}

			key := fmt.Sprintf("%s/%s",
				address.DualStackIP.Ipv4, address.DualStackIP.Ipv6)
			_, ok = ips[key]
			assert.False(t, ok, "the Service reports the address %s more than once", key)
			ips[key] = struct{}{}
		}

		h.Consistently(t, "the Service addresses to stay in sync with its Pods",
			decisionSettle, func(ctx context.Context) error {
				return matchServiceAddresses(ctx, h, svc.Metadata.Name)
			})
	})

	t.Run("PodDeletion", func(t *testing.T) {
		svc := newManagedService(t, h, "nginx", 80)

		h.MustWaitService(t, svc.Metadata.Name)

		svc.Spec.Deployment = &corev1.Service_Spec_Deployment{Replicas: 2}
		svc = h.UpdateService(t, svc)

		waitServiceAddressesMatchPods(t, h, svc.Metadata.Name)
		before := waitServiceAddresses(t, h, svc.Metadata.Name, 2)

		victim := before[0].PodRef
		err := h.K8sC().CoreV1().Pods(vutils.K8sNS).
			Delete(t.Context(), victim.Name, k8smetav1.DeleteOptions{})
		require.Nil(t, err, "could not delete the Pod %s", victim.Name)

		dropped := waitServiceDropsPod(t, h, svc.Metadata.Name, victim)

		zap.L().Info("Service address reconciliation after a Pod deletion",
			zap.Duration("dropped", dropped))

		waitServiceAddresses(t, h, svc.Metadata.Name, 2)
		waitServiceAddressesMatchPods(t, h, svc.Metadata.Name)
	})

	t.Run("ReplicaChurn", func(t *testing.T) {
		svc := newManagedService(t, h, "nginx", 80)

		h.MustWaitService(t, svc.Metadata.Name)
		waitServiceAddresses(t, h, svc.Metadata.Name, 1)

		for _, replicas := range []int{3, 1, 2} {
			svc = h.GetService(t, svc.Metadata.Name)
			svc.Spec.Deployment = &corev1.Service_Spec_Deployment{
				Replicas: uint32(replicas),
			}
			svc = h.UpdateService(t, svc)

			waitServiceAddresses(t, h, svc.Metadata.Name, replicas)
			addresses := waitServiceAddressesMatchPods(t, h, svc.Metadata.Name)

			zap.L().Info("Service addresses after a replica change",
				zap.Int("replicas", replicas), zap.Int("addresses", len(addresses)))
		}
	})

	t.Run("DrainedPods", func(t *testing.T) {
		svc := newManagedService(t, h, "nginx", 80)
		hostname := h.SvcHostname(svc)

		h.MustWaitService(t, svc.Metadata.Name)

		waitServiceAddressesMatchPods(t, h, svc.Metadata.Name)
		before := waitServiceAddresses(t, h, svc.Metadata.Name, 1)

		scaleServiceDeployment(t, h, hostname, 0)

		drained := waitServiceDropsPod(t, h, svc.Metadata.Name, before[0].PodRef)

		zap.L().Info("Service address reconciliation after draining every Pod",
			zap.Duration("drained", drained))

		waitServiceAddressesMatchPods(t, h, svc.Metadata.Name)
	})

	t.Run("ControllerRestart", func(t *testing.T) {
		svc := newManagedService(t, h, "nginx", 80)
		hostname := h.SvcHostname(svc)

		h.MustWaitService(t, svc.Metadata.Name)

		waitServiceAddressesMatchPods(t, h, svc.Metadata.Name)
		before := waitServiceAddresses(t, h, svc.Metadata.Name, 1)

		stopComponent(t, h, "nocturne")

		scaleServiceDeployment(t, h, hostname, 0)
		waitPodGone(t, h, before[0].PodRef.Name)

		waitComponentRunning(t, h, "nocturne")

		resynced := waitServiceDropsPod(t, h, svc.Metadata.Name, before[0].PodRef)

		zap.L().Info("Service address resync after a controller restart",
			zap.Duration("resynced", resynced))

		waitServiceAddressesMatchPods(t, h, svc.Metadata.Name)
	})
}
