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

package podcontroller

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"

	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
)

func TestController(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	netw, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, tests.GenService(netw.Metadata.Name))
	assert.Nil(t, err)

	regionRef := svc.Status.RegionRef

	kubeInformerFactory := informers.NewSharedInformerFactory(fakeC.K8sC, 0)
	podInformer := kubeInformerFactory.Core().V1().Pods()

	ctrl := NewController(podInformer, fakeC.OcteliumC, regionRef)

	kubeInformerFactory.Start(ctx.Done())

	kubeInformerFactory.WaitForCacheSync(ctx.Done())

	go ctrl.Run(ctx, 1)

	genPod := func(name string, addrs []string) *k8scorev1.Pod {
		netStatuses := []networkStatus{
			{
				Name: "octelium/octelium",
				IPs:  addrs,
			},
		}

		netStatusesBytes, _ := json.Marshal(netStatuses)

		return &k8scorev1.Pod{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      name,
				Namespace: vutils.K8sNS,
				UID:       types.UID(vutils.UUIDv4()),
				Labels: map[string]string{
					"octelium.com/namespace": netw.Metadata.Name,
					"octelium.com/svc":       svc.Metadata.Name,
				},
				Annotations: map[string]string{
					"k8s.v1.cni.cncf.io/network-status": string(netStatusesBytes),
				},
			},
			Spec: k8scorev1.PodSpec{},
		}
	}

	pod1 := genPod(utilrand.GetRandomStringLowercase(8), []string{"1.2.3.4"})
	pod2 := genPod(utilrand.GetRandomStringLowercase(8), []string{"2.3.4.5"})

	pod1, err = fakeC.K8sC.CoreV1().Pods(vutils.K8sNS).Create(ctx, pod1, k8smetav1.CreateOptions{})
	assert.Nil(t, err)

	assert.Eventually(t, func() bool {
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: svc.Metadata.Name})
		if err != nil || svcV.Status == nil {
			return false
		}
		if len(svcV.Status.Addresses) != 1 {
			return false
		}
		return svcV.Status.Addresses[0].PodRef.Uid == string(pod1.UID) &&
			svcV.Status.Addresses[0].DualStackIP.Ipv4 == "1.2.3.4"
	}, 10*time.Second, 100*time.Millisecond)

	pod2, err = fakeC.K8sC.CoreV1().Pods(vutils.K8sNS).Create(ctx, pod2, k8smetav1.CreateOptions{})
	assert.Nil(t, err)

	assert.Eventually(t, func() bool {
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: svc.Metadata.Name})
		if err != nil || svcV.Status == nil {
			return false
		}
		return len(svcV.Status.Addresses) == 2
	}, 10*time.Second, 100*time.Millisecond)

	err = fakeC.K8sC.CoreV1().Pods(vutils.K8sNS).Delete(ctx, pod1.Name, k8smetav1.DeleteOptions{})
	assert.Nil(t, err)

	assert.Eventually(t, func() bool {
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: svc.Metadata.Name})
		if err != nil || svcV.Status == nil {
			return false
		}
		if len(svcV.Status.Addresses) != 1 {
			return false
		}
		return svcV.Status.Addresses[0].PodRef.Uid == string(pod2.UID) &&
			svcV.Status.Addresses[0].DualStackIP.Ipv4 == "2.3.4.5"
	}, 10*time.Second, 100*time.Millisecond)
}

func TestResyncOrphanedAddresses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	netw, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, tests.GenService(netw.Metadata.Name))
	assert.Nil(t, err)

	regionRef := svc.Status.RegionRef

	svc.Status.Addresses = []*corev1.Service_Status_Address{
		{
			DualStackIP: &metav1.DualStackIP{
				Ipv4: "1.2.3.4",
			},
			PodRef: &metav1.ObjectReference{
				ApiVersion: "k8s/core/v1",
				Kind:       "Pod",
				Name:       utilrand.GetRandomStringLowercase(8),
				Uid:        vutils.UUIDv4(),
			},
		},
	}

	svc, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svc)
	assert.Nil(t, err, "%+v", err)

	kubeInformerFactory := informers.NewSharedInformerFactory(fakeC.K8sC, 0)
	podInformer := kubeInformerFactory.Core().V1().Pods()

	ctrl := NewController(podInformer, fakeC.OcteliumC, regionRef)

	kubeInformerFactory.Start(ctx.Done())

	kubeInformerFactory.WaitForCacheSync(ctx.Done())

	go ctrl.Run(ctx, 1)

	assert.Eventually(t, func() bool {
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: svc.Metadata.Name})
		if err != nil || svcV.Status == nil {
			return false
		}
		return len(svcV.Status.Addresses) == 0
	}, 10*time.Second, 100*time.Millisecond)
}

func TestGetPodIP(t *testing.T) {

	{
		ip, err := getPodIP([]networkStatus{
			{
				Name: "octelium/octelium",
				IPs:  []string{"1.2.3.4"},
			},
		}, "svc")
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "1.2.3.4", ip.Ipv4)
		assert.Equal(t, "", ip.Ipv6)
	}

	{
		ip, err := getPodIP([]networkStatus{
			{
				Name: "octelium/octelium",
				IPs:  []string{"1.2.3.4", "fd00::1"},
			},
		}, "svc")
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "1.2.3.4", ip.Ipv4)
		assert.Equal(t, "fd00::1", ip.Ipv6)
	}

	{
		ip, err := getPodIP([]networkStatus{
			{
				Name: "some/other",
				IPs:  []string{"1.2.3.4"},
			},
		}, "svc")
		assert.NotNil(t, err)
		assert.Nil(t, ip)
	}

	{
		ip, err := getPodIP([]networkStatus{
			{
				Name: "octelium/octelium",
				IPs:  []string{"not-an-ip"},
			},
		}, "svc")
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "", ip.Ipv4)
		assert.Equal(t, "", ip.Ipv6)
	}
}

func TestAddressesEqualMap(t *testing.T) {

	addr := func(uid, ipv4, ipv6 string) *corev1.Service_Status_Address {
		return &corev1.Service_Status_Address{
			DualStackIP: &metav1.DualStackIP{
				Ipv4: ipv4,
				Ipv6: ipv6,
			},
			PodRef: &metav1.ObjectReference{
				Uid: uid,
			},
		}
	}

	{
		current := []*corev1.Service_Status_Address{addr("a", "1.1.1.1", "")}
		desired := map[string]*corev1.Service_Status_Address{
			"a": addr("a", "1.1.1.1", ""),
		}
		assert.True(t, addressesEqualMap(current, desired))
	}

	{
		current := []*corev1.Service_Status_Address{
			addr("a", "1.1.1.1", ""),
			addr("b", "2.2.2.2", ""),
		}
		desired := map[string]*corev1.Service_Status_Address{
			"a": addr("a", "1.1.1.1", ""),
		}
		assert.False(t, addressesEqualMap(current, desired))
	}

	{
		current := []*corev1.Service_Status_Address{addr("a", "1.1.1.1", "")}
		desired := map[string]*corev1.Service_Status_Address{
			"a": addr("a", "9.9.9.9", ""),
		}
		assert.False(t, addressesEqualMap(current, desired))
	}

	{
		current := []*corev1.Service_Status_Address{addr("a", "1.1.1.1", "")}
		desired := map[string]*corev1.Service_Status_Address{
			"b": addr("b", "1.1.1.1", ""),
		}
		assert.False(t, addressesEqualMap(current, desired))
	}

	{
		current := []*corev1.Service_Status_Address{
			{
				DualStackIP: &metav1.DualStackIP{Ipv4: "1.1.1.1"},
			},
		}
		desired := map[string]*corev1.Service_Status_Address{
			"a": addr("a", "1.1.1.1", ""),
		}
		assert.False(t, addressesEqualMap(current, desired))
	}

	{
		current := []*corev1.Service_Status_Address{
			{
				PodRef: &metav1.ObjectReference{Uid: "a"},
			},
		}
		desired := map[string]*corev1.Service_Status_Address{
			"a": {
				PodRef: &metav1.ObjectReference{Uid: "a"},
			},
		}
		assert.True(t, addressesEqualMap(current, desired))
	}

	{
		current := []*corev1.Service_Status_Address{
			addr("a", "1.1.1.1", ""),
			addr("a", "1.1.1.1", ""),
		}
		desired := map[string]*corev1.Service_Status_Address{
			"a": addr("a", "1.1.1.1", ""),
			"b": addr("b", "2.2.2.2", ""),
		}
		assert.False(t, addressesEqualMap(current, desired))
	}

	{
		assert.True(t, addressesEqualMap(nil, map[string]*corev1.Service_Status_Address{}))
		assert.True(t, addressesEqualMap([]*corev1.Service_Status_Address{}, nil))
		assert.False(t, addressesEqualMap([]*corev1.Service_Status_Address{
			addr("a", "1.1.1.1", ""),
		}, nil))
	}

}

func TestIsPodAddressable(t *testing.T) {

	newPod := func(phase k8scorev1.PodPhase) *k8scorev1.Pod {
		return &k8scorev1.Pod{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      "svc-essh1-default-65c5bbc7d-tqlxw",
				Namespace: vutils.K8sNS,
			},
			Status: k8scorev1.PodStatus{
				Phase: phase,
			},
		}
	}

	withCondition := func(pod *k8scorev1.Pod,
		typ k8scorev1.PodConditionType, status k8scorev1.ConditionStatus) *k8scorev1.Pod {
		pod.Status.Conditions = append(pod.Status.Conditions, k8scorev1.PodCondition{
			Type:   typ,
			Status: status,
		})
		return pod
	}

	{
		assert.True(t, isPodAddressable(newPod(k8scorev1.PodRunning)))
		assert.True(t, isPodAddressable(newPod(k8scorev1.PodPending)))
	}

	{
		assert.False(t, isPodAddressable(newPod(k8scorev1.PodFailed)))
		assert.False(t, isPodAddressable(newPod(k8scorev1.PodSucceeded)))
	}

	{
		pod := newPod(k8scorev1.PodRunning)
		now := k8smetav1.Now()
		pod.DeletionTimestamp = &now
		assert.False(t, isPodAddressable(pod))
	}

	{
		assert.True(t, isPodAddressable(withCondition(newPod(k8scorev1.PodRunning),
			k8scorev1.PodReadyToStartContainers, k8scorev1.ConditionTrue)))

		assert.False(t, isPodAddressable(withCondition(newPod(k8scorev1.PodRunning),
			k8scorev1.PodReadyToStartContainers, k8scorev1.ConditionFalse)))
	}

	{
		pod := withCondition(newPod(k8scorev1.PodRunning),
			k8scorev1.PodReady, k8scorev1.ConditionFalse)
		assert.True(t, isPodAddressable(pod))
	}

	{
		pod := newPod(k8scorev1.PodFailed)
		pod.Status.Reason = "Evicted"
		pod.Status.Message = "The node was low on resource: ephemeral-storage."
		pod.Annotations = map[string]string{
			"k8s.v1.cni.cncf.io/network-status": `[{"name":"octelium/octelium","interface":"net1","ips":["100.64.0.59","fdee:e61::12a"]}]`,
		}

		withCondition(pod, k8scorev1.DisruptionTarget, k8scorev1.ConditionTrue)
		withCondition(pod, k8scorev1.PodReadyToStartContainers, k8scorev1.ConditionFalse)
		withCondition(pod, k8scorev1.PodInitialized, k8scorev1.ConditionTrue)
		withCondition(pod, k8scorev1.PodReady, k8scorev1.ConditionFalse)
		withCondition(pod, k8scorev1.PodScheduled, k8scorev1.ConditionTrue)

		assert.False(t, isPodAddressable(pod))
	}
}

func TestReconcileEvictedPod(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	netw, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, tests.GenService(netw.Metadata.Name))
	assert.Nil(t, err)

	kubeInformerFactory := informers.NewSharedInformerFactory(fakeC.K8sC, 0)
	podInformer := kubeInformerFactory.Core().V1().Pods()

	ctrl := NewController(podInformer, fakeC.OcteliumC, svc.Status.RegionRef)

	kubeInformerFactory.Start(ctx.Done())
	kubeInformerFactory.WaitForCacheSync(ctx.Done())

	go ctrl.Run(ctx, 1)

	genPod := func(name string, addrs []string) *k8scorev1.Pod {
		netStatusesBytes, _ := json.Marshal([]networkStatus{
			{
				Name: "octelium/octelium",
				IPs:  addrs,
			},
		})

		return &k8scorev1.Pod{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:            name,
				Namespace:       vutils.K8sNS,
				UID:             types.UID(vutils.UUIDv4()),
				ResourceVersion: "1",
				Labels: map[string]string{
					"octelium.com/namespace": netw.Metadata.Name,
					"octelium.com/svc":       svc.Metadata.Name,
				},
				Annotations: map[string]string{
					"k8s.v1.cni.cncf.io/network-status": string(netStatusesBytes),
				},
			},
			Spec: k8scorev1.PodSpec{},
			Status: k8scorev1.PodStatus{
				Phase: k8scorev1.PodRunning,
				Conditions: []k8scorev1.PodCondition{
					{
						Type:   k8scorev1.PodReadyToStartContainers,
						Status: k8scorev1.ConditionTrue,
					},
				},
			},
		}
	}

	getAddresses := func() []*corev1.Service_Status_Address {
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: svc.Metadata.Name})
		if err != nil || svcV.Status == nil {
			return nil
		}
		return svcV.Status.Addresses
	}

	pod1 := genPod(utilrand.GetRandomStringLowercase(8), []string{"100.64.0.59", "fdee:e61::12a"})
	pod2 := genPod(utilrand.GetRandomStringLowercase(8), []string{"100.64.0.29", "fdee:e61::1d"})

	pod1, err = fakeC.K8sC.CoreV1().Pods(vutils.K8sNS).Create(ctx, pod1, k8smetav1.CreateOptions{})
	assert.Nil(t, err)
	pod2, err = fakeC.K8sC.CoreV1().Pods(vutils.K8sNS).Create(ctx, pod2, k8smetav1.CreateOptions{})
	assert.Nil(t, err)

	assert.Eventually(t, func() bool {
		return len(getAddresses()) == 2
	}, 10*time.Second, 100*time.Millisecond)

	pod1.Status.Phase = k8scorev1.PodFailed
	pod1.Status.Reason = "Evicted"
	pod1.Status.Message = "The node was low on resource: ephemeral-storage."
	pod1.Status.Conditions = []k8scorev1.PodCondition{
		{
			Type:   k8scorev1.DisruptionTarget,
			Status: k8scorev1.ConditionTrue,
			Reason: "TerminationByKubelet",
		},
		{
			Type:   k8scorev1.PodReadyToStartContainers,
			Status: k8scorev1.ConditionFalse,
		},
	}
	pod1.ResourceVersion = "2"

	_, err = fakeC.K8sC.CoreV1().Pods(vutils.K8sNS).Update(ctx, pod1, k8smetav1.UpdateOptions{})
	assert.Nil(t, err)

	assert.Eventually(t, func() bool {
		addrs := getAddresses()
		return len(addrs) == 1 && addrs[0].PodRef.Uid == string(pod2.UID) &&
			addrs[0].DualStackIP.Ipv4 == "100.64.0.29"
	}, 10*time.Second, 100*time.Millisecond)

	curPod, err := fakeC.K8sC.CoreV1().Pods(vutils.K8sNS).Get(ctx, pod1.Name, k8smetav1.GetOptions{})
	assert.Nil(t, err)
	assert.Equal(t, k8scorev1.PodFailed, curPod.Status.Phase)
	assert.NotEmpty(t, curPod.Annotations["k8s.v1.cni.cncf.io/network-status"])

	pod2.Status.Phase = k8scorev1.PodFailed
	pod2.ResourceVersion = "2"
	_, err = fakeC.K8sC.CoreV1().Pods(vutils.K8sNS).Update(ctx, pod2, k8smetav1.UpdateOptions{})
	assert.Nil(t, err)

	assert.Eventually(t, func() bool {
		return len(getAddresses()) == 0
	}, 10*time.Second, 100*time.Millisecond)
}
