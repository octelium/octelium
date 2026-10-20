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
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
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

type fakeOcteliumC struct {
	octeliumc.ClientInterface
	coreC rcorev1.ResourceServiceClient
}

func (c *fakeOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

type fakeCoreC struct {
	rcorev1.ResourceServiceClient
	getService    func(context.Context, *rmetav1.GetOptions) (*corev1.Service, error)
	updateService func(context.Context, *corev1.Service) (*corev1.Service, error)
	listService   func(context.Context, *rmetav1.ListOptions) (*corev1.ServiceList, error)
}

func (c *fakeCoreC) GetService(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Service, error) {
	return c.getService(ctx, in)
}

func (c *fakeCoreC) UpdateService(ctx context.Context,
	in *corev1.Service, opts ...grpc.CallOption) (*corev1.Service, error) {
	return c.updateService(ctx, in)
}

func (c *fakeCoreC) ListService(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.ServiceList, error) {
	return c.listService(ctx, in)
}

type fakePodLister struct {
	corelisters.PodLister
	err error
}

func (l *fakePodLister) List(selector labels.Selector) ([]*k8scorev1.Pod, error) {
	return nil, l.err
}

type fakePodInformer struct {
	coreinformers.PodInformer
	informer *fakeInformer
}

func (i *fakePodInformer) Informer() cache.SharedIndexInformer {
	return i.informer
}

type fakeInformer struct {
	cache.SharedIndexInformer
	handler cache.ResourceEventHandler
}

func (i *fakeInformer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	i.handler = handler
	return nil, nil
}

func (i *fakeInformer) HasSynced() bool {
	return true
}

func newTstController(t *testing.T, coreC rcorev1.ResourceServiceClient, pods ...*k8scorev1.Pod) *Controller {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, pod := range pods {
		assert.Nil(t, indexer.Add(pod))
	}
	c := &Controller{
		podLister: corelisters.NewPodLister(indexer),
		podSynced: func() bool { return true },
		queue:     workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		octeliumC: &fakeOcteliumC{coreC: coreC},
		regionRef: &metav1.ObjectReference{Uid: "region-uid"},
	}
	t.Cleanup(c.queue.ShutDown)
	return c
}

func newTstPod(uid, svc, annotation string) *k8scorev1.Pod {
	return &k8scorev1.Pod{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:            "pod-" + uid,
			Namespace:       vutils.K8sNS,
			UID:             types.UID(uid),
			ResourceVersion: "1",
			Labels:          map[string]string{"octelium.com/svc": svc},
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/network-status": annotation,
			},
		},
		Status: k8scorev1.PodStatus{Phase: k8scorev1.PodRunning},
	}
}

func TestPodEvents(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(cache.ResourceEventHandler, *k8scorev1.Pod)
		want int
	}{
		{"Add", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) { h.OnAdd(p, false) }, 1},
		{"InvalidAdd", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) { h.OnAdd("pod", false) }, 0},
		{"NoLabel", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) {
			p.Labels = nil
			h.OnAdd(p, false)
		}, 0},
		{"NoAnnotation", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) {
			p.Annotations = nil
			h.OnAdd(p, false)
		}, 0},
		{"Update", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) {
			old := p.DeepCopy()
			p.ResourceVersion = "2"
			h.OnUpdate(old, p)
		}, 1},
		{"Unchanged", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) { h.OnUpdate(p, p) }, 0},
		{"InvalidOld", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) { h.OnUpdate("pod", p) }, 0},
		{"InvalidNew", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) { h.OnUpdate(p, "pod") }, 0},
		{"Delete", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) { h.OnDelete(p) }, 1},
		{"DeleteWithoutAnnotation", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) {
			p.Annotations = nil
			h.OnDelete(p)
		}, 1},
		{"DeleteWithoutLabel", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) {
			p.Labels = nil
			h.OnDelete(p)
		}, 0},
		{"Tombstone", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) {
			h.OnDelete(cache.DeletedFinalStateUnknown{Key: "octelium/pod", Obj: p})
		}, 1},
		{"InvalidTombstone", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) {
			h.OnDelete(cache.DeletedFinalStateUnknown{Obj: "pod"})
		}, 0},
		{"InvalidDelete", func(h cache.ResourceEventHandler, p *k8scorev1.Pod) { h.OnDelete(nil) }, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
			informer := &fakePodInformer{
				informer: &fakeInformer{},
			}
			factory := informers.NewSharedInformerFactory(nil, 0)
			informer.PodInformer = factory.Core().V1().Pods()
			c := NewController(informer, nil, &metav1.ObjectReference{})
			c.podLister = corelisters.NewPodLister(indexer)
			defer c.queue.ShutDown()
			pod := newTstPod("uid", "svc.default", "[]")
			tc.fn(informer.informer.handler, pod)
			assert.Equal(t, tc.want, c.queue.Len())
			if tc.want > 0 {
				key, shutdown := c.queue.Get()
				assert.False(t, shutdown)
				assert.Equal(t, "svc.default", key)
				c.queue.Done(key)
			}
		})
	}
}

func TestReconcilePodAddresses(t *testing.T) {
	ctx := context.Background()
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "svc.default", Uid: "svc-uid", DisplayName: "service"},
		Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP},
		Status: &corev1.Service_Status{
			Port:      8080,
			RegionRef: &metav1.ObjectReference{Uid: "region-uid"},
			Addresses: []*corev1.Service_Status_Address{
				{PodRef: &metav1.ObjectReference{Uid: "removed"}},
			},
		},
	}
	before := proto.Clone(svc).(*corev1.Service)
	var updates int
	coreC := &fakeCoreC{
		getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
			assert.Equal(t, svc.Metadata.Name, in.Name)
			return proto.Clone(svc).(*corev1.Service), nil
		},
		updateService: func(ctx context.Context, in *corev1.Service) (*corev1.Service, error) {
			updates++
			svc = proto.Clone(in).(*corev1.Service)
			return in, nil
		},
	}
	valid := `[{"name":"other/network","ips":["192.0.2.1"]},{"name":"octelium/octelium","ips":["invalid","100.64.0.2","fd00::2"]}]`
	noAnnotation := newTstPod("missing", svc.Metadata.Name, "")
	noAnnotation.Annotations = nil
	failed := newTstPod("failed", svc.Metadata.Name, valid)
	failed.Status.Phase = k8scorev1.PodFailed
	terminating := newTstPod("terminating", svc.Metadata.Name, valid)
	now := k8smetav1.Now()
	terminating.DeletionTimestamp = &now
	notStarted := newTstPod("not-started", svc.Metadata.Name, valid)
	notStarted.Status.Conditions = []k8scorev1.PodCondition{
		{Type: k8scorev1.PodReadyToStartContainers, Status: k8scorev1.ConditionFalse},
	}
	c := newTstController(t, coreC,
		newTstPod("b", svc.Metadata.Name, valid),
		newTstPod("a", svc.Metadata.Name, `[{"name":"octelium/octelium","ips":["fd00::1"]}]`),
		newTstPod("other", "other.default", valid),
		newTstPod("malformed", svc.Metadata.Name, `{`),
		newTstPod("object", svc.Metadata.Name, `{}`),
		newTstPod("null", svc.Metadata.Name, `null`),
		newTstPod("network", svc.Metadata.Name, `[{"name":"other/network","ips":["192.0.2.1"]}]`),
		noAnnotation, failed, terminating, notStarted,
	)
	assert.Nil(t, c.reconcile(ctx, svc.Metadata.Name))
	assert.Equal(t, 1, updates)
	assert.Len(t, svc.Status.Addresses, 2)
	assert.Equal(t, "a", svc.Status.Addresses[0].PodRef.Uid)
	assert.Equal(t, "b", svc.Status.Addresses[1].PodRef.Uid)
	assert.Equal(t, &metav1.DualStackIP{Ipv6: "fd00::1"}, svc.Status.Addresses[0].DualStackIP)
	assert.Equal(t, &metav1.DualStackIP{Ipv4: "100.64.0.2", Ipv6: "fd00::2"}, svc.Status.Addresses[1].DualStackIP)
	assert.Equal(t, "k8s/core/v1", svc.Status.Addresses[0].PodRef.ApiVersion)
	assert.Equal(t, "Pod", svc.Status.Addresses[0].PodRef.Kind)
	assert.Equal(t, "pod-a", svc.Status.Addresses[0].PodRef.Name)
	assert.True(t, proto.Equal(before.Spec, svc.Spec))
	assert.True(t, proto.Equal(before.Metadata, svc.Metadata))
	assert.Equal(t, before.Status.Port, svc.Status.Port)
	assert.True(t, proto.Equal(before.Status.RegionRef, svc.Status.RegionRef))
	assert.Nil(t, c.reconcile(ctx, svc.Metadata.Name))
	assert.Equal(t, 1, updates)
}

func TestReconcileErrors(t *testing.T) {
	ctx := context.Background()
	errTst := errors.New("could not reconcile")
	notFound := status.Error(codes.NotFound, "not found")

	for _, tc := range []struct {
		name      string
		getErr    error
		listErr   error
		updateErr error
		status    *corev1.Service_Status
		wantErr   bool
		updates   int
	}{
		{name: "Deleted", getErr: notFound},
		{name: "GetError", getErr: errTst, wantErr: true},
		{name: "OtherRegion", status: &corev1.Service_Status{RegionRef: &metav1.ObjectReference{Uid: "other"}}},
		{name: "ListerError", listErr: errTst, wantErr: true},
		{name: "UpdateDeleted", updateErr: notFound, updates: 1},
		{name: "UpdateError", updateErr: errTst, wantErr: true, updates: 1},
		{name: "NoStatus", updates: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var updates int
			coreC := &fakeCoreC{
				getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
					return &corev1.Service{
						Metadata: &metav1.Metadata{Name: "svc.default"},
						Status:   tc.status,
					}, tc.getErr
				},
				updateService: func(ctx context.Context, in *corev1.Service) (*corev1.Service, error) {
					updates++
					assert.Len(t, in.Status.Addresses, 1)
					return in, tc.updateErr
				},
			}
			c := newTstController(t, coreC,
				newTstPod("uid", "svc.default", `[{"name":"octelium/octelium","ips":["100.64.0.1"]}]`))
			if tc.listErr != nil {
				c.podLister = &fakePodLister{err: tc.listErr}
			}
			err := c.reconcile(ctx, "svc.default")
			if tc.wantErr {
				assert.ErrorIs(t, err, errTst)
			} else {
				assert.Nil(t, err)
			}
			assert.Equal(t, tc.updates, updates)
		})
	}
}

func TestPodResync(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		listErr bool
		podErr  bool
		noMeta  bool
	}{
		{name: "Paginated"},
		{name: "NoMetadata", noMeta: true},
		{name: "ServiceListError", listErr: true},
		{name: "PodListError", podErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pages []uint32
			coreC := &fakeCoreC{
				listService: func(ctx context.Context, in *rmetav1.ListOptions) (*corev1.ServiceList, error) {
					pages = append(pages, in.Page)
					assert.True(t, in.Paginate)
					assert.Equal(t, uint32(resyncPageSize), in.ItemsPerPage)
					assert.Len(t, in.Filters, 1)
					assert.Equal(t, "status.regionRef.uid", in.Filters[0].Field)
					if tc.listErr {
						return nil, errors.New("could not list Services")
					}
					ret := &corev1.ServiceList{
						Items: []*corev1.Service{{Metadata: &metav1.Metadata{Name: fmt.Sprintf("svc-%d", in.Page)}}},
					}
					if !tc.noMeta {
						ret.ListResponseMeta = &metav1.ListResponseMeta{HasMore: in.Page == 0}
					}
					return ret, nil
				},
			}
			c := newTstController(t, coreC,
				newTstPod("a", "svc-0", "[]"),
				newTstPod("b", "pod-only", "[]"),
				&k8scorev1.Pod{ObjectMeta: k8smetav1.ObjectMeta{Name: "unlabelled"}},
			)
			if tc.podErr {
				c.podLister = &fakePodLister{err: errors.New("could not list pods")}
			}
			c.enqueueAllServices(ctx)
			want := []string{"svc-0", "pod-only"}
			if !tc.noMeta && !tc.listErr {
				want = append(want, "svc-1")
			}
			if tc.podErr {
				want = []string{"svc-0", "svc-1"}
			}
			var got []string
			for c.queue.Len() > 0 {
				key, _ := c.queue.Get()
				got = append(got, key)
				c.queue.Done(key)
			}
			assert.ElementsMatch(t, want, got)
			if tc.noMeta || tc.listErr {
				assert.Equal(t, []uint32{0}, pages)
			} else {
				assert.Equal(t, []uint32{0, 1}, pages)
			}
		})
	}
}

func TestPodWorkerRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var gets atomic.Int32
		var updates atomic.Int32
		coreC := &fakeCoreC{
			getService: func(ctx context.Context, in *rmetav1.GetOptions) (*corev1.Service, error) {
				assert.Nil(t, ctx.Err())
				_, ok := ctx.Deadline()
				assert.True(t, ok)
				if gets.Add(1) == 1 {
					return nil, errors.New("could not get Service")
				}
				return &corev1.Service{
					Metadata: &metav1.Metadata{Name: in.Name},
					Status:   &corev1.Service_Status{},
				}, nil
			},
			updateService: func(ctx context.Context, in *corev1.Service) (*corev1.Service, error) {
				if updates.Add(1) == 1 {
					return nil, errors.New("could not update Service")
				}
				return in, nil
			},
		}
		c := newTstController(t, coreC,
			newTstPod("uid", "svc.default", `[{"name":"octelium/octelium","ips":["100.64.0.1"]}]`))
		done := make(chan struct{})
		go func() {
			c.runWorker(ctx)
			close(done)
		}()
		c.enqueue("svc.default")
		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, int32(3), gets.Load())
		assert.Equal(t, int32(2), updates.Load())
		assert.Zero(t, c.queue.NumRequeues("svc.default"))
		assert.Zero(t, c.queue.Len())
		c.queue.ShutDown()
		<-done
	})
}

func TestPodPeriodicResync(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var calls atomic.Int32
		coreC := &fakeCoreC{
			listService: func(ctx context.Context, in *rmetav1.ListOptions) (*corev1.ServiceList, error) {
				calls.Add(1)
				return &corev1.ServiceList{}, nil
			},
		}
		c := newTstController(t, coreC)
		done := make(chan struct{})
		go func() {
			c.periodicResync(ctx, time.Minute)
			close(done)
		}()
		synctest.Wait()
		assert.Equal(t, int32(1), calls.Load())
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, int32(2), calls.Load())
		cancel()
		<-done
	})
}

func TestPodRunCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := newTstController(t, nil)
	c.podSynced = func() bool { return false }
	c.Run(ctx, 2)
	assert.True(t, c.queue.ShuttingDown())
}

func TestAddressEqualityMissingIP(t *testing.T) {
	current := []*corev1.Service_Status_Address{
		{PodRef: &metav1.ObjectReference{Uid: "uid"}},
	}
	desired := map[string]*corev1.Service_Status_Address{
		"uid": {PodRef: &metav1.ObjectReference{Uid: "uid"}, DualStackIP: &metav1.DualStackIP{Ipv6: "fd00::1"}},
	}
	assert.False(t, addressesEqualMap(current, desired))
	assert.False(t, addressesEqualMap([]*corev1.Service_Status_Address{desired["uid"]}, map[string]*corev1.Service_Status_Address{"uid": current[0]}))
}
