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
