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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestController(t *testing.T) {

	ctx := context.Background()

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
	usr := tests.GenUser(nil)

	_, err = adminSrv.CreateUser(ctx, usr)
	assert.Nil(t, err)

	netw, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, tests.GenService(netw.Metadata.Name))
	assert.Nil(t, err)

	genPod := func(addrs []string) *k8scorev1.Pod {
		netStatuses := []networkStatus{
			{
				Name: "octelium/octelium",
				IPs:  addrs,
			},
		}

		netStatusesBytes, err := json.Marshal(netStatuses)
		assert.Nil(t, err)

		return &k8scorev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Name: utilrand.GetRandomStringLowercase(8),
				UID:  types.UID(vutils.UUIDv4()),
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

	pod := genPod([]string{"1.2.3.4"})
	pod2 := genPod([]string{"2.3.4.5"})

	regionRef := &metav1.ObjectReference{
		Name: "default",
		Uid:  vutils.UUIDv4(),
	}

	for i := 0; i < 3; i++ {
		err = doHandlePodUpdate(ctx, pod, fakeC.K8sC, fakeC.OcteliumC, regionRef)
		assert.Nil(t, err, "%+v", err)

		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		assert.Equal(t, 1, len(svcV.Status.Addresses))
		assert.Equal(t, string(pod.UID), svcV.Status.Addresses[0].PodRef.Uid)
		assert.Equal(t, "1.2.3.4", svcV.Status.Addresses[0].DualStackIP.Ipv4)
	}

	for i := 0; i < 3; i++ {

		err = doHandlePodUpdate(ctx, pod2, fakeC.K8sC, fakeC.OcteliumC, regionRef)
		assert.Nil(t, err, "%+v", err)

		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		assert.Equal(t, 2, len(svcV.Status.Addresses))
		assert.Equal(t, string(pod2.UID), svcV.Status.Addresses[1].PodRef.Uid)
		assert.Equal(t, "2.3.4.5", svcV.Status.Addresses[1].DualStackIP.Ipv4)
	}

	{
		err = doHandlePodDelete(ctx, pod, fakeC.K8sC, fakeC.OcteliumC, regionRef)
		assert.Nil(t, err)
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(svcV.Status.Addresses))
		assert.Equal(t, string(pod2.UID), svcV.Status.Addresses[0].PodRef.Uid)

		err = doHandlePodDelete(ctx, pod2, fakeC.K8sC, fakeC.OcteliumC, regionRef)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(svcV.Status.Addresses))
	}
}

func TestCleanupServicePods(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usr := tests.GenUser(nil)

	_, err = adminSrv.CreateUser(ctx, usr)
	assert.Nil(t, err)

	netw, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, tests.GenService(netw.Metadata.Name))
	assert.Nil(t, err)

	genPod := func() *k8scorev1.Pod {

		return &k8scorev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Name: utilrand.GetRandomStringLowercase(8),

				Labels: map[string]string{
					"octelium.com/namespace": netw.Metadata.Name,
					"octelium.com/svc":       svc.Metadata.Name,
					"octelium.com/svc-uid":   svc.Metadata.Uid,
				},
				Annotations: map[string]string{},
			},
			Spec: k8scorev1.PodSpec{},
		}
	}

	region, err := fakeC.OcteliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
		Name: vutils.GetMyRegionName(),
	})
	assert.Nil(t, err)

	regionRef := umetav1.GetObjectReference(region)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	pod, err := fakeC.K8sC.CoreV1().Pods("octelium").Create(ctx, genPod(), k8smetav1.CreateOptions{})
	assert.Nil(t, err)

	svcV.Status.Addresses = []*corev1.Service_Status_Address{
		{
			PodRef: &metav1.ObjectReference{
				Uid: string(pod.UID),
			},
		},
	}

	svcV, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svcV)
	assert.Nil(t, err)

	err = cleanupServicePods(ctx, pod, fakeC.K8sC, fakeC.OcteliumC, svcV, regionRef)
	assert.Nil(t, err)

	svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(svcV.Status.Addresses))
	assert.Equal(t, string(pod.UID), svcV.Status.Addresses[0].PodRef.Uid)

	pod2, err := fakeC.K8sC.CoreV1().Pods("octelium").Create(ctx, genPod(), k8smetav1.CreateOptions{})
	assert.Nil(t, err)

	svcV.Status.Addresses = append(svcV.Status.Addresses, &corev1.Service_Status_Address{
		PodRef: &metav1.ObjectReference{
			Uid: string(pod2.UID),
		},
	})
	svcV, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svcV)
	assert.Nil(t, err)

	err = cleanupServicePods(ctx, pod, fakeC.K8sC, fakeC.OcteliumC, svcV, regionRef)
	assert.Nil(t, err)

	svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(svcV.Status.Addresses))
	assert.Equal(t, string(pod2.UID), svcV.Status.Addresses[1].PodRef.Uid)

	err = fakeC.K8sC.CoreV1().Pods("octelium").Delete(ctx, pod.Name, k8smetav1.DeleteOptions{})
	assert.Nil(t, err)

	err = cleanupServicePods(ctx, pod, fakeC.K8sC, fakeC.OcteliumC, svcV, regionRef)
	assert.Nil(t, err)

	svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(svcV.Status.Addresses))
	assert.Equal(t, string(pod2.UID), svcV.Status.Addresses[0].PodRef.Uid)

	/*
		svcV.Status.Addresses = append(svcV.Status.Addresses, &corev1.Service_Status_Address{
			PodRef: &metav1.ObjectReference{
				Uid: vutils.UUIDv4(),
			},
		})
		svcV, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svcV)
		assert.Nil(t, err)

		err = cleanupServicePods(ctx, pod, fakeC.K8sC, fakeC.OcteliumC, svcV, regionRef)
		assert.Nil(t, err)

		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		assert.Equal(t, 2, len(svcV.Status.Addresses))
		assert.Equal(t, string(pod2.UID), svcV.Status.Addresses[0].PodRef.Uid)
	*/
}
