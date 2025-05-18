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
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/utilnet"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/pkg/errors"
	"github.com/vmihailenco/taskq/v3"
	"github.com/vmihailenco/taskq/v3/memqueue"

	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	k8scorev1 "k8s.io/api/core/v1"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewController(
	k8sC kubernetes.Interface,
	octeliumC octeliumc.ClientInterface,
	podInformer coreinformers.PodInformer,
	regionRef *metav1.ObjectReference,
) {

	updateQueue := memqueue.NewQueue(&taskq.QueueOptions{
		Name: "update-queue",
	})

	updateTask := taskq.RegisterTask(&taskq.TaskOptions{
		Name:       "update-pod",
		RetryLimit: 5,
		MinBackoff: 1 * time.Second,
		MaxBackoff: 5 * time.Second,
		Handler: func(pod *k8scorev1.Pod) error {
			err := doHandlePodUpdate(context.Background(), pod, k8sC, octeliumC, regionRef)
			if err != nil {
				zap.L().Error("Could not handle update for pod", zap.String("pod", pod.Name), zap.Error(err))
			}
			return err
		},
	})

	deleteQueue := memqueue.NewQueue(&taskq.QueueOptions{
		Name: "delete-queue",
	})

	deleteTask := taskq.RegisterTask(&taskq.TaskOptions{
		Name:       "delete-pod",
		RetryLimit: 5,
		MinBackoff: 1 * time.Second,
		MaxBackoff: 5 * time.Second,
		Handler: func(pod *k8scorev1.Pod) error {
			err := doHandlePodDelete(context.Background(), pod, k8sC, octeliumC, regionRef)
			if err != nil {
				zap.L().Error("Could not handle delete for pod", zap.String("pod", pod.Name), zap.Error(err))
			}
			return err
		},
	})

	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new any) {

			oldPod, ok := old.(*k8scorev1.Pod)
			if !ok {
				return
			}
			newPod, ok := new.(*k8scorev1.Pod)
			if !ok {
				return
			}

			if oldPod.ResourceVersion == newPod.ResourceVersion {
				return
			}

			_, found := newPod.Labels["octelium.com/svc"]
			if !found {
				return
			}
			_, found = newPod.Annotations["k8s.v1.cni.cncf.io/networks"]
			if !found {
				return
			}

			_, found = newPod.Annotations["k8s.v1.cni.cncf.io/network-status"]
			if !found {
				return
			}

			zap.S().Debugf("updating pod %s", newPod.Name)
			if err := updateQueue.Add(updateTask.WithArgs(context.Background(), newPod)); err != nil {
				zap.S().Errorf("Could not add to queue: %+v", err)
			}
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*k8scorev1.Pod)
			if !ok {
				return
			}

			_, found := pod.Labels["octelium.com/svc"]
			if !found {
				return
			}
			_, found = pod.Annotations["k8s.v1.cni.cncf.io/networks"]
			if !found {
				return
			}

			_, found = pod.Annotations["k8s.v1.cni.cncf.io/network-status"]
			if !found {
				return
			}

			zap.S().Debugf("deleting pod %s", pod.Name)

			if err := deleteQueue.Add(deleteTask.WithArgs(context.Background(), pod)); err != nil {
				zap.S().Errorf("Could not add to queue: %+v", err)
			}
		},
	})
}

func handlePodUpdate(ctx context.Context, pod *k8scorev1.Pod,
	k8sC kubernetes.Interface, octeliumC octeliumc.ClientInterface,
	regionRef *metav1.ObjectReference) {

	go func(ctx context.Context, pod *k8scorev1.Pod, k8sC kubernetes.Interface, octeliumC octeliumc.ClientInterface, regionRef *metav1.ObjectReference) {
		for i := 0; i < 5; i++ {
			err := doHandlePodUpdate(ctx, pod, k8sC, octeliumC, regionRef)
			if err == nil {
				return
			}
			zap.S().Errorf("Could not handle pod update for %s: %+v. Trying again...", pod.Name, err)
			time.Sleep(1 * time.Second)
		}
	}(ctx, pod, k8sC, octeliumC, regionRef)

}

func doHandlePodUpdate(ctx context.Context, pod *k8scorev1.Pod, k8sC kubernetes.Interface,
	octeliumC octeliumc.ClientInterface, regionRef *metav1.ObjectReference) error {
	var netStatuses []networkStatus
	netStatusStr, ok := pod.Annotations["k8s.v1.cni.cncf.io/network-status"]
	if !ok {
		return nil
	}

	if err := json.Unmarshal([]byte(netStatusStr), &netStatuses); err != nil {
		return err
	}

	nsName, ok := pod.Labels["octelium.com/namespace"]
	if !ok {
		return errors.Errorf("Could not find `octelium.com/namespace` label")
	}

	svcName, ok := pod.Labels["octelium.com/svc"]
	if !ok {
		return errors.Errorf("Could not find `octelium.com/svc` label")
	}

	zap.S().Debugf("getting pod IP for %s/%s", nsName, svcName)

	wgIP, err := getPodIP(&netStatuses, svcName, nsName)
	if err != nil {
		return err
	}

	svc, err := octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: svcName})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			zap.S().Debugf("The Service of pod %s no longer exists. Nothing to be done.", pod.Name)
			return nil
		}

		return err
	}

	foundPod := false
	for i, addr := range svc.Status.Addresses {
		if addr.PodRef.Uid == string(pod.UID) {
			foundPod = true
			svc.Status.Addresses[i].DualStackIP = wgIP
			break
		}
	}

	if !foundPod {
		svc.Status.Addresses = append(svc.Status.Addresses, &corev1.Service_Status_Address{
			DualStackIP: wgIP,
			PodRef: &metav1.ObjectReference{
				ApiVersion: "k8s/core/v1",
				Kind:       "Pod",
				Name:       pod.Name,
				Uid:        string(pod.UID),
			},
		})
	}

	svc, err = octeliumC.CoreC().UpdateService(ctx, svc)
	if err != nil {
		if grpcerr.IsNotFound(err) {
			zap.S().Debugf("The Service of pod %s no longer exists. Nothing to be done.", pod.Name)
			return nil
		}

		return err
	}

	zap.S().Debugf("svc %s/%s has updated its wg IP to %+v", nsName, svcName, wgIP)

	go func() {

		time.Sleep(time.Duration(utilrand.GetRandomRangeMath(4, 9)) * time.Second)
		if err := cleanupServicePods(ctx, pod, k8sC, octeliumC, svc, regionRef); err != nil {
			zap.S().Errorf("Could not cleanup svc pods for for Service %s: %+v", svc.Metadata.Name, err)
		}
	}()

	return nil
}

func cleanupServicePods(ctx context.Context, pod *k8scorev1.Pod, k8sC kubernetes.Interface, octeliumC octeliumc.ClientInterface, svc *corev1.Service, regionRef *metav1.ObjectReference) error {

	zap.S().Debugf("Starting cleaning up pod addrs for Service %s", svc.Metadata.Name)
	podList, err := k8sC.CoreV1().Pods(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{
		LabelSelector: fmt.Sprintf("octelium.com/svc-uid=%s", svc.Metadata.Uid),
	})
	if err != nil {
		return err
	}

	svc, err = octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	if err != nil {
		return err
	}

	needsDelete := func(addr *corev1.Service_Status_Address) bool {
		if svc.Status.RegionRef != nil && svc.Status.RegionRef.Uid != regionRef.Uid {
			return false
		}
		for _, pod := range podList.Items {
			if string(pod.UID) == addr.PodRef.Uid {
				return false
			}
		}

		return true
	}
	var doUpdate bool
	for i := len(svc.Status.Addresses) - 1; i >= 0; i-- {
		addr := svc.Status.Addresses[i]
		if needsDelete(addr) {
			doUpdate = true
			zap.S().Debugf("Cleaning up addr of pod: %s as it no longer exists", string(pod.UID))
			svc.Status.Addresses = append(svc.Status.Addresses[:i], svc.Status.Addresses[i+1:]...)
		}
	}

	if doUpdate {
		if _, err := octeliumC.CoreC().UpdateService(ctx, svc); err != nil {
			return err
		}
	} else {
		zap.S().Debugf("No pod cleanup needed for Service %s", svc.Metadata.Name)
	}

	return nil
}

/*
func handlePodDelete(ctx context.Context, pod *k8scorev1.Pod, k8sC kubernetes.Interface, octeliumC octeliumc.ClientInterface, regionRef *metav1.ObjectReference) {

	go func(ctx context.Context, pod *k8scorev1.Pod, k8sC kubernetes.Interface, octeliumC octeliumc.ClientInterface, regionRef *metav1.ObjectReference) {
		for i := 0; i < 5; i++ {
			err := doHandlePodDelete(ctx, pod, k8sC, octeliumC, regionRef)
			if err == nil {
				return
			}
			zap.S().Errorf("Could not handle pod delete for %s: %+v. Trying again...", pod.Name, err)
			time.Sleep(1 * time.Second)
		}
	}(ctx, pod, k8sC, octeliumC, regionRef)
}
*/

func doHandlePodDelete(ctx context.Context, pod *k8scorev1.Pod, k8sC kubernetes.Interface,
	octeliumC octeliumc.ClientInterface, regionRef *metav1.ObjectReference) error {
	nsName, ok := pod.Labels["octelium.com/namespace"]
	if !ok {
		return errors.Errorf("Could not found `octelium.com/namespace` label")
	}

	svcName, ok := pod.Labels["octelium.com/svc"]
	if !ok {
		return errors.Errorf("Could not found `octelium.com/svc` label")
	}

	zap.S().Debugf("getting info for deleted pod IP for %s/%s", nsName, svcName)

	svc, err := octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: svcName})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			zap.S().Debugf("The Service of pod %s no longer exists. Nothing to be done.", pod.Name)
			return nil
		}

		return err
	}

	for i := len(svc.Status.Addresses) - 1; i >= 0; i-- {
		addr := svc.Status.Addresses[i]
		if addr.PodRef.Uid == string(pod.UID) {
			zap.S().Debugf("Removing pod: %s from svc addrs", string(pod.UID))
			svc.Status.Addresses = append(svc.Status.Addresses[:i], svc.Status.Addresses[i+1:]...)
		}
	}

	_, err = octeliumC.CoreC().UpdateService(ctx, svc)
	if err != nil {
		if grpcerr.IsNotFound(err) {
			zap.S().Debugf("The Service of pod %s no longer exists. Nothing to be done.", pod.Name)
			return nil
		}

		return err
	}

	zap.S().Debugf("svc %s/%s has been updated after deleting pod %s", nsName, svcName, pod.Name)

	return nil
}

func getPodIP(netStatuses *[]networkStatus, svc, vpn string) (*metav1.DualStackIP, error) {
	ret := &metav1.DualStackIP{}

	for _, itm := range *netStatuses {
		if itm.Name == "octelium/octelium" {
			zap.S().Debugf("Found nad of  svc %s: %+v", svc, itm)
			for _, ipStr := range itm.IPs {
				ip := net.ParseIP(ipStr)
				if utilnet.IsIPv6(ip) {
					ret.Ipv6 = ipStr
				} else {
					ret.Ipv4 = ipStr
				}
			}
			return ret, nil
		}
	}

	return nil, errors.Errorf("Could not find the network status of service %s", svc)
}

type networkStatus struct {
	Name      string   `json:"name"`
	Interface string   `json:"interface,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	Mac       string   `json:"mac,omitempty"`

	Gateway []net.IP `json:"default-route,omitempty"`
}
