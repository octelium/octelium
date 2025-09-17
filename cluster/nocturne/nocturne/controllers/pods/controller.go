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
				zap.L().Warn("Could not handlePodUpdate",
					zap.String("podName", pod.Name), zap.Error(err))
			} else {
				zap.L().Debug("handlePodUpdate successfully done",
					zap.String("podName", pod.Name))
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
				zap.L().Warn("Could not doHandlePodDelete",
					zap.String("podName", pod.Name), zap.Error(err))
			} else {
				zap.L().Debug("doHandlePodDelete successfully done",
					zap.String("podName", pod.Name))
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

			if err := updateQueue.Add(updateTask.WithArgs(context.Background(), newPod)); err != nil {
				zap.L().Warn("Could not add to update queue", zap.Error(err))
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

			if err := deleteQueue.Add(deleteTask.WithArgs(context.Background(), pod)); err != nil {
				zap.L().Warn("Could not add to delete queue", zap.Error(err))
			}
		},
	})
}

func doHandlePodUpdate(ctx context.Context, pod *k8scorev1.Pod, k8sC kubernetes.Interface,
	octeliumC octeliumc.ClientInterface, regionRef *metav1.ObjectReference) error {
	var netStatuses []networkStatus
	netStatusStr, ok := pod.Annotations["k8s.v1.cni.cncf.io/network-status"]
	if !ok {
		return nil
	}

	zap.L().Debug("Stating doHandlePodUpdate", zap.String("podName", pod.Name))

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

	wgIP, err := getPodIP(&netStatuses, svcName, nsName)
	if err != nil {
		return err
	}

	svc, err := octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: svcName})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			zap.L().Debug("The Service of pod no longer exists. Nothing to be done.",
				zap.String("svcName", svcName))
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
			zap.L().Debug("The Service of pod no longer exists. Nothing to be done.",
				zap.String("podName", pod.Name), zap.String("svcName", svc.Metadata.Name))
			return nil
		}

		return err
	}

	// zap.L().Debug("Service IP addr is now updated", zap.String("svc", svc.Metadata.Name))

	go func() {
		time.Sleep(time.Duration(utilrand.GetRandomRangeMath(4, 9)) * time.Second)
		if err := cleanupServicePods(ctx, pod, k8sC, octeliumC, svc, regionRef); err != nil {
			zap.L().Warn("Could not cleanupServicePods", zap.Error(err))
		}
	}()

	return nil
}

func cleanupServicePods(ctx context.Context, pod *k8scorev1.Pod, k8sC kubernetes.Interface, octeliumC octeliumc.ClientInterface, svc *corev1.Service, regionRef *metav1.ObjectReference) error {

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
			zap.L().Debug("Cleaning up addr of Service pod as it no longer exists", zap.String("podName", pod.Name))
			svc.Status.Addresses = append(svc.Status.Addresses[:i], svc.Status.Addresses[i+1:]...)
		}
	}

	if doUpdate {
		if _, err := octeliumC.CoreC().UpdateService(ctx, svc); err != nil {
			return err
		}

		zap.L().Debug("Updated Service after pod IP addr cleanup", zap.Any("svc", svc.Metadata.Name))
	}

	return nil
}

func doHandlePodDelete(ctx context.Context, pod *k8scorev1.Pod, k8sC kubernetes.Interface,
	octeliumC octeliumc.ClientInterface, regionRef *metav1.ObjectReference) error {

	svcName, ok := pod.Labels["octelium.com/svc"]
	if !ok {
		return errors.Errorf("Could not found `octelium.com/svc` label")
	}

	svc, err := octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: svcName})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			zap.L().Debug("The Service of pod no longer exists. Nothing to be done.",
				zap.String("podName", pod.Name))
			return nil
		}

		return err
	}

	doUpdate := false
	for i := len(svc.Status.Addresses) - 1; i >= 0; i-- {
		addr := svc.Status.Addresses[i]
		if addr.PodRef.Uid == string(pod.UID) {
			doUpdate = true
			zap.L().Debug("Removing Service addr",
				zap.Any("addr", addr),
				zap.String("sv", svc.Metadata.Name),
				zap.String("podName", pod.Name))
			svc.Status.Addresses = append(svc.Status.Addresses[:i], svc.Status.Addresses[i+1:]...)
		}
	}

	if doUpdate {
		_, err = octeliumC.CoreC().UpdateService(ctx, svc)
		if err != nil {
			if grpcerr.IsNotFound(err) {
				zap.L().Debug("The Service of pod no longer exists. Nothing to be done.",
					zap.String("podName", pod.Name))
				return nil
			}

			return err
		}

		zap.L().Debug("Service has been updated after deleting pod",
			zap.String("svc", svc.Metadata.Name), zap.String("podName", pod.Name))
	}

	return nil
}

func getPodIP(netStatuses *[]networkStatus, svc, vpn string) (*metav1.DualStackIP, error) {
	ret := &metav1.DualStackIP{}

	for _, itm := range *netStatuses {
		if itm.Name == "octelium/octelium" {
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
