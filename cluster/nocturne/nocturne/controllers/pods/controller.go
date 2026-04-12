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
	"sort"
	"time"

	"go.uber.org/zap"

	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"k8s.io/apimachinery/pkg/labels"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/utilnet"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"

	k8scorev1 "k8s.io/api/core/v1"
)

const (
	reconcileTimeout = 10 * time.Second
	resyncInterval   = 3 * 60 * time.Second
)

type Controller struct {
	podLister corelisters.PodLister
	podSynced cache.InformerSynced
	queue     workqueue.TypedRateLimitingInterface[string]

	octeliumC octeliumc.ClientInterface
	regionRef *metav1.ObjectReference
}

func NewController(
	podInformer coreinformers.PodInformer,
	octeliumC octeliumc.ClientInterface,
	regionRef *metav1.ObjectReference,
) *Controller {

	c := &Controller{
		podLister: podInformer.Lister(),
		podSynced: podInformer.Informer().HasSynced,
		queue:     workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		octeliumC: octeliumC,
		regionRef: regionRef,
	}

	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.handlePod,
		UpdateFunc: func(old, new any) {
			oldPod, ok1 := old.(*k8scorev1.Pod)
			newPod, ok2 := new.(*k8scorev1.Pod)
			if !ok1 || !ok2 {
				return
			}
			if oldPod.ResourceVersion == newPod.ResourceVersion {
				return
			}
			c.handlePod(newPod)
		},
		DeleteFunc: c.handleDelete,
	})

	return c
}

func (c *Controller) handlePod(obj any) {
	pod, ok := obj.(*k8scorev1.Pod)
	if !ok {
		return
	}

	svcName, ok := pod.Labels["octelium.com/svc"]
	if !ok {
		return
	}

	if _, ok := pod.Annotations["k8s.v1.cni.cncf.io/network-status"]; !ok {
		return
	}

	c.enqueue(svcName)
}

func (c *Controller) handleDelete(obj any) {
	pod, ok := obj.(*k8scorev1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			zap.L().Warn("Unexpected type. Exiting...",
				zap.String("type", fmt.Sprintf("%T", obj)))
			return
		}
		pod, ok = tombstone.Obj.(*k8scorev1.Pod)
		if !ok {
			return
		}
	}

	svcName, ok := pod.Labels["octelium.com/svc"]
	if !ok {
		return
	}

	c.enqueue(svcName)
}

func (c *Controller) enqueue(svcName string) {
	c.queue.Add(svcName)
}

func (c *Controller) Run(ctx context.Context, workers int) {
	defer c.queue.ShutDown()

	zap.L().Debug("Starting pod controller")

	if !cache.WaitForNamedCacheSync("pod-controller", ctx.Done(), c.podSynced) {
		zap.L().Error("Timed out waiting for pod cache to sync. Exiting...")
		return
	}

	zap.L().Debug("Pod cache synced, starting workers", zap.Int("count", workers))

	for range workers {
		go c.runWorker(ctx)
	}

	go c.periodicResync(ctx, resyncInterval)

	<-ctx.Done()
	zap.L().Debug("Pod controller shutting down")
}

func (c *Controller) runWorker(ctx context.Context) {
	for {
		svcName, shutdown := c.queue.Get()
		if shutdown {
			return
		}

		func() {
			defer c.queue.Done(svcName)

			reconcileCtx, cancel := context.WithTimeout(ctx, reconcileTimeout)
			defer cancel()

			if err := c.reconcile(reconcileCtx, svcName); err != nil {
				zap.L().Warn("Could not reconcile",
					zap.String("svcName", svcName),
					zap.Error(err))
				c.queue.AddRateLimited(svcName)
				return
			}

			c.queue.Forget(svcName)
		}()
	}
}

func (c *Controller) periodicResync(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.enqueueAllServices()
		case <-ctx.Done():
			return
		}
	}
}

func (c *Controller) enqueueAllServices() {
	pods, err := c.podLister.List(labels.Everything())
	if err != nil {
		zap.L().Warn("Could not list pods", zap.Error(err))
		return
	}

	seen := make(map[string]struct{})
	for _, pod := range pods {
		svcName, ok := pod.Labels["octelium.com/svc"]
		if !ok {
			continue
		}
		if _, already := seen[svcName]; already {
			continue
		}
		seen[svcName] = struct{}{}
		c.enqueue(svcName)
	}

	zap.L().Debug("enqueueAllServices done", zap.Int("count", len(seen)))
}

func (c *Controller) reconcile(ctx context.Context, svcName string) error {
	svc, err := c.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Name: svcName})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil
		}
		return errors.Wrap(err, "get service")
	}

	if svc.Status == nil {
		svc.Status = &corev1.Service_Status{}
	}

	if svc.Status.RegionRef != nil && svc.Status.RegionRef.Uid != c.regionRef.Uid {
		return nil
	}

	selector := labels.Set{"octelium.com/svc": svcName}.AsSelector()
	pods, err := c.podLister.List(selector)
	if err != nil {
		return err
	}

	desired := make(map[string]*corev1.Service_Status_Address, len(pods))

	for _, pod := range pods {
		if pod.DeletionTimestamp != nil {
			continue
		}

		netStatusStr, ok := pod.Annotations["k8s.v1.cni.cncf.io/network-status"]
		if !ok {
			continue
		}

		var netStatuses []networkStatus
		if err := json.Unmarshal([]byte(netStatusStr), &netStatuses); err != nil {
			zap.L().Warn("Could not parse network-status annotation. Skipping...",
				zap.String("pod", pod.Name), zap.Error(err))
			continue
		}

		ip, err := getPodIP(netStatuses, svcName)
		if err != nil {
			continue
		}

		desired[string(pod.UID)] = &corev1.Service_Status_Address{
			DualStackIP: ip,
			PodRef: &metav1.ObjectReference{
				ApiVersion: "k8s/core/v1",
				Kind:       "Pod",
				Name:       pod.Name,
				Uid:        string(pod.UID),
			},
		}
	}

	if addressesEqualMap(svc.Status.Addresses, desired) {
		return nil
	}

	newAddresses := make([]*corev1.Service_Status_Address, 0, len(desired))
	for _, addr := range desired {
		newAddresses = append(newAddresses, addr)
	}
	sort.Slice(newAddresses, func(i, j int) bool {
		return newAddresses[i].PodRef.Uid < newAddresses[j].PodRef.Uid
	})

	svc.Status.Addresses = newAddresses

	svc, err = c.octeliumC.CoreC().UpdateService(ctx, svc)
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil
		}
		return err
	}

	zap.L().Debug("Successfully reconciled Service addresses",
		zap.String("svcName", svcName),
		zap.Int("addresses", len(newAddresses)), zap.Any("svc", svc))

	return nil
}

func addressesEqualMap(
	current []*corev1.Service_Status_Address,
	desired map[string]*corev1.Service_Status_Address,
) bool {
	if len(current) != len(desired) {
		return false
	}

	for _, addr := range current {
		if addr.PodRef == nil {
			return false
		}
		d, ok := desired[addr.PodRef.Uid]
		if !ok {
			return false
		}

		currentIP := addr.DualStackIP
		desiredIP := d.DualStackIP
		if currentIP == nil && desiredIP == nil {
			continue
		}
		if currentIP == nil || desiredIP == nil {
			return false
		}
		if currentIP.Ipv4 != desiredIP.Ipv4 || currentIP.Ipv6 != desiredIP.Ipv6 {
			return false
		}
	}

	return true
}

func getPodIP(netStatuses []networkStatus, svc string) (*metav1.DualStackIP, error) {
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
		return ret, nil
	}
	return nil, errors.Errorf("octelium/octelium network status not found for svc %s", svc)
}

type networkStatus struct {
	Name      string   `json:"name"`
	Interface string   `json:"interface,omitempty"`
	IPs       []string `json:"ips,omitempty"`
	Mac       string   `json:"mac,omitempty"`
}
