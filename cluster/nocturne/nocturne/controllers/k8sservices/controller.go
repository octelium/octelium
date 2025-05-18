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

package k8sservicescontroller

import (
	"context"

	"go.uber.org/zap"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"

	k8scorev1 "k8s.io/api/core/v1"
)

func NewController(
	k8sC kubernetes.Interface,
	octeliumC octeliumc.ClientInterface,
	serviceInformer coreinformers.ServiceInformer) {

	serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new any) {

			ctx := context.Background()

			oldSvc, ok := old.(*k8scorev1.Service)
			if !ok {
				return
			}
			newSvc, ok := new.(*k8scorev1.Service)
			if !ok {
				return
			}

			if oldSvc.ResourceVersion == newSvc.ResourceVersion {
				return
			}

			if err := doHandle(ctx, octeliumC, k8sC, newSvc); err != nil {
				zap.S().Errorf("Could not update DNSctl: %+v", err)
			}
		},

		AddFunc: func(obj any) {

			ctx := context.Background()

			svc, ok := obj.(*k8scorev1.Service)
			if !ok {
				return
			}

			if err := doHandle(ctx, octeliumC, k8sC, svc); err != nil {
				zap.S().Errorf("Could not add DNSctl: %+v", err)
			}

		},
	})
}

func doHandle(ctx context.Context, octeliumC octeliumc.ClientInterface, k8sC kubernetes.Interface, svc *k8scorev1.Service) error {
	if svc.Name != "octelium-ingress-dataplane" {
		return nil
	}
	if svc.Namespace != vutils.K8sNS {
		return nil
	}

	ipAddrs := doGetIPs(svc)

	region, err := octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Name: vutils.GetMyRegionName()})
	if err != nil {
		return err
	}

	if region.Status == nil {
		region.Status = &corev1.Region_Status{}
	}

	region.Status.IngressAddresses = ipAddrs

	_, err = octeliumC.CoreC().UpdateRegion(ctx, region)
	if err != nil {
		return err
	}

	return nil
}

func doGetIPs(svc *k8scorev1.Service) []string {
	var ret []string

	if svc.Spec.ExternalIPs != nil {
		return svc.Spec.ExternalIPs
	}

	for _, ing := range svc.Status.LoadBalancer.Ingress {
		ret = append(ret, ing.IP)
	}

	return ret

}
