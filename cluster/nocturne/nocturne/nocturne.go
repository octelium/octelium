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

package nocturne

import (
	"context"

	"go.uber.org/zap"
	kubeinformers "k8s.io/client-go/informers"

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/commoninit"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	cccontroller "github.com/octelium/octelium/cluster/nocturne/nocturne/controllers/cluster_config"
	devcontroller "github.com/octelium/octelium/cluster/nocturne/nocturne/controllers/devices"
	k8ssecretcontroller "github.com/octelium/octelium/cluster/nocturne/nocturne/controllers/k8ssecrets"
	k8sservicecontroller "github.com/octelium/octelium/cluster/nocturne/nocturne/controllers/k8sservices"
	nodecontroller "github.com/octelium/octelium/cluster/nocturne/nocturne/controllers/nodes"
	podcontroller "github.com/octelium/octelium/cluster/nocturne/nocturne/controllers/pods"
	svccontroller "github.com/octelium/octelium/cluster/nocturne/nocturne/controllers/services"
	usrcontroller "github.com/octelium/octelium/cluster/nocturne/nocturne/controllers/users"
	"github.com/octelium/octelium/cluster/nocturne/nocturne/watcher"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
)

func Run(ctx context.Context) error {
	k8sC, err := k8sutils.NewClient(ctx, nil)
	if err != nil {
		return err
	}

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	if err := commoninit.Run(ctx, nil); err != nil {
		return err
	}

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(k8sC, 0)

	region, err := octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Name: vutils.GetMyRegionName()})
	if err != nil {
		return err
	}

	watcher.InitWatcher(octeliumC).Run(ctx)

	podcontroller.NewController(k8sC,
		octeliumC, kubeInformerFactory.Core().V1().Pods(),
		umetav1.GetObjectReference(region))
	k8ssecretcontroller.NewController(k8sC, octeliumC, kubeInformerFactory.Core().V1().Secrets())
	k8sservicecontroller.NewController(k8sC, octeliumC, kubeInformerFactory.Core().V1().Services())
	nodecontroller.NewController(k8sC, octeliumC, kubeInformerFactory.Core().V1().Nodes())

	usrCtl := usrcontroller.NewController(octeliumC)
	svcCtl := svccontroller.NewController(octeliumC, k8sC)
	// sessCtl := sesscontroller.NewController(octeliumC)
	devCtl := devcontroller.NewController(octeliumC)

	{
		watcher := watchers.NewCoreV1(octeliumC)

		if err := watcher.User(ctx, nil, usrCtl.OnAdd, usrCtl.OnUpdate, usrCtl.OnDelete); err != nil {
			return err
		}

		if err := watcher.Device(ctx, nil, devCtl.OnAdd, devCtl.OnUpdate, devCtl.OnDelete); err != nil {
			return err
		}

		if err := watcher.Service(ctx, nil, svcCtl.OnAdd, svcCtl.OnUpdate, svcCtl.OnDelete); err != nil {
			return err
		}

		/*
			if err := watcher.Session(ctx, nil, sessCtl.OnAdd, sessCtl.OnUpdate, sessCtl.OnDelete); err != nil {
				return err
			}
		*/

		if err := watcher.ClusterConfig(ctx, nil, cccontroller.NewController(octeliumC, k8sC).OnUpdate); err != nil {
			return err
		}
	}

	stopCh := make(chan struct{})

	kubeInformerFactory.Start(stopCh)

	healthcheck.Run(vutils.HealthCheckPortMain)
	zap.L().Info("Nocturne is now running...")

	<-ctx.Done()
	close(stopCh)

	return nil
}
