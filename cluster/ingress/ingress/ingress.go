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

package ingress

import (
	"context"

	"github.com/octelium/octelium/cluster/common/commoninit"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	certcontroller "github.com/octelium/octelium/cluster/ingress/ingress/controllers/certificates"
	svccontroller "github.com/octelium/octelium/cluster/ingress/ingress/controllers/services"
	"github.com/octelium/octelium/cluster/ingress/ingress/envoy"
	"go.uber.org/zap"
)

func Run(ctx context.Context) error {
	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	if err := commoninit.Run(ctx, nil); err != nil {
		return err
	}

	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	envoyServer, err := envoy.NewServer(cc.Status.Domain, octeliumC)
	if err != nil {
		return err
	}
	go envoyServer.Run()

	secretCtl := certcontroller.NewController(octeliumC, envoyServer)
	svcCtl := svccontroller.NewController(octeliumC, envoyServer)

	watcher := watchers.NewCoreV1(octeliumC)
	if err := watcher.Secret(ctx, nil, secretCtl.OnAdd, secretCtl.OnUpdate, secretCtl.OnDelete); err != nil {
		return err
	}

	if err := watcher.Service(ctx, nil, svcCtl.OnAdd, svcCtl.OnUpdate, svcCtl.OnDelete); err != nil {
		return err
	}

	healthcheck.Run(vutils.HealthCheckPortMain)
	zap.L().Info("Ingress controller is now running")

	<-ctx.Done()

	return nil
}
