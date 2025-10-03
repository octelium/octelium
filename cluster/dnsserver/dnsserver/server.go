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

package dnsserver

import (
	"context"

	"github.com/octelium/octelium/cluster/common/commoninit"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	servicecontroller "github.com/octelium/octelium/cluster/dnsserver/dnsserver/controllers/services"
	server "github.com/octelium/octelium/cluster/dnsserver/dnsserver/dnsserver"
	"go.uber.org/zap"
)

func Run(ctx context.Context) error {

	if err := commoninit.Run(ctx, nil); err != nil {
		return err
	}

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	dnsServer, err := server.Initialize(ctx, octeliumC)
	if err != nil {
		return err
	}

	if err := dnsServer.Run(ctx); err != nil {
		return err
	}

	svcCtl := servicecontroller.NewController(dnsServer)

	if err := watchers.NewCoreV1(octeliumC).Service(ctx, nil, svcCtl.OnAdd, svcCtl.OnUpdate, svcCtl.OnDelete); err != nil {
		return err
	}

	healthcheck.Run(vutils.HealthCheckPortManagedService)
	zap.S().Info("DNS server is running")

	<-ctx.Done()

	return nil
}
