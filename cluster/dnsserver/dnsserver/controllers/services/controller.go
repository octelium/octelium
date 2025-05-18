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

package servicecontroller

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/dnsserver/dnsserver/dnsserver"
	"go.uber.org/zap"
)

type Controller struct {
	dnsServer *dnsserver.DNSServer
}

func NewController(dnsServer *dnsserver.DNSServer) *Controller {
	return &Controller{
		dnsServer: dnsServer,
	}
}

func (c *Controller) OnAdd(ctx context.Context, svc *corev1.Service) error {

	zap.S().Debugf("setting addresses for Service %s", svc.Metadata.Name)
	c.dnsServer.Set(svc)
	return nil
}
func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Service) error {

	zap.S().Debugf("updating addresses for Service %s", new.Metadata.Name)
	c.dnsServer.Set(new)
	return nil
}

func (c *Controller) OnDelete(ctx context.Context, svc *corev1.Service) error {
	zap.S().Debugf("Deleting addresses for svc %s", svc.Metadata.Name)
	c.dnsServer.Unset(svc)
	return nil
}
