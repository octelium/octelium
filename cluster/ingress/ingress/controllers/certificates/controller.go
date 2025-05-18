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

package certcontroller

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	envoyserver "github.com/octelium/octelium/cluster/ingress/ingress/envoy"
	"go.uber.org/zap"
)

type Controller struct {
	octeliumC   octeliumc.ClientInterface
	envoyServer *envoyserver.Server
}

func NewController(
	octeliumC octeliumc.ClientInterface,
	envoyServer *envoyserver.Server,
) *Controller {
	return &Controller{
		octeliumC:   octeliumC,
		envoyServer: envoyServer,
	}
}

func (c *Controller) OnAdd(ctx context.Context, crt *corev1.Secret) error {

	if !c.shouldDoSnapshot(crt) {
		return nil
	}

	zap.L().Debug("Cluster certificate added. Doing snapshot...")

	return c.envoyServer.DoSnapshot(ctx)
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Secret) error {

	if !c.shouldDoSnapshot(new) {
		return nil
	}

	zap.L().Debug("Cluster certificate updated. Doing snapshot...")
	return c.envoyServer.DoSnapshot(ctx)
}

func (c *Controller) OnDelete(ctx context.Context, crt *corev1.Secret) error {
	if !c.shouldDoSnapshot(crt) {
		return nil
	}

	zap.L().Debug("Cluster certificate deleted. Doing snapshot...")
	return c.envoyServer.DoSnapshot(ctx)
}

func (c *Controller) shouldDoSnapshot(crt *corev1.Secret) bool {
	return crt.Metadata.SystemLabels != nil && crt.Metadata.SystemLabels["octelium-cert"] == "true"
}
