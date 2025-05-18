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

package memcontroller

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

func setGW(gw *corev1.Gateway) *userv1.Gateway {
	return vutils.GatewayToUser(gw)
}

type Controller struct {
	octeliumC   octeliumc.ClientInterface
	broadcaster BroadcastI
}

type BroadcastI interface {
	BroadcastMessage(msg *userv1.ConnectResponse) error
}

func NewController(
	octeliumC octeliumc.ClientInterface,
	BroadcastI BroadcastI) *Controller {
	return &Controller{
		octeliumC:   octeliumC,
		broadcaster: BroadcastI,
	}
}

func (c *Controller) OnAdd(ctx context.Context, gw *corev1.Gateway) error {

	if time.Now().Add(-1 * time.Minute).After(gw.Metadata.CreatedAt.AsTime()) {
		zap.S().Debugf("Looks like the Gateway: %s is already created. Nothing to be done", gw.Metadata.Uid)
		return nil
	}

	zap.S().Debugf("Sending add gw for %s", gw.Metadata.Name)

	return c.broadcaster.BroadcastMessage(&userv1.ConnectResponse{
		Event: &userv1.ConnectResponse_AddGateway_{
			AddGateway: &userv1.ConnectResponse_AddGateway{
				Gateway: setGW(gw),
			},
		},
	})
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Gateway) error {

	/*
		if new.Status.Wireguard.PublicKey == old.Status.Wireguard.PublicKey {
			zap.S().Debugf("gw %s public key is the same, no need to send update gw event", new.Metadata.Uid)
			return nil
		}

	*/

	if pbutils.IsEqual(setGW(new), setGW(old)) {
		zap.L().Debug("No need to broadcast Gateway update", zap.String("gw", new.Metadata.Name))
		return nil
	}

	zap.S().Debugf("Sending gw update for %s", new.Metadata.Name)

	return c.broadcaster.BroadcastMessage(&userv1.ConnectResponse{
		Event: &userv1.ConnectResponse_UpdateGateway_{
			UpdateGateway: &userv1.ConnectResponse_UpdateGateway{
				Gateway: setGW(new),
			},
		},
	})
}

func (c *Controller) OnDelete(ctx context.Context, gw *corev1.Gateway) error {

	zap.S().Debugf("Broadcasting delete gw for %s", gw.Metadata.Name)

	return c.broadcaster.BroadcastMessage(&userv1.ConnectResponse{
		Event: &userv1.ConnectResponse_DeleteGateway_{
			DeleteGateway: &userv1.ConnectResponse_DeleteGateway{
				Id: gw.Status.Id,
			},
		},
	})
}
