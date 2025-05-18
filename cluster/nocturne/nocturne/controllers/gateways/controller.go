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

/*
import (
	"context"
	"time"

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"

	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/apis/main/clusterv1"
	"github.com/octelium/octelium/apis/main/userv1"
	pbm "github.com/octelium/octelium/cluster/apis/event"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/nocturne/nocturne/publish"
)

func setGW(gw *corev1.Gateway) *userv1.Gateway {
	return vutils.GatewayToUser(gw)
}

type Controller struct {
	k8sC      kubernetes.Interface
	octeliumC octeliumc.ClientInterface
	redisC    *redis.Client
}

func NewController(k8sC kubernetes.Interface,
	octeliumC octeliumc.ClientInterface,
	redisC *redis.Client) *Controller {
	return &Controller{
		octeliumC: octeliumC,
		k8sC:      k8sC,
		redisC:    redisC,
	}
}

func (c *Controller) OnAdd(ctx context.Context, gw *corev1.Gateway) error {

	createdAt, err := time.Parse(time.RFC3339, gw.Metadata.CreatedAt)
	if err != nil {
		return err
	}

	if time.Now().Add(-1 * time.Minute).After(createdAt) {
		zap.S().Debugf("Looks like the Gateway: %s is already created. Nothing to be done", gw.Metadata.Uid)
		return nil
	}

	zap.S().Debugf("Sending add gw for %s", gw.Metadata.Name)

	msg := &pbm.StateMessage{
		Type: pbm.StateMessage_BROADCAST,
		State: &userv1.ConnectResponse{
			Event: &userv1.ConnectResponse_AddGateway_{
				AddGateway: &userv1.ConnectResponse_AddGateway{
					Gateway: setGW(gw),
				},
			},
		},
	}

	if err := publish.PublishConnState(c.redisC, msg); err != nil {
		zap.S().Errorf("Could not publish conn message: %+v", err)
	}
	return nil
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Gateway) error {

	if new.Status.Wireguard.PublicKey == old.Status.Wireguard.PublicKey {
		zap.S().Debugf("gw %s public key is the same, no need to send update gw event", new.Metadata.Uid)
		return nil
	}

	zap.S().Debugf("Sending gw update for %s", new.Metadata.Name)

	msg := &pbm.StateMessage{
		Type: pbm.StateMessage_BROADCAST,
		State: &userv1.ConnectResponse{
			Event: &userv1.ConnectResponse_UpdateGateway_{
				UpdateGateway: &userv1.ConnectResponse_UpdateGateway{
					Gateway: setGW(new),
				},
			},
		},
	}

	if err := publish.PublishConnState(c.redisC, msg); err != nil {
		zap.S().Errorf("Could not publish conn message: %+v", err)
	}
	return nil
}

func (c *Controller) OnDelete(ctx context.Context, gw *corev1.Gateway) error {
	msg := &pbm.StateMessage{
		Type: pbm.StateMessage_BROADCAST,
		State: &userv1.ConnectResponse{
			Event: &userv1.ConnectResponse_DeleteGateway_{
				DeleteGateway: &userv1.ConnectResponse_DeleteGateway{
					Id: gw.Status.Id,
				},
			},
		},
	}

	zap.S().Debugf("Broadcasting delete gw for %s", gw.Metadata.Name)

	if err := publish.PublishConnState(c.redisC, msg); err != nil {
		return err
	}
	return nil
}
*/
