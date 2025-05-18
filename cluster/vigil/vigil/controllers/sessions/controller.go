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

package sesscontroller

/*
import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

type Controller struct {
	srvI srvI
}

type srvI interface {
	GetLBManager() *loadbalancer.LBManager
	GetService() *corev1.Service
}

type lbManager interface {
	SetUpstreamSession(svc *corev1.Service, sess *corev1.Session)
	UnsetUpstreamSession(svc *corev1.Service, sess *corev1.Session)
}

func NewController(
	srvI srvI,
) *Controller {
	return &Controller{
		srvI: srvI,
	}
}

func (c *Controller) OnAdd(ctx context.Context, sess *corev1.Session) error {

	svc := c.srvI.GetService()

	if ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(sess)) {
		c.srvI.GetLBManager().SetUpstreamSession(svc, sess)
	}

	return nil
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Session) error {

	return c.onSessionUpdate(ctx, new, old)
}

func (c *Controller) OnDelete(ctx context.Context, sess *corev1.Session) error {
	svc := c.srvI.GetService()
	c.srvI.GetLBManager().UnsetUpstreamSession(svc, sess)

	return nil
}

func (s *Controller) onSessionUpdate(ctx context.Context, new, old *corev1.Session) error {
	svc := s.srvI.GetService()
	if pbutils.IsEqual(new.Status.Connection, old.Status.Connection) {
		// zap.L().Debug("No need to change lb upstreams", zap.String("sessUID", new.Metadata.Uid))
		return nil
	}

	switch {
	case ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(new)):
		s.srvI.GetLBManager().SetUpstreamSession(svc, new)
	case !ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(new)) &&
		ucorev1.ToService(svc).IsServedBySession(ucorev1.ToSession(old)):
		s.srvI.GetLBManager().UnsetUpstreamSession(svc, new)
	default:
		// zap.L().Debug("No need to use lbManager for sess update", zap.String("sessUID", new.Metadata.Uid))
	}

	return nil
}
*/
