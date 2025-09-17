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

package conncontroller

/*
import (
	"context"
	"fmt"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
)

type Controller struct {
	octeliumC octeliumc.ClientInterface
}

func NewController(octeliumC octeliumc.ClientInterface) *Controller {
	return &Controller{
		octeliumC: octeliumC,
	}
}

func (c *Controller) OnAdd(ctx context.Context, sess *corev1.Session) error {
	return nil
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Session) error {
	if new.Status.Type != corev1.Session_Status_CLIENT {
		return nil
	}

	newConn := new.Status.Connection
	oldConn := old.Status.Connection

	switch {
	case newConn != nil && oldConn == nil:
		return c.onConnect(ctx, new)
	default:
		return nil
	}
}

func (c *Controller) OnDelete(ctx context.Context, sess *corev1.Session) error {
	return nil
}

func (c *Controller) onConnect(ctx context.Context, conn *corev1.Session) error {

	zap.L().Debug("Starting handling new Session Connection", zap.String("sessionName", conn.Metadata.Name))

	usr, err := c.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Uid: conn.Status.UserRef.Uid})
	if err != nil {
		return err
	}

	svcs, err := c.octeliumC.CoreC().ListService(ctx, &rmetav1.ListOptions{
		SpecLabels: map[string]string{
			fmt.Sprintf("host-user-%s", usr.Metadata.Name): usr.Metadata.Uid,
		},
	})
	if err != nil {
		zap.S().Errorf("Could not list services for  for user %s", usr.Metadata.Name)
		return err
	}

	zap.S().Debugf("found %d services for the user %s", len(svcs.Items), usr.Metadata.Name)

	for _, svc := range svcs.Items {
		if _, err := upstream.SetServiceUpstreams(ctx, c.octeliumC, svc); err != nil {
			zap.S().Errorf("Could not set service upstreams: %+v", err)
			return err
		}

		if svc.Metadata.SystemLabels == nil {
			svc.Metadata.SystemLabels = make(map[string]string)
		}
		svc.Metadata.SpecLabels["update-notification"] = utilrand.GetRandomStringLowercase(8)

		_, err := c.octeliumC.CoreC().UpdateService(ctx, svc)
		if err != nil {
			zap.S().Errorf("could not update svc: %s", svc.Metadata.Name)
			return err
		}

	}
	return nil
}
*/
