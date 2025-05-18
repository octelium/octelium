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

package membercontroller

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/wg"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

type Controller struct {
	wgC       *wg.Wg
	quicv0Ctl quicv0Ctl
	hasQUICV0 bool
}

type quicv0Ctl interface {
	RemoveConnection(sess *corev1.Session) error
}

type Opts struct {
	WgC       *wg.Wg
	HasQuicV0 bool
	Quicv0Ctl quicv0Ctl
}

func NewController(opts *Opts) *Controller {
	return &Controller{
		wgC:       opts.WgC,
		hasQUICV0: opts.HasQuicV0,
		quicv0Ctl: opts.Quicv0Ctl,
	}
}

func (c *Controller) OnAdd(ctx context.Context, n *corev1.Session) error {
	if !ucorev1.ToSession(n).IsClient() {
		return nil
	}
	if n.Status.Connection == nil {
		return nil
	}

	return c.wgC.AddConnection(n)
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Session) error {
	if !ucorev1.ToSession(new).IsClient() {
		return nil
	}

	newConn := new.Status.Connection
	oldConn := old.Status.Connection

	if newConn == nil && oldConn == nil {
		return nil
	} else if newConn != nil && oldConn == nil {
		return c.wgC.AddConnection(new)
	} else if newConn != nil && oldConn != nil && !pbutils.IsEqual(newConn, oldConn) {
		return c.wgC.UpdateConnection(new)
	} else if newConn == nil && oldConn != nil {
		if err := c.wgC.RemoveConnection(old); err != nil {
			return err
		}

		if c.hasQUICV0 && c.quicv0Ctl != nil {
			if err := c.quicv0Ctl.RemoveConnection(old); err != nil {
				return err
			}
		}
	}

	return nil

}

func (c *Controller) OnDelete(ctx context.Context, n *corev1.Session) error {
	if !ucorev1.ToSession(n).IsClient() {
		return nil
	}

	if n.Status.Connection == nil {
		return nil
	}

	if err := c.wgC.RemoveConnection(n); err != nil {
		return err
	}

	if c.hasQUICV0 && c.quicv0Ctl != nil {
		if err := c.quicv0Ctl.RemoveConnection(n); err != nil {
			return err
		}
	}

	return nil
}
