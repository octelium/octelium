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

package secretcontroller

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
)

type serverI interface {
	SetClusterCertificate(crt *corev1.Secret) error
}

type Controller struct {
	srv serverI
}

func NewController(
	srv serverI,

) *Controller {
	return &Controller{
		srv: srv,
	}
}

func (c *Controller) OnAdd(ctx context.Context, secret *corev1.Secret) error {

	if c.isReadyClusterCrt(secret) && c.srv != nil {
		return c.srv.SetClusterCertificate(secret)
	}

	return nil
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Secret) error {

	if c.isReadyClusterCrt(new) && c.srv != nil {
		return c.srv.SetClusterCertificate(new)
	}

	return nil
}

func (c *Controller) OnDelete(ctx context.Context, secret *corev1.Secret) error {
	if c.isReadyClusterCrt(secret) && c.srv != nil {
		return c.srv.SetClusterCertificate(nil)
	}

	return nil
}

func (c *Controller) isReadyClusterCrt(crt *corev1.Secret) bool {
	return vutils.IsClusterCertAndReady(crt)
}
