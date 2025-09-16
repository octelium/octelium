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

package usrcontroller

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
)

type Controller struct {
	octeliumC octeliumc.ClientInterface
}

func NewController(
	octeliumC octeliumc.ClientInterface,
) *Controller {
	return &Controller{
		octeliumC: octeliumC,
	}
}

func (c *Controller) OnAdd(ctx context.Context, crt *corev1.User) error {

	return nil
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.User) error {

	return nil
}

func (c *Controller) OnDelete(ctx context.Context, usr *corev1.User) error {

	{
		authnList, err := c.octeliumC.CoreC().ListAuthenticator(ctx, urscsrv.FilterByUser(usr))
		if err != nil {
			return err
		}

		for _, authn := range authnList.Items {
			c.octeliumC.CoreC().DeleteAuthenticator(ctx, &rmetav1.DeleteOptions{Uid: authn.Metadata.Uid})
		}
	}

	{
		devList, err := c.octeliumC.CoreC().ListDevice(ctx, urscsrv.FilterByUser(usr))
		if err != nil {
			return err
		}

		for _, dev := range devList.Items {
			c.octeliumC.CoreC().DeleteDevice(ctx, &rmetav1.DeleteOptions{Uid: dev.Metadata.Uid})
		}
	}

	{
		sessList, err := c.octeliumC.CoreC().ListSession(ctx, urscsrv.FilterByUser(usr))
		if err != nil {
			return err
		}

		for _, sess := range sessList.Items {
			c.octeliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{Uid: sess.Metadata.Uid})
		}
	}

	return nil
}
