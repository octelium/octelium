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
	"github.com/octelium/octelium/cluster/common/vutils"
)

type serverI interface {
	SetClusterCertificate(crt *corev1.Secret) error
}

type secretManI interface {
	Set(secret *corev1.Secret)
	Delete(secret *corev1.Secret)
}

type serviceGetter interface {
	GetService() *corev1.Service
}

type Controller struct {
	srv           serverI
	secretMan     secretManI
	serviceGetter serviceGetter
}

func NewController(
	srv serverI,
	secretMan secretManI,
	serviceGetter serviceGetter,
) *Controller {
	return &Controller{
		srv:           srv,
		secretMan:     secretMan,
		serviceGetter: serviceGetter,
	}
}

func (c *Controller) OnAdd(ctx context.Context, secret *corev1.Secret) error {

	if c.isReadyClusterCrt(secret) {
		return c.srv.SetClusterCertificate(secret)
	}

	c.secretMan.Set(secret)

	return nil
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.Secret) error {

	if c.isReadyClusterCrt(new) {
		return c.srv.SetClusterCertificate(new)
	}

	c.secretMan.Set(new)

	return nil
}

func (c *Controller) OnDelete(ctx context.Context, secret *corev1.Secret) error {
	if c.isReadyClusterCrt(secret) {
		return c.srv.SetClusterCertificate(nil)
	}

	c.secretMan.Delete(secret)

	return nil
}

func (c *Controller) isReadyClusterCrt(crt *corev1.Secret) bool {
	ns := "default"
	if c.serviceGetter != nil {
		ns = c.serviceGetter.GetService().Status.NamespaceRef.Name
	}
	return vutils.IsClusterCertAndReadyWithNamespace(crt, ns)
}
