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

package policytemplates

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
)

type Controller struct {
	c PolicyTriggerCtlI
}

type PolicyTriggerCtlI interface {
	SetPolicyTrigger(i *corev1.PolicyTrigger) error
	DeletePolicyTrigger(i *corev1.PolicyTrigger) error
}

func NewController(c PolicyTriggerCtlI) *Controller {
	return &Controller{
		c: c,
	}
}

func (c *Controller) OnAdd(ctx context.Context, p *corev1.PolicyTrigger) error {
	return c.c.SetPolicyTrigger(p)
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.PolicyTrigger) error {
	return c.c.SetPolicyTrigger(new)
}

func (c *Controller) OnDelete(ctx context.Context, p *corev1.PolicyTrigger) error {
	return c.c.SetPolicyTrigger(p)
}
