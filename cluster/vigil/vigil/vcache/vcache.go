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

package vcache

import (
	"context"
	"sync/atomic"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

type Cache struct {
	svc atomic.Pointer[corev1.Service]
}

func NewCache(ctx context.Context) (*Cache, error) {
	return &Cache{}, nil
}

func (c *Cache) SetService(svc *corev1.Service) {
	clone := pbutils.Clone(svc).(*corev1.Service)
	c.svc.Store(clone)
}

func (c *Cache) GetService() *corev1.Service {
	svc := c.svc.Load()
	if svc == nil {
		return nil
	}
	return pbutils.Clone(svc).(*corev1.Service)
}
