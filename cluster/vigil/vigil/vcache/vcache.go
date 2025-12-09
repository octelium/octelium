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
	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
)

type Cache struct {
	// c   *cache.Cache
	mu  sync.RWMutex
	svc *corev1.Service
}

func NewCache(ctx context.Context) (*Cache, error) {
	return &Cache{
		// c: cache.New(5*cache.NoExpiration, 10*time.Minute),
	}, nil
}

func (c *Cache) SetService(svc *corev1.Service) {
	// c.c.Set("svc", svc, cache.NoExpiration)
	c.mu.Lock()
	c.svc = svc
	c.mu.Unlock()
}

func (c *Cache) GetService() *corev1.Service {
	c.mu.RLock()
	ret := c.svc
	c.mu.RUnlock()
	return ret
}
