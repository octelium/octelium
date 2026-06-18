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
	"sync/atomic"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

type Cache struct {
	svc      atomic.Pointer[corev1.Service]
	children atomic.Pointer[map[string]*corev1.Service]
	childMu  sync.Mutex
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

func (c *Cache) SetChildService(svc *corev1.Service) {
	if svc == nil {
		return
	}
	name := svc.GetMetadata().GetName()
	if name == "" {
		return
	}
	clone := pbutils.Clone(svc).(*corev1.Service)

	c.childMu.Lock()
	defer c.childMu.Unlock()

	next := c.copyChildrenLocked()
	next[name] = clone
	c.children.Store(&next)
}

func (c *Cache) SetChildServices(svcs []*corev1.Service) {
	next := make(map[string]*corev1.Service, len(svcs))
	for _, svc := range svcs {
		if svc == nil {
			continue
		}
		name := svc.GetMetadata().GetName()
		if name == "" {
			continue
		}
		next[name] = pbutils.Clone(svc).(*corev1.Service)
	}

	c.childMu.Lock()
	defer c.childMu.Unlock()
	c.children.Store(&next)
}

func (c *Cache) DeleteChildService(name string) {
	if name == "" {
		return
	}

	c.childMu.Lock()
	defer c.childMu.Unlock()

	cur := c.children.Load()
	if cur == nil {
		return
	}
	if _, ok := (*cur)[name]; !ok {
		return
	}
	next := c.copyChildrenLocked()
	delete(next, name)
	c.children.Store(&next)
}

func (c *Cache) GetChildService(name string) *corev1.Service {
	if name == "" {
		return nil
	}
	cur := c.children.Load()
	if cur == nil {
		return nil
	}
	svc, ok := (*cur)[name]
	if !ok {
		return nil
	}
	return pbutils.Clone(svc).(*corev1.Service)
}

func (c *Cache) GetServiceByName(name string) *corev1.Service {
	if name == "" {
		return nil
	}
	if parent := c.svc.Load(); parent != nil && parent.GetMetadata().GetName() == name {
		return pbutils.Clone(parent).(*corev1.Service)
	}
	return c.GetChildService(name)
}

func (c *Cache) copyChildrenLocked() map[string]*corev1.Service {
	cur := c.children.Load()
	if cur == nil {
		return make(map[string]*corev1.Service)
	}
	next := make(map[string]*corev1.Service, len(*cur)+1)
	for k, v := range *cur {
		next[k] = v
	}
	return next
}
