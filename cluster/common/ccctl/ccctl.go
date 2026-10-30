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

package ccctl

import (
	"context"
	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

type Controller struct {
	mu        sync.RWMutex
	cc        *corev1.ClusterConfig
	octeliumC octeliumc.ClientInterface
	opts      *Opts
}

type Opts struct {
	OnUpdate func(ctx context.Context, new, old *corev1.ClusterConfig) error
}

func New(ctx context.Context, octeliumC octeliumc.ClientInterface, o *Opts) (*Controller, error) {
	ret := &Controller{
		octeliumC: octeliumC,
		opts:      o,
	}
	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}
	ret.cc = pbutils.Clone(cc).(*corev1.ClusterConfig)

	return ret, nil
}

func (c *Controller) Run(ctx context.Context) error {

	watcher, err := watchers.NewWatcher(ucorev1.API, ucorev1.Version, ucorev1.KindClusterConfig,
		func(ctx context.Context, item umetav1.ResourceObjectI) error {
			return c.set(ctx, item.(*corev1.ClusterConfig), nil)
		},
		func(ctx context.Context, new, old umetav1.ResourceObjectI) error {
			return c.set(ctx, new.(*corev1.ClusterConfig), old.(*corev1.ClusterConfig))
		},
		nil, c.octeliumC.CoreC(), func() (umetav1.ResourceObjectI, error) {
			return ucorev1.NewObject(ucorev1.KindClusterConfig)
		})
	if err != nil {
		return err
	}

	return watcher.Run(ctx)
}

func (c *Controller) set(ctx context.Context, new, old *corev1.ClusterConfig) error {
	c.mu.Lock()
	cur := c.cc
	c.cc = pbutils.Clone(new).(*corev1.ClusterConfig)
	c.mu.Unlock()

	if old == nil {
		if pbutils.IsEqual(cur, new) {
			return nil
		}
		old = cur
	}

	if c.opts != nil && c.opts.OnUpdate != nil {
		return c.opts.OnUpdate(ctx, new, old)
	}

	return nil
}

func (c *Controller) Get() *corev1.ClusterConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return pbutils.Clone(c.cc).(*corev1.ClusterConfig)
}
