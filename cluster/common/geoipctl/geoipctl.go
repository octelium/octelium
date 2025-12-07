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

package geoipctl

import (
	"context"
	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/oschwald/geoip2-golang/v2"
	"github.com/pkg/errors"
)

type Opts struct {
	ConfigName string
	OcteliumC  octeliumc.ClientInterface
}

type Controller struct {
	octeliumC octeliumc.ClientInterface
	mu        sync.RWMutex
	db        *geoip2.Reader
	name      string
}

func New(ctx context.Context, o *Opts) (*Controller, error) {
	ret := &Controller{
		octeliumC: o.OcteliumC,
		name:      o.ConfigName,
	}

	return ret, nil
}

func (c *Controller) Run(ctx context.Context) error {

	if cfg, err := c.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{
		Name: c.name,
	}); err == nil {
		return c.setConfig(ctx, cfg)
	}

	if err := watchers.NewCoreV1(c.octeliumC).Config(ctx, nil,
		func(ctx context.Context, item *corev1.Config) error {
			return c.setConfig(ctx, item)
		}, func(ctx context.Context, new, old *corev1.Config) error {
			return c.setConfig(ctx, new)
		}, func(ctx context.Context, item *corev1.Config) error {
			return nil
		}); err != nil {
		return err
	}

	return nil
}

func (c *Controller) setConfig(ctx context.Context, cfg *corev1.Config) error {

	c.mu.Lock()
	defer c.mu.Unlock()
	var err error

	if cfg == nil || cfg.Data == nil || len(cfg.Data.GetValueBytes()) == 0 {
		return errors.Errorf("Could not find config content")
	}

	c.db, err = geoip2.OpenBytes(cfg.Data.GetValueBytes())
	if err != nil {
		return err
	}

	return nil
}
