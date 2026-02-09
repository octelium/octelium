// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"context"
	"sync"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	controller "github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy"
	"go.uber.org/zap"
)

type Controller struct {
	c *cliconfigv1.Connection

	ipv4Supported bool
	ipv6Supported bool
	ctl           *controller.Controller

	goNetCtl ccommon.GoNetCtl
	mu       sync.Mutex
	isClosed bool

	ctx      context.Context
	cancelFn context.CancelFunc
}

func NewController(ctx context.Context, c *cliconfigv1.Connection, goNetCtl ccommon.GoNetCtl) (*Controller, error) {

	ipv4Supported := c.Connection.L3Mode == userv1.ConnectionState_BOTH ||
		c.Connection.L3Mode == userv1.ConnectionState_V4
	ipv6Supported := c.Connection.L3Mode == userv1.ConnectionState_BOTH ||
		c.Connection.L3Mode == userv1.ConnectionState_V6

	ret := &Controller{
		c:             c,
		ipv4Supported: ipv4Supported,
		ipv6Supported: ipv6Supported,
		goNetCtl:      goNetCtl,
	}

	ctl, err := controller.NewController(ctx, c, ret.goNetCtl)
	if err != nil {
		return nil, err
	}
	ret.ctl = ctl

	return ret, nil
}

func (c *Controller) Start(ctx context.Context) error {
	c.ctx, c.cancelFn = context.WithCancel(ctx)

	zap.L().Debug("Starting proxy controller")

	return c.ctl.Start(ctx)
}

func (c *Controller) AddService(svc *userv1.HostedService) error {

	if err := c.ctl.AddService(c.ctx, svc); err != nil {
		return err
	}

	return nil
}

func (c *Controller) DeleteService(name string) error {

	return c.ctl.DeleteService(name)
}

func (c *Controller) UpdateService(svc *userv1.HostedService) error {

	return c.ctl.UpdateService(c.ctx, svc)
}

func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return nil
	}
	zap.S().Debugf("Closing proxy controller...")
	c.isClosed = true
	c.cancelFn()

	return c.ctl.Close()
}
