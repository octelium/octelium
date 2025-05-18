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

package controller

import (
	"context"
	"fmt"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func (c *Controller) setDevUp() error {

	return c.doSetDevUp()
}

func (c *Controller) DeleteDev() error {
	if c.isQUIC && c.quicEngine != nil {
		c.quicEngine.close()
	}
	return c.doDeleteDev()
}

func (c *Controller) SetDevAddrs() error {
	return c.doSetDevAddrs()
}

func (c *Controller) doInitDevNetstack(ctx context.Context) error {
	if err := c.createNetstackTUN(); err != nil {
		return err
	}

	if c.isQUIC {
		return c.doInitDevQUICV0(ctx)
	}

	logger := device.NewLogger(
		device.LogLevelSilent,
		fmt.Sprintf("(%s) ", c.c.Preferences.DeviceName),
	)

	device := device.NewDevice(c.getTUNDev(), conn.NewDefaultBind(), logger)
	if err := device.IpcSet(c.toUAPI()); err != nil {
		return err
	}

	if err := device.Up(); err != nil {
		return err
	}

	c.dev = device

	return nil
}

func (c *Controller) getTUNDev() tun.Device {
	if c.isNetstack {
		return c.nsTun
	}
	return c.tundev
}
