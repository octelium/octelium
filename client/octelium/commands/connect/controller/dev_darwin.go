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
	"net"
	"os/exec"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func (c *Controller) doInitDev(ctx context.Context) error {
	err := c.doInitDevTUN(ctx)
	if err == nil {
		return nil
	}
	zap.L().Debug("Could not init TUN implementation. Trying gVisor netstack mode.", zap.Error(err))
	return c.doInitDevNetstack(ctx)
}

func (c *Controller) doSetDevUp() error {
	if c.isNetstack {
		if !c.isQUIC {
			if err := c.dev.Up(); err != nil {
				return err
			}
		}
		return nil
	}

	zap.S().Debugf("setting dev up")
	if o, err := exec.Command("ifconfig", c.c.Preferences.DeviceName, "up").CombinedOutput(); err != nil {
		zap.S().Debugf("Could not set dev up: %s", string(o))
		return err
	}
	return nil
}

func (c *Controller) doDeleteDev() error {
	if c.isNetstack {
		return nil
	}

	if c.uapi != nil {
		c.uapi.Close()
	}
	if c.dev != nil {
		c.dev.Down()
	}

	zap.S().Debugf("setting dev down")
	if o, err := exec.Command("ifconfig", c.c.Preferences.DeviceName, "down").CombinedOutput(); err != nil {
		zap.S().Warnf("Could not set dev down: %s", string(o))
	}

	return nil
}

func (c *Controller) doSetDevAddrs() error {
	if c.isNetstack {
		return nil
	}

	curDevAddrs, err := c.getDevAddresses()
	if err != nil {
		return err
	}

	isInConfigAddrs := func(addr string) bool {
		for _, curAddr := range c.c.Connection.Addresses {
			if addr == curAddr.V4 || addr == curAddr.V6 {
				return true
			}
		}
		return false
	}

	for _, addr := range curDevAddrs {
		if !isInConfigAddrs(addr) {
			zap.S().Debugf("The address %s is going to be removed", addr)
			ip, _, _ := net.ParseCIDR(addr)
			cmdArgs := []string{c.c.Preferences.DeviceName}
			if govalidator.IsIPv4(ip.String()) {
				cmdArgs = append(cmdArgs, "inet")
			} else {
				cmdArgs = append(cmdArgs, "inet6")
			}
			cmdArgs = append(cmdArgs, addr, "-alias")

			if o, err := exec.Command("ifconfig", cmdArgs...).CombinedOutput(); err != nil {
				return errors.Errorf("Could not remove address %s: %s", addr, string(o))
			}
		}
	}

	for _, addr := range c.c.Connection.Addresses {
		if c.ipv4Supported && addr.V4 != "" {
			ip, _, _ := net.ParseCIDR(addr.V4)
			zap.S().Debugf("Adding the address: %s", ip.String())
			if o, err := exec.Command("ifconfig", c.c.Preferences.DeviceName, "inet", addr.V4, ip.String(), "alias").CombinedOutput(); err != nil {
				return errors.Errorf("Could not set address %s: %s", addr.V4, string(o))
			}
		}

		if c.ipv6Supported && addr.V6 != "" {
			ip, _, _ := net.ParseCIDR(addr.V6)
			zap.S().Debugf("Adding the address: %s", ip.String())
			if o, err := exec.Command("ifconfig", c.c.Preferences.DeviceName, "inet6", addr.V6, ip.String(), "alias").CombinedOutput(); err != nil {
				return errors.Errorf("Could not set address %s: %s", addr.V4, string(o))
			}
		}
	}
	return nil
}

func (c *Controller) getDevAddresses() ([]string, error) {
	iface, err := net.InterfaceByName(c.c.Preferences.DeviceName)
	if err != nil {
		return nil, err
	}
	zap.S().Debugf("Found interface: %+v", iface)
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	zap.S().Debugf("Found current dev addresses: %+q", addrs)

	ret := []string{}
	for _, addr := range addrs {
		ret = append(ret, addr.String())
	}

	return ret, nil

}

func (c *Controller) doInitDevTUN(ctx context.Context) error {

	if err := c.doSetTunDev(); err != nil {
		return err
	}

	realdevname, err := c.tundev.Name()
	if err != nil {
		return err
	}

	if realdevname != c.c.Preferences.DeviceName {
		zap.S().Debugf("real tun device name is now: %s", realdevname)
		c.c.Preferences.DeviceName = realdevname
	}

	if c.isQUIC {
		return c.doInitDevQUICV0(ctx)
	}

	logger := device.NewLogger(
		device.LogLevelSilent,
		fmt.Sprintf("(%s) ", c.c.Preferences.DeviceName),
	)

	fileUAPI, err := ipc.UAPIOpen(c.c.Preferences.DeviceName)
	if err != nil {
		return errors.Errorf("Could not open UAPI: %+v", err)
	}

	device := device.NewDevice(c.tundev, conn.NewDefaultBind(), logger)

	uapi, err := ipc.UAPIListen(c.c.Preferences.DeviceName, fileUAPI)
	if err != nil {
		return errors.Errorf("Could not listen UAPI: %+v", err)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn, err := uapi.Accept()
				if err != nil {
					zap.S().Debugf("Could not accept UAPI conn: %+v", err)
					return
				}
				go device.IpcHandle(conn)
			}

		}
	}()

	c.dev = device
	c.uapi = uapi

	return nil
}

func (c *Controller) doSetTunDev() error {

	zap.L().Debug("Creating TUN device",
		zap.String("name", c.c.Preferences.DeviceName),
		zap.Int("mtu", c.getMTU()))

	tundev, err := tun.CreateTUN(c.c.Preferences.DeviceName, c.getMTU())
	if err != nil {
		return errors.Errorf("Could not create TUN dev %+v", err)
	}

	c.tundev = tundev

	return nil
}
