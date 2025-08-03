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
	"os"
	"os/exec"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func (c *Controller) doInitDev(ctx context.Context) error {
	zap.L().Debug("Initializing dev")

	if c.c.Preferences.LinuxPrefs.EnforceImplementationMode {
		zap.L().Debug("Enforcing WireGuard mode",
			zap.String("mode", c.c.Preferences.LinuxPrefs.ImplementationMode.String()))
		switch c.c.Preferences.LinuxPrefs.ImplementationMode {
		case cliconfigv1.Connection_Preferences_Linux_WG_KERNEL:
			return c.doInitDevKernel()
		case cliconfigv1.Connection_Preferences_Linux_WG_USERSPACE:
			return c.doInitDevTUN(ctx)
		case cliconfigv1.Connection_Preferences_Linux_WG_NETSTACK:
			return c.doInitDevNetstack(ctx)
		default:
			return errors.Errorf("unknown Implementation is enforced")
		}
	}

	if !c.isQUIC {
		if err := c.doInitDevKernel(); err == nil {
			zap.L().Debug("WG mode chosen: kernel")
			return nil
		} else {
			c.c.Preferences.LinuxPrefs.ImplementationMode = cliconfigv1.Connection_Preferences_Linux_WG_USERSPACE
			zap.L().Debug("Could not init kernel implementation. Trying userspace.", zap.Error(err))
		}
	}
	{
		if err := c.doInitDevTUN(ctx); err == nil {
			zap.L().Debug("WG mode chosen: TUN mode")
			return nil
		} else {
			c.c.Preferences.LinuxPrefs.ImplementationMode = cliconfigv1.Connection_Preferences_Linux_WG_NETSTACK
			zap.L().Debug("Could not init userspace implementation. Trying gVisor netstack mode.", zap.Error(err))
		}
	}

	if err := c.doInitDevNetstack(ctx); err != nil {
		return errors.Errorf("Could not init netstack dev: %+v", err)
	}

	return nil

}

func (c *Controller) prepareTUN() error {

	zap.S().Debugf("Checking whether /dev/net/tun exists")
	_, err := os.Stat("/dev/net/tun")
	if err == nil {
		zap.L().Debug("/dev/net/tun exists. No mknod needed")
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}

	zap.L().Debug("mknoding /dev/net/tun")

	cmds := []string{
		"mkdir -p /dev/net",
		"mknod /dev/net/tun c 10 200",
		"chmod 600 /dev/net/tun",
	}

	for _, cmd := range cmds {
		if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
			return errors.Errorf("Could not install /dev/net/tun device: %+v", err)
		}
	}

	return nil
}

func (c *Controller) doInitDevKernel() error {

	link := newWgLink(c.c.Preferences.DeviceName, c.getMTU())

	if err := netlink.LinkAdd(link); err != nil {
		return err
	}

	return nil
}

type WgLink struct {
	attr     netlink.LinkAttrs
	linkType string
}

func newWgLink(name string, mtu int) WgLink {
	ret := WgLink{attr: netlink.NewLinkAttrs(), linkType: "wireguard"}
	ret.attr.Name = name
	ret.attr.MTU = mtu

	return ret
}

func (w WgLink) Attrs() *netlink.LinkAttrs {
	return &w.attr
}

func (w WgLink) Type() string {
	return w.linkType
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

	zap.L().Debug("Setting dev up")
	link := newWgLink(c.c.Preferences.DeviceName, c.getMTU())

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	return nil
}

func (c *Controller) doDeleteDev() error {
	if c.isNetstack {
		return nil
	}

	zap.L().Debug("Deleting dev")
	l, err := netlink.LinkByName(c.c.Preferences.DeviceName)
	if err != nil {
		return err
	}

	if err := netlink.LinkDel(l); err != nil {
		return err
	}
	return nil
}

func (c *Controller) doSetDevAddrs() error {

	if c.isNetstack {
		return nil
	}

	zap.L().Debug("Setting dev addresses")
	l, err := netlink.LinkByName(c.c.Preferences.DeviceName)
	if err != nil {
		return err
	}

	if len(c.c.Connection.Addresses) < 1 {
		return errors.Errorf("No addresses found for the connection")
	}

	oldAddrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	addAddrs := []*metav1.DualStackNetwork{}
	deleteAddrs := []netlink.Addr{}

	isInAddList := func(lst []*metav1.DualStackNetwork, itm *metav1.DualStackNetwork) bool {
		for _, i := range lst {
			if i.V4 == itm.V4 && i.V6 == itm.V6 {
				return true
			}
		}
		return false
	}

	for _, addr := range c.c.Connection.Addresses {
		isAdd := func() bool {
			for _, oldAddr := range oldAddrs {
				oldIPNet := oldAddr.IPNet.String()
				if oldIPNet == addr.V4 || oldIPNet == addr.V6 {
					return false
				}
			}
			return true
		}()
		if isAdd && !isInAddList(addAddrs, addr) {
			addAddrs = append(addAddrs, addr)
		}
	}

	for _, oldAddr := range oldAddrs {
		isDelete := func() bool {
			for _, addr := range c.c.Connection.Addresses {
				oldIPNet := oldAddr.IPNet.String()
				if oldIPNet == addr.V4 || oldIPNet == addr.V6 {
					return false
				}
			}
			return true
		}()

		if isDelete {
			deleteAddrs = append(deleteAddrs, oldAddr)
		}
	}

	for _, ip := range addAddrs {
		if c.ipv4Supported && ip.V4 != "" {
			_, cidr, err := net.ParseCIDR(ip.V4)
			if err != nil {
				return err
			}
			zap.L().Debug("Adding ipv4 addr", zap.String("addr", cidr.String()))
			if err := netlink.AddrAdd(l, &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   cidr.IP,
					Mask: cidr.Mask,
				},
			}); err != nil {
				return err
			}
		}

		if c.ipv6Supported && ip.V6 != "" {
			_, cidr, err := net.ParseCIDR(ip.V6)
			if err != nil {
				return err
			}
			zap.L().Debug("Adding ipv6 addr", zap.String("addr", cidr.String()))
			if err := netlink.AddrAdd(l, &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   cidr.IP,
					Mask: cidr.Mask,
				},
			}); err != nil {
				return err
			}
		}
	}

	for _, addr := range deleteAddrs {
		if err := netlink.AddrDel(l, &addr); err != nil {
			return err
		}
	}

	return nil
}

func (c *Controller) doInitDevTUN(ctx context.Context) error {

	if err := c.prepareTUN(); err != nil {
		return err
	}

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
	} else {
		return c.doInitDevTunWG(ctx)
	}
}

func (c *Controller) doInitDevTunWG(ctx context.Context) error {
	logger := device.NewLogger(
		device.LogLevelSilent,
		fmt.Sprintf("(%s) ", c.c.Preferences.DeviceName),
	)

	fileUAPI, err := ipc.UAPIOpen(c.c.Preferences.DeviceName)
	if err != nil {
		return errors.Errorf("Could not open UAPI: %+v", err)
	}

	device := device.NewDevice(c.getTUNDev(), conn.NewDefaultBind(), logger)

	uapi, err := ipc.UAPIListen(c.c.Preferences.DeviceName, fileUAPI)
	if err != nil {
		return errors.Errorf("Could not listen UAPI: %+v", err)
	}

	go func(ctx context.Context) {
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
	}(ctx)

	c.dev = device
	c.uapi = uapi

	return nil
}

func (c *Controller) doSetTunDev() error {
	const devTunPath = "/dev/net/tun"

	zap.L().Debug("Creating TUN device",
		zap.String("name", c.c.Preferences.DeviceName),
		zap.Int("mtu", c.getMTU()))

	if !c.isQUIC {
		tundev, err := tun.CreateTUN(c.c.Preferences.DeviceName, c.getMTU())
		if err != nil {
			return errors.Errorf("Could not create TUN dev %+v", err)
		}

		c.tundev = tundev
		return nil
	}

	nfd, err := unix.Open(devTunPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return err
		}
		return err
	}

	ifr, err := unix.NewIfreq(c.c.Preferences.DeviceName)
	if err != nil {
		return err
	}

	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		return err
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		return err
	}

	fd := os.NewFile(uintptr(nfd), devTunPath)
	tundev, err := tun.CreateTUNFromFile(fd, c.getMTU())
	if err != nil {
		return errors.Errorf("Could not create TUN dev %+v", err)
	}

	c.tundev = tundev
	return nil
}
