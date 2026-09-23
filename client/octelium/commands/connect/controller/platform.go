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
	stderrors "errors"
	"fmt"
	"net/netip"

	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type Platform interface {
	OpenTUN(ctx context.Context, cfg *mobilev1.TunnelConfiguration) (tun.Device, error)
	SetTunnelConfiguration(ctx context.Context, cfg *mobilev1.TunnelConfiguration) error
	WatchNetwork(ctx context.Context) <-chan struct{}
}

func (c *Controller) isUserspaceDev() bool {
	return c.isNetstack || c.platform != nil
}

func (c *Controller) startPlatform(ctx context.Context) error {
	cfg, err := c.getTunnelConfiguration()
	if err != nil {
		return err
	}

	tunDev, err := c.platform.OpenTUN(ctx, cfg)
	if err != nil {
		return err
	}

	c.platformCtx = ctx
	c.tundev = tunDev

	if c.isQUIC {
		if err := c.doInitDevQUICV0(ctx); err != nil {
			return err
		}
	} else {
		if err := c.doInitDevPlatformWG(); err != nil {
			return err
		}
	}

	go c.startPlatformNetworkLoop(ctx)

	return nil
}

func (c *Controller) doInitDevPlatformWG() error {
	logger := device.NewLogger(
		device.LogLevelSilent,
		fmt.Sprintf("(%s) ", c.c.Preferences.DeviceName),
	)

	dev := device.NewDevice(c.tundev, conn.NewDefaultBind(), logger)
	dev.DisableSomeRoamingForBrokenMobileSemantics()

	if err := dev.IpcSet(c.toUAPI()); err != nil {
		dev.Close()
		return err
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return err
	}

	c.dev = dev

	return nil
}

func (c *Controller) doClosePlatform() error {
	var retErr error

	if c.quicEngine != nil {
		retErr = stderrors.Join(retErr, c.quicEngine.close())
	}

	if c.dev != nil {
		c.dev.Close()
	}

	if c.tundev != nil {
		if err := c.tundev.Close(); err != nil {
			zap.L().Debug("Could not close the platform TUN device", zap.Error(err))
			retErr = stderrors.Join(retErr, err)
		}
	}

	return retErr
}

func (c *Controller) setPlatformTunnelConfiguration() error {
	if c.platformCtx == nil {
		return errors.Errorf("The controller is not started")
	}

	cfg, err := c.getTunnelConfiguration()
	if err != nil {
		return err
	}

	return c.platform.SetTunnelConfiguration(c.platformCtx, cfg)
}

func (c *Controller) getTunnelConfiguration() (*mobilev1.TunnelConfiguration, error) {
	ret := &mobilev1.TunnelConfiguration{
		Mtu: int32(c.getMTU()),
	}

	appendPrefix := func(lst []string, arg string, isV6 bool) ([]string, error) {
		if arg == "" {
			return lst, nil
		}

		prefix, err := netip.ParsePrefix(arg)
		if err != nil {
			return nil, errors.Errorf("Invalid prefix: %s", arg)
		}

		if prefix.Addr().Is6() != isV6 {
			return nil, errors.Errorf("Invalid prefix family: %s", arg)
		}

		if (isV6 && !c.ipv6Supported) || (!isV6 && !c.ipv4Supported) {
			return lst, nil
		}

		return append(lst, prefix.String()), nil
	}

	var err error

	for _, addr := range c.c.Connection.Addresses {
		if ret.Addresses, err = appendPrefix(ret.Addresses, addr.V4, false); err != nil {
			return nil, err
		}
		if ret.Addresses, err = appendPrefix(ret.Addresses, addr.V6, true); err != nil {
			return nil, err
		}
	}

	if len(ret.Addresses) == 0 {
		return nil, errors.Errorf("No addresses found for the connection")
	}

	if cidr := c.c.Connection.Cidr; cidr != nil {
		if ret.Routes, err = appendPrefix(ret.Routes, cidr.V4, false); err != nil {
			return nil, err
		}
		if ret.Routes, err = appendPrefix(ret.Routes, cidr.V6, true); err != nil {
			return nil, err
		}
	}

	if c.c.Preferences.IgnoreDNS {
		return ret, nil
	}

	servers := c.getClusterDNSServers()
	if len(servers) == 0 {
		return ret, nil
	}

	ret.Dns = &mobilev1.TunnelConfiguration_DNS{
		Servers:         servers,
		SearchDomains:   c.getDNSSearchDomains(),
		MatchAllDomains: c.isFullDNS(),
	}

	if !ret.Dns.MatchAllDomains {
		ret.Dns.MatchDomains = c.getDNSSearchDomains()
	}

	return ret, nil
}

func (c *Controller) startPlatformNetworkLoop(ctx context.Context) {
	networkCh := c.platform.WatchNetwork(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-networkCh:
			if !ok {
				return
			}

			c.onNetworkChanged()
		}
	}
}

func (c *Controller) onNetworkChanged() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return
	}

	zap.L().Debug("The underlying network has changed. Rebinding the tunnel transport")

	if c.isQUIC {
		if c.quicEngine != nil {
			c.quicEngine.reconnectGWs()
		}
		return
	}

	if c.dev == nil {
		return
	}

	if err := c.dev.BindUpdate(); err != nil {
		zap.L().Warn("Could not rebind the WireGuard device", zap.Error(err))
		return
	}

	c.dev.SendKeepalivesToPeersWithCurrentKeypair()
}
