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
	"net"
	"net/netip"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/pkg/utils/netutils"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func (c *Controller) doSetRoutes() error {
	if c.isNetstack {
		return nil
	}

	luid := c.opts.adapter.LUID()
	routes := []*winipcfg.RouteData{}

	for _, gw := range c.c.Connection.Gateways {
		for _, cidr := range gw.CIDRs {
			ip, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				return err
			}

			nextHopIP, err := netutils.GetIndexedIP(ipnet, 1)
			if err != nil {
				return err
			}

			if c.ipv4Supported && govalidator.IsIPv4(ip.String()) {
				routes = append(routes, &winipcfg.RouteData{
					Destination: netip.MustParsePrefix(ipnet.String()),
					NextHop:     netip.MustParseAddr(nextHopIP.String()),
					Metric:      0,
				})
			}

			if c.ipv6Supported && govalidator.IsIPv6(ip.String()) {
				routes = append(routes, &winipcfg.RouteData{
					Destination: netip.MustParsePrefix(ipnet.String()),
					NextHop:     netip.MustParseAddr(nextHopIP.String()),
					Metric:      0,
				})
			}

		}
	}

	if err := luid.SetRoutes(routes); err != nil {
		return err
	}

	return c.setIPIF()
}

func (c *Controller) setIPIF() error {
	zap.S().Debugf("Setting IPIF")
	luid := c.opts.adapter.LUID()

	if c.ipv4Supported {
		ipif, err := luid.IPInterface(windows.AF_INET)
		if err != nil {
			return err
		}

		ipif.NLMTU = uint32(c.getMTU())
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0

		if err := ipif.Set(); err != nil {
			return err
		}
	}

	if c.ipv6Supported {
		ipif, err := luid.IPInterface(windows.AF_INET6)
		if err != nil {
			return err
		}

		ipif.NLMTU = uint32(c.getMTU())
		ipif.UseAutomaticMetric = false
		ipif.Metric = 0

		if err := ipif.Set(); err != nil {
			return err
		}
	}

	return nil
}

func (c *Controller) doUnsetRoutes() error {

	if c.ipv4Supported {
		if err := c.opts.adapter.LUID().FlushRoutes(windows.AF_INET); err != nil {
			return err
		}
	}

	if c.ipv6Supported {
		if err := c.opts.adapter.LUID().FlushRoutes(windows.AF_INET6); err != nil {
			return err
		}
	}

	return nil

}
