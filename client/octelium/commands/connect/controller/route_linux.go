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

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
)

func (c *Controller) doSetRoutes() error {
	if c.isNetstack {
		return nil
	}

	zap.S().Debugf("setting routes")

	mainTable := int(c.c.Preferences.LinuxPrefs.MainTableIndex)
	l, err := netlink.LinkByName(c.c.Preferences.DeviceName)
	if err != nil {
		return err
	}

	doAddRoute := func(arg string, table int) error {
		_, route, err := net.ParseCIDR(arg)
		if err != nil {
			return err
		}

		return netlink.RouteAdd(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Table:     table,
			Dst:       route,
		})
	}

	cidr := c.c.Connection.Cidr

	if c.ipv4Supported && cidr.V4 != "" {
		zap.S().Debugf("setting route: %s", cidr.V4)
		if err := doAddRoute(cidr.V4, mainTable); err != nil {
			return errors.Errorf("Could not set route: %s: %+v", cidr.V4, err)
		}
	}

	if c.ipv6Supported && cidr.V6 != "" {
		zap.S().Debugf("setting route: %s", cidr.V6)
		if err := doAddRoute(cidr.V6, mainTable); err != nil {
			return errors.Errorf("Could not set route: %s: %+v", cidr.V6, err)
		}
	}

	return nil
}

func (c *Controller) doUnsetRoutes() error {
	if c.isNetstack {
		return nil
	}

	tableIdx := int(c.c.Preferences.LinuxPrefs.TableIndex)

	l, err := netlink.LinkByName(c.c.Preferences.DeviceName)
	if err != nil {
		return err
	}

	doDeleteRoute := func(arg string) error {
		_, route, _ := net.ParseCIDR(arg)
		return netlink.RouteDel(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Table:     tableIdx,
			Dst:       route,
		})
	}

	cidr := c.c.Connection.Cidr

	if c.ipv4Supported && cidr.V4 != "" {
		if err := doDeleteRoute(cidr.V4); err != nil {
			return err
		}
	}

	if c.ipv6Supported && cidr.V6 != "" {
		if err := doDeleteRoute(cidr.V6); err != nil {
			return err
		}
	}

	return nil
}
