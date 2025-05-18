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
	"net/netip"

	"github.com/asaskevich/govalidator"
	"golang.org/x/sys/windows"
)

func (c *Controller) doSetDNS() error {
	if c.isNetstack {
		return nil
	}

	luid := c.opts.adapter.LUID()

	dnsServers := c.getDNSServers()

	if c.ipv4Supported {
		dnsAddrs := []netip.Addr{}

		for _, addr := range dnsServers {
			if govalidator.IsIPv4(addr) {
				netaddr, err := netip.ParseAddr(addr)
				if err != nil {
					return err
				}
				dnsAddrs = append(dnsAddrs, netaddr)
			}
		}

		if err := luid.SetDNS(windows.AF_INET, dnsAddrs, c.getDNSSearchDomains()); err != nil {
			return err
		}
	}

	if c.ipv6Supported {
		dnsAddrs := []netip.Addr{}

		for _, addr := range dnsServers {
			if govalidator.IsIPv6(addr) {
				netaddr, err := netip.ParseAddr(addr)
				if err != nil {
					return err
				}
				dnsAddrs = append(dnsAddrs, netaddr)
			}
		}

		if err := luid.SetDNS(windows.AF_INET6, dnsAddrs, c.getDNSSearchDomains()); err != nil {
			return err
		}
	}

	return nil
}

func (c *Controller) doUnsetDNS() error {
	if c.isNetstack {
		return nil
	}

	if c.opts.adapter == nil {
		return nil
	}

	luid := c.opts.adapter.LUID()

	if c.ipv4Supported {
		if err := luid.FlushDNS(windows.AF_INET); err != nil {
			return err
		}
	}

	if c.ipv6Supported {
		if err := luid.FlushDNS(windows.AF_INET6); err != nil {
			return err
		}
	}

	return nil
}
