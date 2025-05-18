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

	"golang.zx2c4.com/wireguard/windows/conf"
)

func (c *Controller) getWgConf() (*conf.Config, error) {

	pk, err := conf.NewPrivateKeyFromString(c.wgPrivateKey.String())
	if err != nil {
		return nil, err
	}

	addrs := []netip.Prefix{}

	for _, addr := range c.c.Connection.Addresses {
		if c.ipv4Supported && addr.V4 != "" {
			naddr, err := netip.ParsePrefix(addr.V4)
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, naddr)
		}

		if c.ipv6Supported && addr.V4 != "" {
			naddr, err := netip.ParsePrefix(addr.V6)
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, naddr)
		}
	}

	dnsAddrs := []net.IP{}

	dnsServers := c.getDNSServers()

	for _, dnsAddr := range dnsServers {
		dnsAddrs = append(dnsAddrs, net.ParseIP(dnsAddr))
	}

	peers := []conf.Peer{}

	for _, gw := range c.c.Connection.Gateways {
		key, err := conf.NewPrivateKeyFromString(gw.Wireguard.PublicKey)
		if err != nil {
			return nil, err
		}

		allowedIPs := []netip.Prefix{}
		for _, svcCIDR := range gw.CIDRs {

			netaddr, err := netip.ParsePrefix(svcCIDR)
			if err != nil {
				return nil, err
			}

			if netaddr.Addr().Is4() && c.ipv4Supported {
				allowedIPs = append(allowedIPs, netaddr)
			} else if netaddr.Addr().Is6() && c.ipv6Supported {
				allowedIPs = append(allowedIPs, netaddr)
			}
		}

		peers = append(peers, conf.Peer{
			PublicKey:  *key,
			AllowedIPs: allowedIPs,
			Endpoint: conf.Endpoint{
				Host: gw.Addresses[0],
				Port: uint16(gw.Wireguard.Port),
			},
		})
	}

	var netDNSAddrs []netip.Addr

	for _, addr := range dnsAddrs {
		netDNSAddrs = append(netDNSAddrs, netip.MustParseAddr(addr.String()))
	}

	return &conf.Config{
		Name: c.c.Preferences.DeviceName,
		Interface: conf.Interface{
			PrivateKey: *pk,
			Addresses:  addrs,
			DNS:        netDNSAddrs,
			DNSSearch:  []string{c.c.Info.Cluster.Domain},
		},
		Peers: peers,
	}, nil
}

func (c *Controller) setWGDev() error {
	if c.isNetstack {
		return c.dev.IpcSet(c.toUAPI())
	}

	conf, err := c.getWgConf()
	if err != nil {
		return err
	}

	return c.opts.adapter.SetConfiguration(conf.ToDriverConfiguration())
}
