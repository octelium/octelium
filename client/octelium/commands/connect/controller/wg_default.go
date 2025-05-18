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

//go:build !windows
// +build !windows

package controller

import (
	"net"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/userv1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (c *Controller) setWGDev() error {

	if c.isNetstack {
		return c.dev.IpcSet(c.toUAPI())
	}

	peers := []wgtypes.PeerConfig{}

	for _, gw := range c.c.Connection.Gateways {

		allowedIPs, err := c.getWGPeerAllowedIPs(gw)
		if err != nil {
			return err
		}

		gwPubK, err := wgtypes.ParseKey(gw.Wireguard.PublicKey)
		if err != nil {
			return err
		}

		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:         gwPubK,
			AllowedIPs:        allowedIPs,
			ReplaceAllowedIPs: true,
			Endpoint: &net.UDPAddr{
				IP:   net.ParseIP(gw.Addresses[0]),
				Port: int(gw.Wireguard.Port),
			},

			PersistentKeepaliveInterval: func() *time.Duration {
				if c.c.Preferences.KeepAliveSeconds == 0 {
					return nil
				}

				ret := time.Duration(c.c.Preferences.KeepAliveSeconds) * time.Second
				return &ret
			}(),
		})
	}

	wgCfg := wgtypes.Config{
		PrivateKey:   &c.wgPrivateKey,
		ReplacePeers: true,
		Peers:        peers,
	}

	if err := c.wgC.ConfigureDevice(c.c.Preferences.DeviceName, wgCfg); err != nil {
		return err
	}

	return nil
}

func (c *Controller) getWGPeerAllowedIPs(gw *userv1.Gateway) ([]net.IPNet, error) {
	allowedIPs := []net.IPNet{}

	for _, cidrStr := range gw.CIDRs {
		mip, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, err
		}
		if govalidator.IsIPv4(mip.String()) && c.ipv4Supported {
			allowedIPs = append(allowedIPs, *cidr)
		}

		if govalidator.IsIPv6(mip.String()) && c.ipv6Supported {
			allowedIPs = append(allowedIPs, *cidr)
		}

	}

	return allowedIPs, nil
}
