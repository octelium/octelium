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

	"github.com/octelium/octelium/apis/main/userv1"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (c *Controller) SetGatewayWGPeer(gw *userv1.Gateway) error {
	zap.S().Debugf("setting wg config for gw %s", gw.Id)
	allowedIPs, err := c.getWGPeerAllowedIPs(gw)
	if err != nil {
		return err
	}

	zap.S().Debugf("allowed IPs for gw %s are %+q", gw.Id, allowedIPs)

	gwPubK, err := wgtypes.ParseKey(gw.Wireguard.PublicKey)
	if err != nil {
		return err
	}

	peerCfg := wgtypes.PeerConfig{
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
	}

	wgCfg := wgtypes.Config{
		PrivateKey:   &c.wgPrivateKey,
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			peerCfg,
		},
	}

	if err := c.wgC.ConfigureDevice(c.c.Preferences.DeviceName, wgCfg); err != nil {
		return err
	}
	zap.S().Debugf("success setting wg config for gw %s", gw.Id)
	return nil
}

func (c *Controller) UnsetGatewayWGPeer(gw *userv1.Gateway) error {

	gwPubK, err := wgtypes.ParseKey(gw.Wireguard.PublicKey)
	if err != nil {
		return err
	}

	wgCfg := wgtypes.Config{
		PrivateKey:   &c.wgPrivateKey,
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: gwPubK,
				Remove:    true,
			},
		},
	}

	if err := c.wgC.ConfigureDevice(c.c.Preferences.DeviceName, wgCfg); err != nil {
		return err
	}

	return nil
}
