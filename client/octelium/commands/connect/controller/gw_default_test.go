//go:build !windows
// +build !windows

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
	"testing"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
)

func TestSetGatewayWGPeerRejectsGatewayWithoutWireGuard(t *testing.T) {
	c := newTestGatewayCtl(nil)

	assert.NotNil(t, c.SetGatewayWGPeer(nil))
	assert.NotNil(t, c.SetGatewayWGPeer(&userv1.Gateway{
		Id:        "no-wireguard",
		Addresses: []string{"1.2.3.4"},
	}))
	assert.NotNil(t, c.SetGatewayWGPeer(&userv1.Gateway{
		Id:        "no-addresses",
		Wireguard: &userv1.Gateway_WireGuard{Port: 5432},
	}))

	assert.Nil(t, c.UnsetGatewayWGPeer(nil))
	assert.Nil(t, c.UnsetGatewayWGPeer(&userv1.Gateway{Id: "no-wireguard"}))
}

func TestWireGuardAllowedIPsByIPMode(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			gw := &userv1.Gateway{CIDRs: []string{"100.64.9.1/16", "fd00::9/64"}}
			allowed, err := c.getWGPeerAllowedIPs(gw)
			assert.Nil(t, err)
			var want []net.IPNet
			if tt.v4 {
				_, cidr, _ := net.ParseCIDR("100.64.0.0/16")
				want = append(want, *cidr)
			}
			if tt.v6 {
				_, cidr, _ := net.ParseCIDR("fd00::/64")
				want = append(want, *cidr)
			}
			assert.Equal(t, want, allowed)
			gw.CIDRs = nil
			allowed, err = c.getWGPeerAllowedIPs(gw)
			assert.Nil(t, err)
			assert.Empty(t, allowed)
			gw.CIDRs = []string{"invalid"}
			allowed, err = c.getWGPeerAllowedIPs(gw)
			assert.NotNil(t, err)
			assert.Nil(t, allowed)
		})
	}
}
