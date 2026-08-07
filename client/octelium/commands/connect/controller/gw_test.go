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
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newTestGatewayCtl(gws []*userv1.Gateway) *Controller {
	k, _ := wgtypes.GeneratePrivateKey()

	return &Controller{
		wgPrivateKey:  k,
		ipv4Supported: true,
		ipv6Supported: true,
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Gateways: gws,
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				KeepAliveSeconds: 25,
			},
		},
	}
}

func TestToUAPISkipsGatewaysWithoutWireGuard(t *testing.T) {
	k, _ := wgtypes.GeneratePrivateKey()
	pubKey := k.PublicKey().String()

	c := newTestGatewayCtl([]*userv1.Gateway{
		nil,
		{
			Id:        "no-wireguard",
			Addresses: []string{"1.2.3.4"},
			CIDRs:     []string{"10.0.0.0/8"},
			Quicv0:    &userv1.Gateway_QUICV0{Port: 8443},
		},
		{
			Id:        "no-addresses",
			CIDRs:     []string{"10.0.0.0/8"},
			Wireguard: &userv1.Gateway_WireGuard{Port: 5432, PublicKey: pubKey},
		},
		{
			Id:        "ok",
			Addresses: []string{"5.6.7.8"},
			CIDRs:     []string{"10.0.0.0/8"},
			Wireguard: &userv1.Gateway_WireGuard{Port: 5432, PublicKey: pubKey},
		},
	})

	uapi := c.toUAPI()

	assert.Equal(t, 1, strings.Count(uapi, "public_key="))
	assert.Equal(t, 1, strings.Count(uapi, "endpoint="))
	assert.True(t, strings.Contains(uapi, "endpoint=5.6.7.8:5432"))
}

func TestGatewayEventsWithoutDevice(t *testing.T) {
	ctx := context.Background()

	c := newTestGatewayCtl(nil)
	c.isNetstack = true

	assert.NotNil(t, c.AddGateway(ctx, nil))
	assert.NotNil(t, c.UpdateGateway(ctx, nil))

	assert.NotNil(t, c.AddGateway(ctx, &userv1.Gateway{
		Id:        "gw-1",
		Addresses: []string{"1.2.3.4"},
		Wireguard: &userv1.Gateway_WireGuard{Port: 5432},
	}))

	assert.NotNil(t, c.DeleteGateway(ctx, "gw-1"))
}

func TestGatewayEventsWithoutQUICEngine(t *testing.T) {
	ctx := context.Background()

	c := newTestGatewayCtl(nil)
	c.isQUIC = true

	assert.NotNil(t, c.AddGateway(ctx, &userv1.Gateway{
		Id:     "gw-1",
		Quicv0: &userv1.Gateway_QUICV0{Port: 8443},
	}))

	assert.Nil(t, c.DeleteGateway(ctx, "gw-1"))
}

func TestGetGWFromPktEmpty(t *testing.T) {
	e := &quicEngine{
		quicGWMap: quicGWMap{
			gwMap: make(map[string]*quicGW),
		},
	}

	assert.Nil(t, e.getGWFromPkt(nil))
	assert.Nil(t, e.getGWFromPkt([]byte{}))
}

func TestGetClusterDNSServersWithoutDNS(t *testing.T) {
	c := newTestGatewayCtl(nil)

	assert.Nil(t, c.getClusterDNSServers())
}
