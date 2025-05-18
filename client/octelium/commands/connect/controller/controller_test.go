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
	"runtime"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func genConnectionConfig(t *testing.T, domain string) *cliconfigv1.Connection {

	k, _ := wgtypes.GeneratePrivateKey()

	connCfg := &cliconfigv1.Connection{
		Connection: &userv1.ConnectionState{
			X25519Key: k[:],
			Cidr: &metav1.DualStackNetwork{
				V4: "100.64.0.0/16",
				V6: "fdee:be1d::/96",
			},
			Addresses: []*metav1.DualStackNetwork{
				{
					V4: "100.64.1.2/32",
					V6: "fdee:be1d::3/128",
				},
			},
			Gateways: []*userv1.Gateway{},
			Dns: &userv1.DNS{
				Servers: []string{"8.8.8.8"},
			},
		},
		Info: &cliconfigv1.Connection_Info{
			Cluster: &cliconfigv1.Connection_Info_Cluster{
				Domain: domain,
			},
		},

		Preferences: &cliconfigv1.Connection_Preferences{
			DeviceName: fmt.Sprintf("octelium-%s", utilrand.GetRandomStringLowercase(6)),

			IgnoreDNS:        false,
			KeepAliveSeconds: 25,
			Mtu:              1280,

			L3Mode:   cliconfigv1.Connection_Preferences_BOTH,
			LocalDNS: &cliconfigv1.Connection_Preferences_LocalDNS{},

			/*
				ServeOpts: &cliconfigv1.Connection_Preferences_ServeOpts{
					IsEnabled: true,
					ProxyMode: cliconfigv1.Connection_Preferences_ServeOpts_USERSPACE,
				},
			*/
		},
	}

	switch runtime.GOOS {
	case "linux":
		connCfg.Preferences.LinuxPrefs = &cliconfigv1.Connection_Preferences_Linux{}
	case "windows":
		connCfg.Preferences.WindowsPrefs = &cliconfigv1.Connection_Preferences_Windows{}
	case "darwin":
		connCfg.Preferences.MacosPrefs = &cliconfigv1.Connection_Preferences_MacOS{}
		connCfg.Preferences.DeviceName = "utun"
	}

	connCfg.Preferences.LinuxPrefs.ImplementationMode = cliconfigv1.Connection_Preferences_Linux_WG_NETSTACK
	connCfg.Preferences.LinuxPrefs.EnforceImplementationMode = true

	return connCfg
}

func TestController(t *testing.T) {
	ctx := context.Background()

	{

		connCfg := genConnectionConfig(t, "example.com")

		c, err := NewController(connCfg)
		assert.Nil(t, err, "%+v", err)

		err = c.Start(context.Background())
		assert.Nil(t, err, "%+v", err)

		ipc, err := c.dev.IpcGet()
		assert.Nil(t, err, "%+v", err)

		zap.S().Debugf("ipc: %s", ipc)

		{
			k, _ := wgtypes.GeneratePrivateKey()

			gw := &userv1.Gateway{
				Id:        utilrand.GetRandomStringLowercase(6),
				Addresses: []string{"1.2.3.4"},

				CIDRs: []string{"1.2.3.4/32"},

				Wireguard: &userv1.Gateway_WireGuard{
					Port:      5432,
					PublicKey: k.PublicKey().String(),
				},
			}

			err := c.AddGateway(ctx, gw)
			assert.Nil(t, err)

			uapiCfg, err := c.dev.IpcGet()
			assert.Nil(t, err)
			cfg := fromUAPI(uapiCfg)

			assert.Equal(t, 1, len(cfg.Peers))
			assert.Equal(t, gw.Wireguard.PublicKey, cfg.Peers[0].PublicKey.String())

			k, _ = wgtypes.GeneratePrivateKey()

			gw.Wireguard.PublicKey = k.PublicKey().String()
			err = c.UpdateGateway(ctx, gw)
			assert.Nil(t, err)

			uapiCfg, err = c.dev.IpcGet()
			assert.Nil(t, err)
			cfg = fromUAPI(uapiCfg)

			assert.Equal(t, 1, len(cfg.Peers))
			assert.Equal(t, gw.Wireguard.PublicKey, cfg.Peers[0].PublicKey.String())

			assert.Nil(t, err)

			err = c.DeleteGateway(ctx, gw.Id)
			assert.Nil(t, err)

			uapiCfg, err = c.dev.IpcGet()
			assert.Nil(t, err)
			cfg = fromUAPI(uapiCfg)

			assert.Equal(t, 0, len(cfg.Peers))
		}

		for i := 0; i < 10; i++ {
			k, _ := wgtypes.GeneratePrivateKey()

			gw := &userv1.Gateway{
				Id:        utilrand.GetRandomStringLowercase(6),
				Addresses: []string{fmt.Sprintf("%d.2.3.4", i)},
				CIDRs:     []string{fmt.Sprintf("%d.2.3.4/32", i)},

				Wireguard: &userv1.Gateway_WireGuard{
					Port:      5432,
					PublicKey: k.PublicKey().String(),
				},
			}

			err := c.AddGateway(ctx, gw)
			assert.Nil(t, err)

			uapiCfg, err := c.dev.IpcGet()
			assert.Nil(t, err)
			cfg := fromUAPI(uapiCfg)

			assert.Equal(t, i+1, len(cfg.Peers))

			k, _ = wgtypes.GeneratePrivateKey()

			gw.Wireguard.PublicKey = k.PublicKey().String()
			err = c.UpdateGateway(ctx, gw)
			assert.Nil(t, err)
			assert.Equal(t, i+1, len(cfg.Peers))
		}

		err = c.Close()
		assert.Nil(t, err)
	}
}
