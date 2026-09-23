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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeTUN struct {
	closeOnce sync.Once
	closedCh  chan struct{}
	events    chan tun.Event
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{
		closedCh: make(chan struct{}),
		events:   make(chan tun.Event, 1),
	}
}

func (t *fakeTUN) File() *os.File {
	return nil
}

func (t *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-t.closedCh
	return 0, os.ErrClosed
}

func (t *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closedCh:
		return 0, os.ErrClosed
	default:
		return len(bufs), nil
	}
}

func (t *fakeTUN) MTU() (int, error) {
	return 1280, nil
}

func (t *fakeTUN) Name() (string, error) {
	return "faketun0", nil
}

func (t *fakeTUN) Events() <-chan tun.Event {
	return t.events
}

func (t *fakeTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.closedCh)
		close(t.events)
	})
	return nil
}

func (t *fakeTUN) BatchSize() int {
	return 1
}

func (t *fakeTUN) isClosed() bool {
	select {
	case <-t.closedCh:
		return true
	default:
		return false
	}
}

type fakePlatform struct {
	mu        sync.Mutex
	openErr   error
	setErr    error
	tuns      []*fakeTUN
	openCfgs  []*mobilev1.TunnelConfiguration
	setCfgs   []*mobilev1.TunnelConfiguration
	networkCh chan struct{}
}

func newFakePlatform() *fakePlatform {
	return &fakePlatform{
		networkCh: make(chan struct{}, 1),
	}
}

func (p *fakePlatform) OpenTUN(ctx context.Context, cfg *mobilev1.TunnelConfiguration) (tun.Device, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.openCfgs = append(p.openCfgs, pbutils.Clone(cfg).(*mobilev1.TunnelConfiguration))
	if p.openErr != nil {
		return nil, p.openErr
	}

	ret := newFakeTUN()
	p.tuns = append(p.tuns, ret)
	return ret, nil
}

func (p *fakePlatform) SetTunnelConfiguration(ctx context.Context, cfg *mobilev1.TunnelConfiguration) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.setCfgs = append(p.setCfgs, pbutils.Clone(cfg).(*mobilev1.TunnelConfiguration))
	return p.setErr
}

func (p *fakePlatform) WatchNetwork(ctx context.Context) <-chan struct{} {
	return p.networkCh
}

func (p *fakePlatform) getSetCfgs() []*mobilev1.TunnelConfiguration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.setCfgs
}

func genPlatformConnectionConfig(t *testing.T, domain string) *cliconfigv1.Connection {
	k, err := wgtypes.GeneratePrivateKey()
	assert.Nil(t, err)

	return &cliconfigv1.Connection{
		Connection: &userv1.ConnectionState{
			X25519Key: k[:],
			L3Mode:    userv1.ConnectionState_BOTH,
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
			Dns: &userv1.DNS{
				Servers: []string{"100.64.0.53", "fdee:be1d::53"},
			},
		},
		Info: &cliconfigv1.Connection_Info{
			Cluster: &cliconfigv1.Connection_Info_Cluster{
				Domain: domain,
			},
		},
		Preferences: &cliconfigv1.Connection_Preferences{
			DeviceName:       "octelium-mobile",
			KeepAliveSeconds: 25,
			L3Mode:           cliconfigv1.Connection_Preferences_BOTH,
			LocalDNS:         &cliconfigv1.Connection_Preferences_LocalDNS{},
			ServeOpts:        &cliconfigv1.Connection_Preferences_ServeOpts{},
		},
	}
}

func TestGetTunnelConfiguration(t *testing.T) {

	{
		connCfg := genPlatformConnectionConfig(t, "example.com")
		c, err := NewControllerWithOpts(connCfg, &Opts{Platform: newFakePlatform()})
		assert.Nil(t, err)

		cfg, err := c.getTunnelConfiguration()
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(&mobilev1.TunnelConfiguration{
			Addresses: []string{"100.64.1.2/32", "fdee:be1d::3/128"},
			Routes:    []string{"100.64.0.0/16", "fdee:be1d::/96"},
			Mtu:       1280,
			Dns: &mobilev1.TunnelConfiguration_DNS{
				Servers:       []string{"100.64.0.53", "fdee:be1d::53"},
				SearchDomains: []string{"local.example.com"},
				MatchDomains:  []string{"local.example.com"},
			},
		}, cfg), "%+v", cfg)
	}

	{
		connCfg := genPlatformConnectionConfig(t, "example.com")
		connCfg.Connection.L3Mode = userv1.ConnectionState_V6
		connCfg.Connection.Mtu = 1400
		c, err := NewControllerWithOpts(connCfg, &Opts{Platform: newFakePlatform()})
		assert.Nil(t, err)

		cfg, err := c.getTunnelConfiguration()
		assert.Nil(t, err)
		assert.Equal(t, []string{"fdee:be1d::3/128"}, cfg.Addresses)
		assert.Equal(t, []string{"fdee:be1d::/96"}, cfg.Routes)
		assert.Equal(t, []string{"fdee:be1d::53"}, cfg.Dns.Servers)
		assert.Equal(t, int32(1400), cfg.Mtu)
	}

	{
		connCfg := genPlatformConnectionConfig(t, "example.com")
		connCfg.Connection.L3Mode = userv1.ConnectionState_V4
		connCfg.Preferences.Mtu = 1300
		c, err := NewControllerWithOpts(connCfg, &Opts{Platform: newFakePlatform()})
		assert.Nil(t, err)

		cfg, err := c.getTunnelConfiguration()
		assert.Nil(t, err)
		assert.Equal(t, []string{"100.64.1.2/32"}, cfg.Addresses)
		assert.Equal(t, []string{"100.64.0.0/16"}, cfg.Routes)
		assert.Equal(t, []string{"100.64.0.53"}, cfg.Dns.Servers)
		assert.Equal(t, int32(1300), cfg.Mtu)
	}

	{
		connCfg := genPlatformConnectionConfig(t, "example.com")
		connCfg.Preferences.FullDNS = true
		c, err := NewControllerWithOpts(connCfg, &Opts{Platform: newFakePlatform()})
		assert.Nil(t, err)

		cfg, err := c.getTunnelConfiguration()
		assert.Nil(t, err)
		assert.True(t, cfg.Dns.MatchAllDomains)
		assert.Equal(t, 0, len(cfg.Dns.MatchDomains))
		assert.Equal(t, []string{"local.example.com"}, cfg.Dns.SearchDomains)
	}

	{
		connCfg := genPlatformConnectionConfig(t, "example.com")
		connCfg.Preferences.IgnoreDNS = true
		c, err := NewControllerWithOpts(connCfg, &Opts{Platform: newFakePlatform()})
		assert.Nil(t, err)

		cfg, err := c.getTunnelConfiguration()
		assert.Nil(t, err)
		assert.Nil(t, cfg.Dns)
		assert.Equal(t, 2, len(cfg.Routes))
	}

	{
		connCfg := genPlatformConnectionConfig(t, "example.com")
		connCfg.Connection.Dns = nil
		c, err := NewControllerWithOpts(connCfg, &Opts{Platform: newFakePlatform()})
		assert.Nil(t, err)

		cfg, err := c.getTunnelConfiguration()
		assert.Nil(t, err)
		assert.Nil(t, cfg.Dns)
	}

	{
		connCfg := genPlatformConnectionConfig(t, "example.com")
		connCfg.Connection.Cidr = nil
		c, err := NewControllerWithOpts(connCfg, &Opts{Platform: newFakePlatform()})
		assert.Nil(t, err)

		cfg, err := c.getTunnelConfiguration()
		assert.Nil(t, err)
		assert.Equal(t, 0, len(cfg.Routes))
	}

	invalidFns := []func(c *cliconfigv1.Connection){
		func(c *cliconfigv1.Connection) {
			c.Connection.Addresses = nil
		},
		func(c *cliconfigv1.Connection) {
			c.Connection.Addresses[0].V4 = "100.64.1.2"
		},
		func(c *cliconfigv1.Connection) {
			c.Connection.Addresses[0].V4 = "fdee:be1d::3/128"
		},
		func(c *cliconfigv1.Connection) {
			c.Connection.Addresses[0].V6 = "100.64.1.2/32"
		},
		func(c *cliconfigv1.Connection) {
			c.Connection.Cidr.V4 = "100.64.0.0/33"
		},
		func(c *cliconfigv1.Connection) {
			c.Connection.Cidr.V6 = "invalid"
		},
	}

	for _, fn := range invalidFns {
		connCfg := genPlatformConnectionConfig(t, "example.com")
		fn(connCfg)
		c, err := NewControllerWithOpts(connCfg, &Opts{Platform: newFakePlatform()})
		assert.Nil(t, err)

		_, err = c.getTunnelConfiguration()
		assert.NotNil(t, err)
	}
}

func TestControllerPlatform(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	platform := newFakePlatform()
	connCfg := genPlatformConnectionConfig(t, "example.com")

	c, err := NewControllerWithOpts(connCfg, &Opts{Platform: platform})
	assert.Nil(t, err)
	assert.Nil(t, c.wgC)
	assert.True(t, c.isUserspaceDev())

	assert.Nil(t, c.Start(ctx))

	assert.Equal(t, 1, len(platform.openCfgs))
	assert.Equal(t, 1, len(platform.tuns))
	assert.Equal(t, []string{"100.64.1.2/32", "fdee:be1d::3/128"}, platform.openCfgs[0].Addresses)
	assert.NotNil(t, c.dev)

	{
		k, err := wgtypes.GeneratePrivateKey()
		assert.Nil(t, err)

		gw := &userv1.Gateway{
			Id:        utilrand.GetRandomStringLowercase(6),
			Addresses: []string{"1.2.3.4"},
			CIDRs:     []string{"100.64.0.0/16", "fdee:be1d::/96"},
			Wireguard: &userv1.Gateway_WireGuard{
				Port:      5432,
				PublicKey: k.PublicKey().String(),
			},
		}

		assert.Nil(t, c.AddGateway(ctx, gw))

		uapiCfg, err := c.dev.IpcGet()
		assert.Nil(t, err)
		cfg := fromUAPI(uapiCfg)
		assert.Equal(t, 1, len(cfg.Peers))
		assert.Equal(t, gw.Wireguard.PublicKey, cfg.Peers[0].PublicKey.String())
		assert.Equal(t, 2, len(cfg.Peers[0].AllowedIPs))

		assert.Nil(t, c.DeleteGateway(ctx, gw.Id))

		uapiCfg, err = c.dev.IpcGet()
		assert.Nil(t, err)
		assert.Equal(t, 0, len(fromUAPI(uapiCfg).Peers))
	}

	assert.Equal(t, 0, len(platform.getSetCfgs()))

	{
		assert.Nil(t, c.UpdateDNS(&userv1.DNS{}))
		assert.Equal(t, 0, len(platform.getSetCfgs()))

		assert.Nil(t, c.UpdateDNS(&userv1.DNS{
			Servers: []string{"100.64.0.54"},
		}))

		setCfgs := platform.getSetCfgs()
		assert.Equal(t, 1, len(setCfgs))
		assert.Equal(t, []string{"100.64.0.54"}, setCfgs[0].Dns.Servers)
	}

	{
		state := pbutils.Clone(connCfg.Connection).(*userv1.ConnectionState)
		state.Addresses = []*metav1.DualStackNetwork{
			{
				V4: "100.64.1.9/32",
				V6: "fdee:be1d::9/128",
			},
		}

		assert.Nil(t, c.SetConnectionState(state))

		setCfgs := platform.getSetCfgs()
		assert.Equal(t, 2, len(setCfgs))
		assert.Equal(t, []string{"100.64.1.9/32", "fdee:be1d::9/128"}, setCfgs[1].Addresses)
	}

	{
		platform.mu.Lock()
		platform.setErr = errors.Errorf("could not apply")
		platform.mu.Unlock()

		state := pbutils.Clone(connCfg.Connection).(*userv1.ConnectionState)
		state.Addresses = []*metav1.DualStackNetwork{
			{
				V4: "100.64.1.10/32",
			},
		}

		assert.NotNil(t, c.SetConnectionState(state))
		assert.Equal(t, "100.64.1.9/32", c.c.Connection.Addresses[0].V4)

		assert.NotNil(t, c.UpdateDNS(&userv1.DNS{
			Servers: []string{"100.64.0.55"},
		}))
		assert.Equal(t, []string{"100.64.0.54"}, c.c.Connection.Dns.Servers)

		platform.mu.Lock()
		platform.setErr = nil
		platform.mu.Unlock()
	}

	{
		k, err := wgtypes.GeneratePrivateKey()
		assert.Nil(t, err)
		assert.Nil(t, c.UpdatePrivateKey(k.String()))
	}

	platform.networkCh <- struct{}{}
	c.onNetworkChanged()

	assert.Nil(t, c.Close())
	assert.True(t, platform.tuns[0].isClosed())

	assert.Nil(t, c.Close())
	assert.NotNil(t, c.AddGateway(ctx, &userv1.Gateway{}))
	assert.NotNil(t, c.UpdateDNS(&userv1.DNS{}))
	assert.NotNil(t, c.SetConnectionState(connCfg.Connection))

	c.onNetworkChanged()
}

func TestControllerPlatformQUIC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	platform := newFakePlatform()
	connCfg := genPlatformConnectionConfig(t, "example.com")
	connCfg.Preferences.ConnectionType = cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0

	c, err := NewControllerWithOpts(connCfg, &Opts{Platform: platform})
	assert.Nil(t, err)
	assert.True(t, c.isQUIC)

	assert.Nil(t, c.Start(ctx))
	assert.Nil(t, c.dev)
	assert.NotNil(t, c.quicEngine)
	assert.Equal(t, platform.tuns[0], c.getTUNDev())

	platform.networkCh <- struct{}{}

	assert.Eventually(t, func() bool {
		return len(platform.networkCh) == 0
	}, 5*time.Second, 10*time.Millisecond)

	assert.Nil(t, c.UpdateDNS(&userv1.DNS{
		Servers: []string{"100.64.0.54"},
	}))
	assert.Equal(t, 1, len(platform.getSetCfgs()))

	cancel()
	assert.Nil(t, c.Close())
	assert.True(t, platform.tuns[0].isClosed())
	assert.True(t, c.quicEngine.getIsClosed())
}

func TestControllerPlatformStartErr(t *testing.T) {
	ctx := context.Background()

	{
		platform := newFakePlatform()
		platform.openErr = errors.Errorf("could not open")

		c, err := NewControllerWithOpts(genPlatformConnectionConfig(t, "example.com"), &Opts{Platform: platform})
		assert.Nil(t, err)

		assert.NotNil(t, c.Start(ctx))
		assert.Nil(t, c.Close())
	}

	{
		platform := newFakePlatform()
		connCfg := genPlatformConnectionConfig(t, "example.com")
		connCfg.Connection.Addresses = nil

		c, err := NewControllerWithOpts(connCfg, &Opts{Platform: platform})
		assert.Nil(t, err)

		assert.NotNil(t, c.Start(ctx))
		assert.Equal(t, 0, len(platform.openCfgs))
		assert.Nil(t, c.Close())
	}

	{
		platform := newFakePlatform()
		c, err := NewControllerWithOpts(genPlatformConnectionConfig(t, "example.com"), &Opts{Platform: platform})
		assert.Nil(t, err)

		assert.NotNil(t, c.setPlatformTunnelConfiguration())
	}
}
