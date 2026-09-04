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
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octelium/commands/connect/controller/esshmain"
	"github.com/octelium/octelium/client/octelium/commands/connect/dnssrv"
	"github.com/octelium/octelium/client/octelium/commands/connect/esocks5"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Controller struct {
	c             *cliconfigv1.Connection
	ipv4Supported bool
	ipv6Supported bool
	wgC           *wgctrl.Client
	wgPrivateKey  wgtypes.Key

	dev    *device.Device
	uapi   net.Listener
	tundev tun.Device

	mu sync.Mutex

	opts platformOpts

	dnsServers struct {
		sync.Mutex
		servers []net.IP
	}

	clusterDNSServers struct {
		sync.Mutex
		servers []string
	}

	isNetstack bool
	isQUIC     bool
	nsTun      *netTun

	dnsConfigSaved bool
	resolvConf     resolvConfState
	svcProxy       *serviceProxy

	isClosed bool

	quicEngine   *quicEngine
	eSSHHMainSrv *esshmain.ESSHMain
	esocks5Srv   *esocks5.Server
	localDNSSrv  *dnssrv.Server
}

func NewController(c *cliconfigv1.Connection) (*Controller, error) {

	ipv4Supported := c.Connection.L3Mode == userv1.ConnectionState_V4 ||
		c.Connection.L3Mode == userv1.ConnectionState_BOTH
	ipv6Supported := c.Connection.L3Mode == userv1.ConnectionState_V6 ||
		c.Connection.L3Mode == userv1.ConnectionState_BOTH

	ret := &Controller{
		c:             c,
		ipv4Supported: ipv4Supported,
		ipv6Supported: ipv6Supported,
		isQUIC:        c.Preferences.ConnectionType == cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0,
	}

	switch {
	case cliutils.IsLinux(), cliutils.IsWindows(), cliutils.IsDarwin():
	default:
		return nil, errors.Errorf("Could not initialize controller, invalid runtime OS")
	}

	if wgClient, err := wgctrl.New(); err != nil {
		zap.L().Debug(
			"Could not create the WireGuard control client. Kernel WireGuard will be unavailable",
			zap.Error(err))
	} else {
		ret.wgC = wgClient
	}

	privK, err := wgtypes.NewKey(c.Connection.X25519Key)
	if err != nil {
		if ret.wgC != nil {
			ret.wgC.Close()
		}
		return nil, err
	}

	ret.wgPrivateKey = privK

	return ret, nil
}

func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return nil
	}
	zap.L().Debug("Closing dev controller")

	c.isClosed = true
	if c.svcProxy != nil {
		if err := c.svcProxy.Close(); err != nil {
			zap.L().Debug("Could not close svcProxy", zap.Error(err))
		}
	}

	if err := c.doDisconnect(); err != nil {
		zap.L().Debug("Could not doDisconnect", zap.Error(err))
	}

	c.doClose()

	if c.nsTun != nil {
		if err := c.nsTun.Close(); err != nil {
			zap.L().Debug("Could not close the netstack TUN", zap.Error(err))
		}
	}

	if c.eSSHHMainSrv != nil {
		if err := c.eSSHHMainSrv.Close(); err != nil {
			zap.L().Warn("Could not close main eSSH server", zap.Error(err))
		}
	}

	if c.esocks5Srv != nil {
		if err := c.esocks5Srv.Close(); err != nil {
			zap.L().Warn("Could not close embedded SOCKS5 server", zap.Error(err))
		}
	}

	if c.localDNSSrv != nil {
		if err := c.localDNSSrv.Close(); err != nil {
			zap.L().Warn("Could not close local DNS server", zap.Error(err))
		}
	}

	if err := c.unsetServiceConfigs(); err != nil {
		zap.L().Debug("Could not unset Service configs", zap.Error(err))
	}

	zap.L().Debug("Closed dev controller")
	return nil
}

func (c *Controller) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The controller is already closed")
	}

	zap.L().Debug("Starting controller...")

	if err := c.setServiceConfigs(); err != nil {
		return err
	}

	c.startLocalDNSServer()

	if err := c.doStart(ctx); err != nil {
		return err
	}

	svcProxy, err := newServiceProxy(c)
	if err != nil {
		return err
	}
	c.svcProxy = svcProxy
	if err := svcProxy.Start(ctx); err != nil {
		return err
	}

	if c.c.Preferences.ESSH != nil && c.c.Preferences.ESSH.IsEnabled {
		zap.L().Debug("Creating eSSH main server")
		c.eSSHHMainSrv, err = esshmain.New(c.c, c, c.ipv4Supported, c.ipv6Supported)
		if err != nil {
			zap.L().Warn("Could not create a new eSSH server", zap.Error(err))
		} else {
			zap.L().Debug("Running eSSH main server")
			if err := c.eSSHHMainSrv.Run(ctx); err != nil {
				zap.L().Warn("Could not run the eSSH server", zap.Error(err))
			}
		}
	}

	if c.c.Preferences != nil &&
		c.c.Preferences.ESOCKS5 != nil &&
		c.c.Preferences.ESOCKS5.IsEnabled {

		c.esocks5Srv, err = esocks5.NewServer(&esocks5.Opts{
			ListenAddrs: getESOCKS5ListenAddrs(c.c),
			GoNetCtl:    c,
		})
		if err != nil {
			zap.L().Warn("Could not create a new embedded SOCKS5 server", zap.Error(err))
		} else {
			if err := c.esocks5Srv.Start(ctx); err != nil {
				zap.L().Warn("Could not run the embedded SOCKS5 server", zap.Error(err))
			}
		}
	}

	return nil
}

func (c *Controller) startLocalDNSServer() {
	if c.c.Preferences.LocalDNS == nil || !c.c.Preferences.LocalDNS.IsEnabled {
		return
	}

	disable := func(err error) {
		zap.L().Warn("Could not start the local DNS server. Falling back to the Cluster DNS servers",
			zap.Error(err))
		c.c.Preferences.LocalDNS.IsEnabled = false
		c.localDNSSrv = nil
	}

	localDNSServer, err := dnssrv.NewDNSServer(&dnssrv.Opts{
		ClusterDomain: c.c.Info.Cluster.Domain,
		HasV4:         c.ipv4Supported,
		HasV6:         c.ipv6Supported,
		DNSGetter:     c,
		ListenAddr:    c.getLocalDNSServerAddr(),
		IsFullDNS:     c.isFullDNS(),
	})
	if err != nil {
		disable(err)
		return
	}

	c.localDNSSrv = localDNSServer

	if err := c.localDNSSrv.Run(); err != nil {
		if err := localDNSServer.Close(); err != nil {
			zap.L().Debug("Could not close the local DNS server", zap.Error(err))
		}
		disable(err)
	}
}

func (c *Controller) Reconfigure() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The controller is already closed")
	}

	return c.reconfigure()
}

func (c *Controller) reconfigure() error {

	if err := c.setWGDev(); err != nil {
		return err
	}

	if err := c.SetDevAddrs(); err != nil {
		return err
	}

	if err := c.setRoutes(); err != nil {
		return err
	}

	if err := c.setDNS(); err != nil {
		return err
	}

	return nil
}

func (c *Controller) SetConnectionState(state *userv1.ConnectionState) error {
	if state == nil {
		return errors.Errorf("Cannot set a nil Connection state")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The controller is already closed")
	}

	old := c.c.Connection

	if err := c.unsetRoutes(); err != nil {
		zap.L().Debug("Could not unset the current routes", zap.Error(err))
	}

	c.c.Connection = state

	if err := c.reconfigure(); err != nil {
		zap.L().Warn("Could not apply the new Connection state. Rolling back", zap.Error(err))
		c.c.Connection = old
		return err
	}

	return nil
}

func (c *Controller) UpdateDNS(dns *userv1.DNS) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The controller is already closed")
	}

	c.c.Connection.Dns = dns

	return c.setDNS()
}

func (c *Controller) UpdatePrivateKey(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The controller is already closed")
	}

	if c.isQUIC {
		return nil
	}

	privK, err := wgtypes.ParseKey(key)
	if err != nil {
		return err
	}

	c.wgPrivateKey = privK

	return c.setWGDev()
}

func (c *Controller) getMTU() int {
	if c.c.Preferences.Mtu != 0 {
		return int(c.c.Preferences.Mtu)
	}
	if c.c.Connection.Mtu != 0 {
		return int(c.c.Connection.Mtu)
	}

	return 1280
}

func getESOCKS5ListenAddrs(connCfg *cliconfigv1.Connection) []string {
	if connCfg == nil ||
		connCfg.Connection == nil ||
		connCfg.Preferences == nil ||
		connCfg.Preferences.ESOCKS5 == nil {
		return nil
	}

	portStr := strconv.Itoa(int(connCfg.Preferences.ESOCKS5.Port))
	if portStr == "0" {
		portStr = strconv.Itoa(1080)
	}

	if len(connCfg.Preferences.ESOCKS5.ListenIPAddresses) > 0 {
		var ret []string
		for _, addr := range connCfg.Preferences.ESOCKS5.ListenIPAddresses {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				ret = append(ret, net.JoinHostPort(addr, portStr))
			}
		}
		return ret
	}

	ipv4Supported := connCfg.Preferences.L3Mode != cliconfigv1.Connection_Preferences_V6
	ipv6Supported := connCfg.Preferences.L3Mode != cliconfigv1.Connection_Preferences_V4

	var ret []string
	for _, addr := range connCfg.Connection.Addresses {
		if addr.V4 != "" && ipv4Supported {
			ret = append(ret,
				net.JoinHostPort(umetav1.ToDualStackNetwork(addr).ToIP().Ipv4, portStr))
		}
		if addr.V6 != "" && ipv6Supported {
			ret = append(ret,
				net.JoinHostPort(umetav1.ToDualStackNetwork(addr).ToIP().Ipv6, portStr))
		}
	}

	return ret
}
