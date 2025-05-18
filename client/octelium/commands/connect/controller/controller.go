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
	"runtime"
	"sync"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/controller/esshmain"
	"github.com/octelium/octelium/client/octelium/commands/connect/dnssrv"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type OSType int

const (
	OSTypeLinux OSType = iota
	OSTypeWindows
	OSTypeMacOS
)

type Controller struct {
	c             *cliconfigv1.Connection
	ipv4Supported bool
	ipv6Supported bool
	OSType        OSType
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

	isNetstack bool
	isQUIC     bool
	nsTun      *netTun

	dnsConfigSaved bool
	svcProxy       *serviceProxy

	isClosed bool

	quicEngine *quicEngine
	// eSSHWSSrv    *esshws.ESSHWS
	eSSHHMainSrv *esshmain.ESSHMain

	localDNSSrv *dnssrv.Server
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

	switch runtime.GOOS {
	case "linux":
		ret.OSType = OSTypeLinux
	case "darwin":
		ret.OSType = OSTypeMacOS
	case "windows":
		ret.OSType = OSTypeWindows
		/*
			if ret.isQUIC {
				return nil, errors.Errorf("QUIC mode is not currently supported on Windows")
			}
		*/
	default:
		return nil, errors.Errorf("Could not initialize controller, invalid runtime OS")
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	ret.wgC = wgClient

	privK, err := wgtypes.NewKey(c.Connection.X25519Key)
	if err != nil {
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

	c.doClose()
	if err := c.doDisconnect(); err != nil {
		zap.L().Debug("Could not doDisconnect", zap.Error(err))
	}

	/*
		if c.eSSHWSSrv != nil {
			if err := c.eSSHWSSrv.Close(); err != nil {
				zap.L().Warn("Could not close Worskpace eSSH server", zap.Error(err))
			}
		}
	*/

	if c.eSSHHMainSrv != nil {
		if err := c.eSSHHMainSrv.Close(); err != nil {
			zap.L().Warn("Could not close main eSSH server", zap.Error(err))
		}
	}

	if c.localDNSSrv != nil {
		if err := c.localDNSSrv.Close(); err != nil {
			zap.L().Warn("Could not close local DNS server", zap.Error(err))
		}
	}

	zap.L().Debug("Closed dev controller")
	return nil
}

func (c *Controller) Start(ctx context.Context) error {
	zap.S().Debugf("Starting controller...")

	if err := c.setServiceConfigs(); err != nil {
		return err
	}

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

	if c.c.Preferences.LocalDNS.IsEnabled {
		localDNSServer, err := dnssrv.NewDNSServer(&dnssrv.Opts{
			ClusterDomain: c.c.Info.Cluster.Domain,
			HasV4:         c.ipv4Supported,
			HasV6:         c.ipv6Supported,
			DNSGetter:     c,
			ListenAddr:    c.c.Preferences.LocalDNS.ListenAddress,
			/*
				FallbackServers: c.c.Preferences.LocalDNS.FallbackServers,
				UseFallback:     c.c.Preferences.LocalDNS.UseFallback,
			*/
		})
		if err != nil {
			zap.L().Warn("Could not initialize local DNS server", zap.Error(err))
		}
		c.localDNSSrv = localDNSServer

		if err := c.localDNSSrv.Run(); err != nil {
			zap.L().Warn("Could not run local DNS server", zap.Error(err))
		}
	}

	/*
		if os.Getenv("OCTELIUM_WS_ESSH") == "true" {
			zap.L().Debug("Creating Workspace eSSH server")
			c.eSSHWSSrv, err = esshws.New(c.c, c)
			if err != nil {
				zap.L().Warn("Could not create a new Workspace eSSH server", zap.Error(err))
			} else {
				zap.L().Debug("Running Workspace eSSH server")
				if err := c.eSSHWSSrv.Run(ctx); err != nil {
					zap.L().Warn("Could not run the Workspace eSSH server", zap.Error(err))
				}
			}
		}
	*/

	if c.c.Preferences.ESSH != nil && c.c.Preferences.ESSH.IsEnabled {
		zap.L().Debug("Creating eSSH main server")
		c.eSSHHMainSrv, err = esshmain.New(c.c, c, c.ipv4Supported, c.ipv6Supported)
		if err != nil {
			zap.L().Warn("Could not create a new Workspace eSSH server", zap.Error(err))
		} else {
			zap.L().Debug("Running eSSH main server")
			if err := c.eSSHHMainSrv.Run(ctx); err != nil {
				zap.L().Warn("Could not run the Workspace eSSH server", zap.Error(err))
			}
		}
	}

	return nil
}

func (c *Controller) Reconfigure() error {

	if err := c.setWGDev(); err != nil {
		return err
	}

	if err := c.SetDevAddrs(); err != nil {
		return err
	}

	if err := c.SetDNS(); err != nil {
		return err
	}

	return nil
}

func (c *Controller) UpdatePrivateKey(key string) error {
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
