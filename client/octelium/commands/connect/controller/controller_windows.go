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

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/elevate"
)

func (c *Controller) doClose() {
	if c.wgC != nil {
		c.wgC.Close()
	}

	if c.dev != nil {
		c.dev.Close()
	}

	if c.uapi != nil {
		c.uapi.Close()
	}

	if c.tundev != nil {
		if err := c.tundev.Close(); err != nil {
			zap.L().Debug("Could not close the TUN device", zap.Error(err))
		}
		c.tundev = nil
	}
}

func (c *Controller) pre() error {

	var processToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken)
	if err != nil {
		return errors.Errorf("Unable to open current process token: %v", err)
	}
	defer processToken.Close()
	if !elevate.TokenIsElevatedOrElevatable(processToken) {
		return errors.Errorf("WireGuard may only be used by users who are a member of the Builtin %s group.", elevate.AdminGroupName())
	}

	return nil
}

func (c *Controller) doStart(ctx context.Context) error {
	if err := c.SetPrefs(); err != nil {
		return err
	}

	if err := c.pre(); err != nil {
		return err
	}

	if err := c.doInitDev(ctx); err != nil {
		return errors.Errorf("Could not init dev: %+v", err)
	}

	switch c.c.Preferences.ConnectionType {
	case cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0:
	default:
		zap.S().Debugf("initializing dev wg config")
		if err := c.setWGDev(); err != nil {
			return errors.Errorf("Could not set wg dev: %+v", err)
		}
	}

	if err := c.setDNS(); err != nil {
		return err
	}

	return nil

}

func (c *Controller) doDisconnect() error {
	var retErr error

	if err := c.unsetRoutes(); err != nil {
		zap.L().Debug("Could not unset routes", zap.Error(err))
	}

	if err := c.unsetDNS(); err != nil {
		zap.L().Warn("Could not unset DNS", zap.Error(err))
		retErr = err
	}

	if err := c.DeleteDev(); err != nil {
		zap.L().Warn("Could not delete dev", zap.Error(err))
		retErr = err
	}

	return retErr
}

type platformOpts struct {
	ifaceWatcher *interfaceWatcher
	adapter      *driver.Adapter
}
