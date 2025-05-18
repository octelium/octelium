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
	"context"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (c *Controller) InitDev(ctx context.Context) error {

	zap.S().Debugf("initializing dev")
	if err := c.doInitDev(ctx); err != nil {
		return err
	}

	zap.S().Debugf("setting dev up")
	if err := c.setDevUp(); err != nil {
		return err
	}

	zap.S().Debugf("setting dev addresses")
	if err := c.SetDevAddrs(); err != nil {
		return err
	}

	zap.S().Debugf("setting routes")
	if err := c.setRoutes(); err != nil {
		return err
	}

	switch c.c.Preferences.ConnectionType {
	case cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0:
	default:
		zap.S().Debugf("initializing dev wg config")
		if err := c.setWGDev(); err != nil {
			return errors.Errorf("Could not set wg dev: %+v", err)
		}
	}

	return nil
}
