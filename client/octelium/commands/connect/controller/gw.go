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

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (c *Controller) AddGateway(ctx context.Context, gw *userv1.Gateway) error {
	if gw == nil {
		return errors.Errorf("Cannot add a nil Gateway")
	}

	c.c.Connection.Gateways = append(c.c.Connection.Gateways, gw)

	if c.isQUIC {
		if c.quicEngine == nil {
			return errors.Errorf("The QUIC engine is not initialized")
		}
		return c.quicEngine.addGW(ctx, gw)
	}

	if c.isNetstack {
		if c.dev == nil {
			return errors.Errorf("The WireGuard device is not initialized")
		}
		if err := c.dev.IpcSet(c.toUAPI()); err != nil {
			return err
		}

	} else {
		if err := c.SetGatewayWGPeer(gw); err != nil {
			return err
		}
	}

	return nil
}

func (c *Controller) UpdateGateway(ctx context.Context, gw *userv1.Gateway) error {
	if gw == nil {
		return errors.Errorf("Cannot update a nil Gateway")
	}

	if c.isQUIC {
		return nil
	}

	for i, cur := range c.c.Connection.Gateways {
		if cur.Id == gw.Id {
			c.c.Connection.Gateways[i] = gw

			if c.isNetstack {
				if c.dev == nil {
					return errors.Errorf("The WireGuard device is not initialized")
				}
				if err := c.dev.IpcSet(c.toUAPI()); err != nil {
					return err
				}
			} else {
				if err := c.UnsetGatewayWGPeer(cur); err != nil {
					return err
				}

				if err := c.SetGatewayWGPeer(gw); err != nil {
					return err
				}
			}

			return nil
		}
	}

	return errors.Errorf("Could not find gw %s to update", gw.Id)
}

func (c *Controller) DeleteGateway(ctx context.Context, gwID string) error {

	if c.isQUIC {
		if c.quicEngine == nil {
			return nil
		}
		return c.quicEngine.deleteGWByID(gwID)
	}

	for i, gw := range c.c.Connection.Gateways {
		if gw.Id == gwID {

			c.c.Connection.Gateways = append(c.c.Connection.Gateways[:i], c.c.Connection.Gateways[i+1:]...)

			zap.L().Debug("Removing gw", zap.Any("gw", gw))

			if c.isNetstack {
				if c.dev == nil {
					return errors.Errorf("The WireGuard device is not initialized")
				}
				if err := c.dev.IpcSet(c.toUAPI()); err != nil {
					return err
				}
			} else {
				if err := c.UnsetGatewayWGPeer(gw); err != nil {
					return err
				}
			}

			return nil

		}
	}

	return nil
}
