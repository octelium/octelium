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

package connect

import (
	"context"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/controller"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type stateController struct {
	c                     *cliconfigv1.Connection
	ctl                   *controller.Controller
	proxy                 *proxy.Controller
	getConnErrCh          chan error
	apiserverDisconnectCh chan struct{}
	streamC               userv1.MainService_ConnectClient
}

func newStateController(c *cliconfigv1.Connection,
	ctl *controller.Controller,
	proxy *proxy.Controller,

	streamC userv1.MainService_ConnectClient,
) *stateController {

	return &stateController{
		c:                     c,
		ctl:                   ctl,
		proxy:                 proxy,
		getConnErrCh:          make(chan error),
		apiserverDisconnectCh: make(chan struct{}),
		streamC:               streamC,
	}
}

func (c *stateController) Start(ctx context.Context) error {
	zap.L().Debug("Starting state controller")
	go c.doStartLoop(ctx)
	return nil
}

func (c *stateController) doStartLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("State controller loop ctx done")
			return
		default:
			resp, err := c.streamC.Recv()
			if err != nil {
				zap.L().Debug("Error in receiving the stream", zap.Error(err))
				c.getConnErrCh <- err
				return
			}

			if resp == nil || resp.Event == nil {
				zap.L().Error("Invalid empty event")
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if c.isDisconnect(resp) {
				zap.L().Debug("Got disconnected msg")
				close(c.apiserverDisconnectCh)
				return
			}

			if err := c.handleState(ctx, resp); err != nil {
				zap.L().Error("Could not handle state", zap.Error(err))
			}
		}
	}
}

func (c *stateController) isDisconnect(state *userv1.ConnectResponse) bool {
	switch state.Event.(type) {
	case *userv1.ConnectResponse_Disconnect_:
		return true
	default:
		return false
	}
}

func (c *stateController) handleState(ctx context.Context, state *userv1.ConnectResponse) error {

	switch state.Event.(type) {
	case *userv1.ConnectResponse_AddGateway_:
		gw := state.Event.(*userv1.ConnectResponse_AddGateway_).AddGateway.Gateway
		zap.L().Debug("Adding Gateway", zap.Any("gw", gw))
		if err := c.ctl.AddGateway(ctx, gw); err != nil {
			return errors.Errorf("Could not add gw: %+v", err)
		}

	case *userv1.ConnectResponse_UpdateGateway_:
		gw := state.Event.(*userv1.ConnectResponse_UpdateGateway_).UpdateGateway.Gateway
		zap.L().Debug("Updating Gateway", zap.Any("gw", gw))
		if err := c.ctl.UpdateGateway(ctx, gw); err != nil {
			return errors.Errorf("Could not update gw: %+v", err)
		}

	case *userv1.ConnectResponse_DeleteGateway_:
		gwID := state.Event.(*userv1.ConnectResponse_DeleteGateway_).DeleteGateway.Id
		zap.L().Debug("Deleting Gateway", zap.String("id", gwID))
		if err := c.ctl.DeleteGateway(ctx, gwID); err != nil {
			return errors.Errorf("Could not add gw: %+v", err)
		}

	case *userv1.ConnectResponse_UpdateDNS_:
		dns := state.Event.(*userv1.ConnectResponse_UpdateDNS_).UpdateDNS.Dns
		zap.L().Debug("Updating DNS", zap.Any("dns", dns))
		c.c.Connection.Dns = dns
		if err := c.ctl.SetDNS(); err != nil {
			return errors.Errorf("Could not set DNS: %+v", err)
		}
	case *userv1.ConnectResponse_AddService_:
		svc := state.Event.(*userv1.ConnectResponse_AddService_).AddService.Service
		zap.L().Debug("Adding Service", zap.Any("svc", svc))

		if c.c.Connection.ServiceOptions == nil {
			c.c.Connection.ServiceOptions = &userv1.ConnectionState_ServiceOptions{}
		}

		if c.c.Preferences.ServeOpts.ProxyMode == cliconfigv1.Connection_Preferences_ServeOpts_NONE {
			return nil
		}

		if c.proxy != nil {
			if err := c.proxy.AddService(svc); err != nil {
				return err
			}
		}

	case *userv1.ConnectResponse_UpdateService_:
		svc := state.Event.(*userv1.ConnectResponse_UpdateService_).UpdateService.Service
		zap.L().Debug("Updating Service", zap.Any("svc", svc))

		if c.c.Connection.ServiceOptions == nil {
			c.c.Connection.ServiceOptions = &userv1.ConnectionState_ServiceOptions{}
		}

		if c.c.Preferences.ServeOpts.ProxyMode == cliconfigv1.Connection_Preferences_ServeOpts_NONE {
			return nil
		}

		if c.proxy != nil {
			if err := c.proxy.UpdateService(svc); err != nil {
				return err
			}
		}

	case *userv1.ConnectResponse_DeleteService_:
		svcName := state.Event.(*userv1.ConnectResponse_DeleteService_).DeleteService.Name

		zap.L().Debug("Deleting Service", zap.String("svc", svcName))

		if c.c.Connection.ServiceOptions == nil {
			return errors.Errorf("Could not delete svc: %s. Service options is nil", svcName)
		}

		if c.c.Preferences.ServeOpts.ProxyMode == cliconfigv1.Connection_Preferences_ServeOpts_NONE {
			return nil
		}

		if c.proxy != nil {
			if err := c.proxy.DeleteService(svcName); err != nil {
				return err
			}
		}

	case *userv1.ConnectResponse_State:
		zap.L().Debug("Setting the state")
		connection := state.Event.(*userv1.ConnectResponse_State).State
		c.c.Connection = connection
		if err := c.ctl.Reconfigure(); err != nil {
			return err
		}

	default:
		zap.L().Warn("Unhandled event", zap.Any("state", state))
	}

	return nil
}
