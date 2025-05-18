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

package proxy

import (
	"context"
	"sync"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	controller "github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy"
	"go.uber.org/zap"
)

type Controller struct {
	c *cliconfigv1.Connection

	ipv4Supported bool
	ipv6Supported bool
	// isEnvoyMode     bool
	// envoyController *envoy.Server
	ctl *controller.Controller

	goNetCtl ccommon.GoNetCtl
	mu       sync.Mutex
	isClosed bool

	ctx      context.Context
	cancelFn context.CancelFunc
}

const envoyConfigTemplate = `
admin:
    access_log_path: /tmp/admin_access.log
    address:
        pipe: { path: /tmp/envoy-admin.sock }
dynamic_resources:
    lds_config:
        resource_api_version: V3
        api_config_source:
            api_type: GRPC
            transport_api_version: V3
            grpc_services:
                - envoy_grpc:
                      cluster_name: xds_cluster
    cds_config:
        resource_api_version: V3
        api_config_source:
            api_type: GRPC
            transport_api_version: V3
            grpc_services:
                - envoy_grpc:
                      cluster_name: xds_cluster
node:
    cluster: octelium
    id: octelium
static_resources:
    clusters:
        - name: xds_cluster
          type: STATIC
          connect_timeout: 3s
          lb_policy: round_robin
          http2_protocol_options: {}
          load_assignment:
              cluster_name: xds_cluster
              endpoints:
                  - lb_endpoints:
                        - endpoint:
                              address:
                                  socket_address:
                                      address: 127.0.0.1
                                      port_value: 44444

`

var envoyAlreadyStarted = false

func NewController(ctx context.Context, c *cliconfigv1.Connection, goNetCtl ccommon.GoNetCtl) (*Controller, error) {

	ipv4Supported := c.Connection.L3Mode == userv1.ConnectionState_BOTH ||
		c.Connection.L3Mode == userv1.ConnectionState_V4
	ipv6Supported := c.Connection.L3Mode == userv1.ConnectionState_BOTH ||
		c.Connection.L3Mode == userv1.ConnectionState_V6

	ret := &Controller{
		c:             c,
		ipv4Supported: ipv4Supported,
		ipv6Supported: ipv6Supported,
		goNetCtl:      goNetCtl,
	}

	/*
		if envoy.IsEnabled && (c.Preferences.ServeOpts.ProxyMode == cliconfigv1.Connection_Preferences_ServeOpts_ENVOY_EMBEDDED ||
			c.Preferences.ServeOpts.ProxyMode == cliconfigv1.Connection_Preferences_ServeOpts_ENVOY) {



			zap.S().Debugf("Going for Envoy proxy mode")
			envoyCtl, err := envoy.NewServer(ipv4Supported, ipv6Supported)
			if err != nil {
				return nil, err
			}

			go envoyCtl.Run()

			ret.envoyController = envoyCtl
			ret.isEnvoyMode = true

			if c.Preferences.ServeOpts.ProxyMode == cliconfigv1.Connection_Preferences_ServeOpts_ENVOY_EMBEDDED {
				if envoyAlreadyStarted {
					zap.S().Debugf("Envoy instance already started.")
				} else {
					zap.S().Debugf("Initializing Envoy")
					if err := os.WriteFile("/tmp/envoy.yaml", []byte(envoyConfigTemplate), 0600); err != nil {
						return nil, err
					}

					cmdArgs := []string{"-c", "/tmp/envoy.yaml"}
					if ldflags.IsDev() {
						cmdArgs = append(cmdArgs, "-l", "debug")
					}

					cmd := exec.Command("envoy", cmdArgs...)
					if ldflags.IsDev() {
						cmd.Stdout = os.Stdout
						cmd.Stderr = os.Stderr
					}

					if err := cmd.Start(); err != nil {
						return nil, err
					}
					envoyAlreadyStarted = true
				}
			}
		}
	*/
	{

		ctl, err := controller.NewController(ctx, c, ret.goNetCtl)
		if err != nil {
			return nil, err
		}
		ret.ctl = ctl
	}

	return ret, nil
}

func (c *Controller) Start(ctx context.Context) error {
	c.ctx, c.cancelFn = context.WithCancel(ctx)

	zap.S().Debugf("Starting proxy controller")

	/*
		if c.isEnvoyMode {
			if c.c.Connection.ServiceOptions == nil {
				return nil
			}

			for _, svc := range c.c.Connection.ServiceOptions.Services {
				if err := c.envoyController.AddService(svc); err != nil {
					return err
				}
			}
			return nil
		}
	*/

	return c.ctl.Start(ctx)
}

func (c *Controller) AddService(svc *userv1.HostedService) error {

	/*
		if c.isEnvoyMode {
			return c.envoyController.AddService(svc)
		}
	*/

	if err := c.ctl.AddService(c.ctx, svc); err != nil {
		return err
	}

	return nil
}

func (c *Controller) DeleteService(name string) error {

	/*
		if c.isEnvoyMode {
			return c.envoyController.DeleteService(name, "")
		}
	*/

	return c.ctl.DeleteService(name)
}

func (c *Controller) UpdateService(svc *userv1.HostedService) error {

	/*
		if c.isEnvoyMode {
			return c.envoyController.UpdateService(svc)
		}
	*/

	return c.ctl.UpdateService(c.ctx, svc)
}

func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return nil
	}
	zap.S().Debugf("Closing proxy controller...")
	c.isClosed = true
	c.cancelFn()

	/*
		if c.isEnvoyMode {
			c.envoyController.Close()
			return nil
		}
	*/

	return c.ctl.Close()
}
