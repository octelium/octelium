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

package daemon

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/octelium/octelium/client/octelium/commands/daemon/server"
	"go.uber.org/zap"
	"golang.org/x/sys/windows/svc"
)

const windowsServiceName = "OcteliumDaemon"

func runDaemon(ctx context.Context, opts *server.Opts) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if isService {
		return svc.Run(windowsServiceName, &serviceController{
			ctx:  ctx,
			opts: opts,
		})
	}

	ctx, cancelFn := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancelFn()

	return runServer(ctx, opts)
}

type serviceController struct {
	ctx  context.Context
	opts *server.Opts
}

func (c *serviceController) Execute(_ []string, requests <-chan svc.ChangeRequest,
	changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancelFn := context.WithCancel(c.ctx)
	defer cancelFn()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx, c.opts)
	}()

	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case err := <-errCh:
			if err != nil {
				zap.L().Error("The daemon service exited with an error", zap.Error(err))
				return false, 1
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				cancelFn()
				err := <-errCh
				if err != nil {
					zap.L().Error("The daemon service exited with an error", zap.Error(err))
					return false, 1
				}
				return false, 0
			}

			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancelFn()
				err := <-errCh
				if err != nil {
					zap.L().Error("The daemon service exited with an error", zap.Error(err))
					return false, 1
				}
				return false, 0
			case svc.Interrogate:
				changes <- request.CurrentStatus
			}
		}
	}
}
