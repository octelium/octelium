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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func doRunDetached(domain string, args []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}

	path, err := os.Executable()
	if err != nil {
		return nil
	}

	svcName := getWindowSvcName(domain)
	zap.L().Debug("opening service...")
	service, err := m.OpenService(svcName)
	if err == nil {
		zap.L().Debug("querying service")
		status, err := service.Query()
		if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			service.Close()
			return err
		}
		if status.State != svc.Stopped && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			service.Close()
			return errors.New("Tunnel already installed and running")
		}
		err = service.Delete()

		zap.L().Debug("Closing service")
		service.Close()
		if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			return err
		}

		for {
			zap.L().Debug("service loop")
			service, err = m.OpenService(svcName)
			if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
				break
			}
			service.Close()
			time.Sleep(time.Second / 3)
		}
	}

	config := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
		Dependencies: []string{"Nsi", "TcpIp"},
		DisplayName:  fmt.Sprintf("Octelium (%s)", domain),
		Description:  fmt.Sprintf("Octelium connection for %s", domain),
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}

	zap.L().Debug("Creating service",
		zap.String("path", path),
		zap.Strings("args", args))

	service, err = m.CreateService(svcName, path, config, args...)
	if err != nil {
		return err
	}

	zap.L().Debug("Starting service")

	if err := service.Start(); err != nil {
		return err
	}

	zap.L().Debug("Waiting for service to start...")
	timeout := time.Now().Add(30 * time.Second)
	for time.Now().Before(timeout) {
		status, err := service.Query()
		if err != nil {
			return err
		}

		if status.State == svc.Running {
			zap.L().Debug("Service started successfully")
			return nil
		}

		if status.State == svc.Stopped {
			return errors.Errorf("service stopped unexpectedly during startup")
		}

		time.Sleep(300 * time.Millisecond)
	}

	return errors.Errorf("timeout waiting for service to start")
}

func getWindowSvcName(domain string) string {
	return fmt.Sprintf("octelium-%s", strings.ReplaceAll(domain, ".", "-"))
}
