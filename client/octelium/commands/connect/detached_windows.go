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
	"os"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var windowsServiceName = "octelium-io"

func doRunDetached(args []string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}

	path, err := os.Executable()
	if err != nil {
		return nil
	}

	zap.S().Debugf("opening service...")
	service, err := m.OpenService(windowsServiceName)
	if err == nil {
		zap.S().Debugf("querying service")
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

		zap.S().Debugf("Closing service")
		service.Close()
		if err != nil && err != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			return err
		}

		for {
			zap.S().Debugf("service loop")
			service, err = m.OpenService(windowsServiceName)
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
		DisplayName:  windowsServiceName,
		SidType:      windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}

	zap.S().Debugf("Creating service")

	service, err = m.CreateService(windowsServiceName, path, config, args...)
	if err != nil {
		return err
	}

	zap.S().Debugf("Starting service")

	return service.Start()

}
