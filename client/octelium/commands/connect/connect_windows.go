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
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
)

func doConnect(ctx context.Context, domain string) error {

	/*
		if ldflags.IsDev() {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}

			f, err := os.OpenFile(path.Join(home, "octelium-logs"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
			if err != nil {
				return err
			}
			defer f.Close()

			mw := io.MultiWriter(os.Stdout, f)

		}
	*/

	isWindowsService, _ := svc.IsWindowsService()
	if isWindowsService {
		svcController := &serviceController{
			domain: domain,
		}
		return svc.Run(windowsServiceName, svcController)
	}

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	ctx, cancelFn := context.WithCancel(ctx)
	go func() {
		<-signalCh
		zap.S().Debugf("Received shutdown signal")
		cancelFn()
	}()

	return connect(ctx, domain)

}

type serviceController struct {
	domain string
}

func (c *serviceController) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	defer func() {
		changes <- svc.Status{State: svc.StopPending}
	}()

	ctx := context.Background()
	if err := copyConfigOwnerToIPCSecurityDescriptor(); err != nil {
		return
	}

	logFile, err := conf.LogFile(true)
	if err != nil {
		return
	}

	if err := ringlogger.InitGlobalLogger(logFile, "octelium"); err != nil {
		return
	}

	if m, err := mgr.Connect(); err == nil {
		if lockStatus, err := m.LockStatus(); err == nil && lockStatus.IsLocked {
			zap.S().Debugf("SCM locked for %v by %s, marking service as started", lockStatus.Age, lockStatus.Owner)
			changes <- svc.Status{State: svc.Running}
		}
		m.Disconnect()
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	ctx, cancelFn := context.WithCancel(ctx)

	go func() {
		for {
			select {
			case cr := <-r:
				switch cr.Cmd {
				case svc.Stop, svc.Shutdown:
					zap.S().Debugf("Received shutdown signal")
					cancelFn()
					return
				case svc.Interrogate:
					changes <- cr.CurrentStatus
				default:
				}
			}
		}
	}()

	connect(ctx, c.domain)
	return
}

func copyConfigOwnerToIPCSecurityDescriptor() error {
	filename, err := os.Executable()
	if err != nil {
		return err
	}

	fileSd, err := windows.GetNamedSecurityInfo(filename, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	fileOwner, _, err := fileSd.Owner()
	if err != nil {
		return err
	}
	if fileOwner.IsWellKnown(windows.WinLocalSystemSid) {
		return nil
	}
	additionalEntries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(fileOwner),
		},
	}}

	sd, err := ipc.UAPISecurityDescriptor.ToAbsolute()
	if err != nil {
		return err
	}
	dacl, defaulted, _ := sd.DACL()

	newDacl, err := windows.ACLFromEntries(additionalEntries, dacl)
	if err != nil {
		return err
	}
	err = sd.SetDACL(newDacl, true, defaulted)
	if err != nil {
		return err
	}
	sd, err = sd.ToSelfRelative()
	if err != nil {
		return err
	}
	ipc.UAPISecurityDescriptor = sd

	return nil
}
