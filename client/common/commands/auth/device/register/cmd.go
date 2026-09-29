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

package register

import (
	"context"
	"strings"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/cliutils/deviceinfo"
	"github.com/octelium/octelium/client/common/commands/auth/authcommon/deviceprobe"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var Cmd = &cobra.Command{
	Use:   "register",
	Short: "Register your Device",
	Example: `
octelium auth device register
octelium auth dev register
	   `,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

func doCmd(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	return DoRegisterDevice(ctx, i.Domain)
}

func DoRegisterDevice(ctx context.Context, domain string) error {
	c, err := cliutils.NewAuthClient(ctx, domain, nil)
	if err != nil {
		return err
	}
	defer c.Close()

	info, err := deviceinfo.GetDeviceInfo(ctx)
	if err != nil {
		return err
	}

	zap.L().Debug("Obtained Device info", zap.Any("info", info))

	return doRegisterDevice(ctx, c.C(), info)
}

func doRegisterDevice(ctx context.Context, c authv1.MainServiceClient, info *deviceinfo.DeviceInfo) error {
	req := getRegisterDeviceRequest(info)

	_, err := c.RegisterDevice(ctx, req)
	switch {
	case err == nil:
		cliutils.LineNotify("Device successfully registered\n")
	case grpcerr.AlreadyExists(err):
		cliutils.LineNotify("Device already registered\n")
	case grpcerr.IsUnimplemented(err):
		zap.L().Debug("RegisterDevice is not implemented by the Cluster. Falling back to the legacy registration")
		return doRegisterDeviceLegacy(ctx, c, req.Info)
	default:
		return err
	}

	runDeviceProbe(ctx, c)

	return nil
}

func doRegisterDeviceLegacy(ctx context.Context, c authv1.MainServiceClient, info *authv1.RegisterDeviceRequest_Info) error {
	resp, err := c.RegisterDeviceBegin(ctx, &authv1.RegisterDeviceBeginRequest{
		Info: info,
	})
	if err != nil {
		if grpcerr.AlreadyExists(err) {
			cliutils.LineNotify("Device already registered\n")
			return nil
		}
		return err
	}

	if _, err := c.RegisterDeviceFinish(ctx, &authv1.RegisterDeviceFinishRequest{
		Uid: resp.Uid,
	}); err != nil {
		return err
	}

	cliutils.LineNotify("Device successfully registered\n")

	return nil
}

func runDeviceProbe(ctx context.Context, c authv1.MainServiceClient) {
	if err := deviceprobe.Run(ctx, c); err != nil {
		zap.L().Warn("Could not run the Device probes", zap.Error(err))
	}
}

func getRegisterDeviceRequest(info *deviceinfo.DeviceInfo) *authv1.RegisterDeviceRequest {
	return &authv1.RegisterDeviceRequest{
		Info: &authv1.RegisterDeviceRequest_Info{
			Hostname:     getHostname(info.Hostname),
			Id:           info.ID,
			SerialNumber: info.SerialNumber,
			OsType:       getOSType(),
			MacAddresses: info.MacAddresses,
		},
	}
}

const maxHostnameLen = 32

func getHostname(arg string) string {
	arg = strings.TrimSpace(arg)
	if len(arg) <= maxHostnameLen {
		return arg
	}

	end := 0
	for i := range arg {
		if i > maxHostnameLen {
			break
		}
		end = i
	}

	return strings.TrimSpace(arg[:end])
}

func getOSType() authv1.RegisterDeviceRequest_Info_OSType {
	switch {
	case cliutils.IsWindows():
		return authv1.RegisterDeviceRequest_Info_WINDOWS
	case cliutils.IsLinux():
		return authv1.RegisterDeviceRequest_Info_LINUX
	case cliutils.IsDarwin():
		return authv1.RegisterDeviceRequest_Info_MAC
	case cliutils.IsAndroid():
		return authv1.RegisterDeviceRequest_Info_ANDROID
	case cliutils.IsIOS():
		return authv1.RegisterDeviceRequest_Info_IOS
	default:
		return authv1.RegisterDeviceRequest_Info_OS_TYPE_UNKNOWN
	}
}
