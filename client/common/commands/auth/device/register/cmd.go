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
	"os"
	"os/exec"
	"runtime"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/cliutils/deviceinfo"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
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

	return DoRegister(ctx, i.Domain)
}

func DoRegister(ctx context.Context, domain string) error {
	c, err := cliutils.NewAuthClient(ctx, domain, nil)
	if err != nil {
		return err
	}

	req, err := doRegisterBegin(ctx, c.C())
	if err != nil {
		if grpcerr.AlreadyExists(err) {
			cliutils.LineNotify("Device already registered\n")
			return nil
		}
		return err
	}

	if _, err := doRegisterFinish(ctx, c.C(), req); err != nil {
		return err
	}

	cliutils.LineNotify("Device successfully registered\n")

	return nil
}

func doRegisterBegin(ctx context.Context, c authv1.MainServiceClient) (*authv1.RegisterDeviceBeginResponse, error) {

	info, err := deviceinfo.GetDeviceInfo(ctx)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("Obtained Device info", zap.Any("info", info))

	req := &authv1.RegisterDeviceBeginRequest{
		Info: &authv1.RegisterDeviceBeginRequest_Info{
			Hostname:     info.Hostname,
			Id:           info.ID,
			SerialNumber: info.SerialNumber,
			OsType: func() authv1.RegisterDeviceBeginRequest_Info_OSType {
				switch runtime.GOOS {
				case "windows":
					return authv1.RegisterDeviceBeginRequest_Info_WINDOWS
				case "linux":
					return authv1.RegisterDeviceBeginRequest_Info_LINUX
				case "darwin":
					return authv1.RegisterDeviceBeginRequest_Info_MAC
				default:
					return authv1.RegisterDeviceBeginRequest_Info_OS_TYPE_UNKNOWN
				}
			}(),
			MacAddresses: info.MacAddresses,
		},
	}

	return c.RegisterDeviceBegin(ctx, req)
}

func doRegisterFinish(ctx context.Context, c authv1.MainServiceClient, req *authv1.RegisterDeviceBeginResponse) (*authv1.RegisterDeviceFinishResponse, error) {

	var responses []*authv1.RegisterDeviceFinishRequest_Response

	for _, rq := range req.Requests {
		switch rq.Type.(type) {
		case *authv1.RegisterDeviceBeginResponse_Request_Command_:
			out, err := exec.CommandContext(ctx, rq.GetCommand().Command, rq.GetCommand().Args...).CombinedOutput()
			if err != nil {
				return nil, err
			}

			resp := &authv1.RegisterDeviceFinishRequest_Response{
				Uid: rq.Uid,
				Type: &authv1.RegisterDeviceFinishRequest_Response_Command_{
					Command: &authv1.RegisterDeviceFinishRequest_Response_Command{
						Output: out,
					},
				},
			}
			responses = append(responses, resp)
		case *authv1.RegisterDeviceBeginResponse_Request_File_:
			out, err := os.ReadFile(rq.GetFile().Path)
			if err != nil {
				return nil, err
			}
			resp := &authv1.RegisterDeviceFinishRequest_Response{
				Uid: rq.Uid,
				Type: &authv1.RegisterDeviceFinishRequest_Response_File_{
					File: &authv1.RegisterDeviceFinishRequest_Response_File{
						Output: out,
					},
				},
			}
			responses = append(responses, resp)
		default:
			return nil, errors.Errorf("Unknown device registration type. Please upgrade Octelium...")
		}
	}

	return c.RegisterDeviceFinish(ctx, &authv1.RegisterDeviceFinishRequest{
		Uid:       req.Uid,
		Responses: responses,
	})
}
