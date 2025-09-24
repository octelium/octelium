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

package cliutils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/octelium-go/authc"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
)

type CLIInfo struct {
	Domain string

	args []string
}

func (i *CLIInfo) FirstArg() string {
	if len(i.args) >= 1 {
		return i.args[0]
	}
	return ""
}

func GetCLIInfo(cmd *cobra.Command, args []string) (*CLIInfo, error) {
	ret := &CLIInfo{
		args: args,
	}
	if cmd.Flag("domain") != nil {
		ret.Domain = cmd.Flag("domain").Value.String()
	}

	if ret.Domain == "" {
		ret.Domain = os.Getenv("OCTELIUM_DOMAIN")
	}

	if ret.Domain == "" {
		return nil, errors.Errorf("The Cluster domain is not set. Set the domain either via the --domain flag or the OCTELIUM_DOMAIN environment variable")
	}

	return ret, nil
}

func PrintBoolean(arg bool) string {
	if arg {
		return "True"
	}
	return ""
}

type ServiceNamespace struct {
	Service   string
	Namespace string
}

func ParseServiceNamespace(arg string) (*ServiceNamespace, error) {
	svcArgs := strings.Split(arg, ".")
	ret := &ServiceNamespace{}
	if len(svcArgs) == 1 {
		ret.Service = svcArgs[0]
		ret.Namespace = "default"
	} else if len(svcArgs) == 2 {
		ret.Service = svcArgs[0]
		ret.Namespace = svcArgs[1]
	} else {
		return nil, errors.Errorf("Could not parse Service: %s. It must be in the format svc.namespace", arg)
	}
	return ret, nil
}

func (s *ServiceNamespace) String() string {
	return fmt.Sprintf("%s.%s", s.Service, s.Namespace)
}

func GetServiceFullNameFromName(arg string) string {
	if arg == "" {
		return ""
	}
	args := strings.Split(arg, ".")
	if len(args) == 1 {
		return fmt.Sprintf("%s.default", arg)
	}
	if len(args) == 2 {
		return arg
	}
	return ""
}

func GetGenesisImage(version string) string {
	return ldflags.GetImage("octelium-genesis", version)
}

func GetSecretPrompt() ([]byte, error) {

	prompt := promptui.Prompt{
		Label:       "Enter the Secret value",
		HideEntered: true,
		Mask:        '*',
	}

	res, err := prompt.Run()
	if err != nil {
		return nil, err
	}

	return []byte(res), nil
}

func GetRefreshToken(ctx context.Context, domain string) (string, error) {
	at, err := GetDB().GetSessionToken(domain)
	if err != nil {
		return "", err
	}

	return at.RefreshToken, nil
}

func OpenFileByDefaultAppCmd(url string) (*exec.Cmd, error) {

	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url), nil
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url), nil
	case "darwin":
		return exec.Command("open", url), nil
	default:
		return nil, errors.Errorf("This OS is not supported currently")
	}
}

type NewAuthClientOpts struct {
}

func NewAuthClient(ctx context.Context, domain string, o *NewAuthClientOpts) (*authc.Client, error) {
	return authc.NewClient(ctx, domain, &authc.Opts{
		GetRefreshToken: GetRefreshToken,
		UserAgent:       fmt.Sprintf("octelium-cli/%s", ldflags.SemVer),
	})
}

func GetCommonListOptions(cmd *cobra.Command) *metav1.CommonListOptions {
	if cmd == nil {
		return nil
	}

	ret := &metav1.CommonListOptions{
		Page: func() uint32 {
			ret := getFlagUint32(cmd, "page")
			if ret < 1 {
				return 0
			}
			return ret - 1
		}(),
		ItemsPerPage: getFlagUint32(cmd, "items-per-page"),
	}

	if getFlagBoolean(cmd, "order-by-name") {
		ret.OrderBy = &metav1.CommonListOptions_OrderBy{
			Type: metav1.CommonListOptions_OrderBy_NAME,
		}
	}

	if getFlagBoolean(cmd, "order-reverse") {
		if ret.OrderBy == nil {
			ret.OrderBy = &metav1.CommonListOptions_OrderBy{}
		}
		ret.OrderBy.Mode = metav1.CommonListOptions_OrderBy_DESC
	}

	return ret
}

func getFlagStr(cmd *cobra.Command, arg string) string {
	if cmd.Flags() != nil && cmd.Flags().Lookup(arg) != nil && cmd.Flags().Lookup(arg).Value.String() != "" {
		return cmd.Flags().Lookup(arg).Value.String()
	}
	return ""
}

func getFlagUint32(cmd *cobra.Command, arg string) uint32 {
	if argStr := getFlagStr(cmd, arg); argStr != "" {
		ret, _ := strconv.ParseUint(argStr, 10, 32)
		return uint32(ret)
	}

	return 0
}

func getFlagBoolean(cmd *cobra.Command, arg string) bool {
	return getFlagStr(cmd, arg) == "true"
}

func GrpcErr(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	return errors.Errorf("gRPC error %s: %s", st.Code(), st.Message())
}
