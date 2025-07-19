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
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/octelium/octelium/octelium-go/authc"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
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
