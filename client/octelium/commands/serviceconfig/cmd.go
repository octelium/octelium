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

package serviceconfig

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var cmdArgs args

type args struct {
	Print     bool
	Out       string
	SSHFormat string
}

func init() {
	Cmd.PersistentFlags().BoolVar(&cmdArgs.Print, "print", false, "Print the configuration instead of applying it")
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "",
		"Print the configuration in the given output format (json|yaml) instead of applying it")
	Cmd.PersistentFlags().StringVar(&cmdArgs.SSHFormat, "ssh-format", "",
		"Print the configuration of SSH Services in the given format (known-hosts|authorized-keys|ca-public-key) instead of applying it")
}

var Cmd = &cobra.Command{
	Use:   "config",
	Short: "Set Service Config",
	Example: `
octelium cfg svc1
octelium config svc1.ns1
octelium cfg svc1 --print
octelium cfg svc1 -o yaml
octelium cfg ssh1 --ssh-format authorized-keys
octelium cfg ssh1 --ssh-format ca-public-key
	`,
	Aliases: []string{"cfg"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
	Args: cobra.ExactArgs(1),
}

func validateArgs() error {
	if err := cliutils.ValidateOutFormat(cmdArgs.Out); err != nil {
		return err
	}

	if cmdArgs.SSHFormat != "" {
		if err := validateSSHFormat(cmdArgs.SSHFormat); err != nil {
			return err
		}
	}

	if cmdArgs.Out != "" && cmdArgs.SSHFormat != "" {
		return errors.Errorf("The --out and --ssh-format flags cannot be used together")
	}

	return nil
}

func doCmd(cmd *cobra.Command, args []string) error {
	if err := validateArgs(); err != nil {
		return err
	}

	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	ctx := cmd.Context()

	conn, err := client.GetGRPCClientConn(ctx, i.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()

	c := userv1.NewMainServiceClient(conn)

	svc, err := c.GetService(ctx, &metav1.GetOptions{
		Name: i.FirstArg(),
	})
	if err != nil {
		return err
	}

	resp, err := c.SetServiceConfigs(ctx, &userv1.SetServiceConfigsRequest{
		Name: svc.Metadata.Name,
	})
	if err != nil {
		return err
	}

	switch {
	case cmdArgs.Out != "":
		out, err := cliutils.OutFormatPrint(cmdArgs.Out, resp)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(out))
		return nil
	case cmdArgs.SSHFormat != "":
		return printSSHConfigs(os.Stdout, resp, cmdArgs.SSHFormat)
	case cmdArgs.Print:
		return printConfigs(os.Stdout, resp)
	}

	var applied int
	for _, cfg := range resp.Configs {
		ok, err := setConfig(ctx, cfg, svc, i.Domain)
		if err != nil {
			return err
		}
		if ok {
			applied++
		}
	}

	if unsupported := len(resp.Configs) - applied; unsupported > 0 {
		cliutils.LineWarn("This Service has %d configuration(s) that this octelium CLI version does not support. You can use the --out flag to print them\n",
			unsupported)
	}

	switch {
	case applied > 0:
		cliutils.LineNotify("Configuration successfully applied for Service: %s\n", svc.Status.PrimaryHostname)
	case len(resp.Configs) == 0:
		cliutils.LineNotify("This Service does not need a configuration to be set\n")
	}

	return nil
}

func setConfig(_ context.Context, cfg *userv1.SetServiceConfigsResponse_Config, svc *userv1.Service, domain string) (bool, error) {
	switch cfg.Type.(type) {
	case *userv1.SetServiceConfigsResponse_Config_Kubeconfig_:
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return false, err
		}
		kubeHome := path.Join(homeDir, ".kube")

		if err := os.MkdirAll(kubeHome, 0744); err != nil {
			return false, err
		}

		kubeConfigPath := path.Join(kubeHome,
			fmt.Sprintf("%s.%s", svc.Status.PrimaryHostname, domain))
		if err := os.WriteFile(kubeConfigPath, cfg.GetKubeconfig().Content, 0644); err != nil {
			return false, err
		}

		cliutils.LineInfo("Set the following environment variable to use kubectl commands for the Service %s:\n",
			svc.Status.PrimaryHostname)
		cliutils.LineInfo("export KUBECONFIG=%s\n", kubeConfigPath)
	case *userv1.SetServiceConfigsResponse_Config_Ssh:
		if err := setConfigSSH(cfg.GetSsh(), domain); err != nil {
			return false, err
		}
	default:
		zap.L().Debug("Unsupported service config. Skipping...", zap.Any("cfg", cfg))
		return false, nil
	}

	return true, nil
}

func printConfigs(w io.Writer, resp *userv1.SetServiceConfigsResponse) error {
	if len(resp.Configs) == 0 {
		cliutils.LineNotify("This Service does not need a configuration to be set\n")
		return nil
	}

	for _, cfg := range resp.Configs {
		switch cfg.Type.(type) {
		case *userv1.SetServiceConfigsResponse_Config_Kubeconfig_:
			if _, err := w.Write(cfg.GetKubeconfig().Content); err != nil {
				return err
			}
		case *userv1.SetServiceConfigsResponse_Config_Ssh:
			if err := printSSHConfig(w, cfg.GetSsh()); err != nil {
				return err
			}
		default:
			zap.L().Warn("This octelium CLI version does not support a configuration of this Service. You can use the --out flag to print it")
		}
	}

	return nil
}
