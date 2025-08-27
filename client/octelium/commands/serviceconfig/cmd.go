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
	"os"
	"path"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var Cmd = &cobra.Command{
	Use:   "config",
	Short: "Set Service Config",
	Example: `
octelium cfg svc1
octelium config svc1.ns1
	`,
	Aliases: []string{"cfg"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
	Args: cobra.ExactArgs(1),
}

func doCmd(cmd *cobra.Command, args []string) error {
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

	for _, cfg := range resp.Configs {
		if err := setConfig(ctx, cfg, svc, i.Domain); err != nil {
			return err
		}
	}

	if len(resp.Configs) > 0 {
		cliutils.LineNotify("Configuration successfully applied for Service: %s\n", svc.Status.PrimaryHostname)
	} else {
		cliutils.LineNotify("This Service does not need a configuration to be set\n")
	}

	return nil
}

func setConfig(_ context.Context, cfg *userv1.SetServiceConfigsResponse_Config, svc *userv1.Service, domain string) error {
	switch cfg.Type.(type) {
	case *userv1.SetServiceConfigsResponse_Config_Kubeconfig_:
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		kubeHome := path.Join(homeDir, ".kube")

		if err := os.MkdirAll(kubeHome, 0744); err != nil {
			return err
		}

		kubeConfigPath := path.Join(kubeHome,
			fmt.Sprintf("%s.%s", svc.Status.PrimaryHostname, domain))
		if err := os.WriteFile(kubeConfigPath, cfg.GetKubeconfig().Content, 0644); err != nil {
			return err
		}

		cliutils.LineInfo("Set the following environment variable to use kubectl commands for the Service %s:\n",
			svc.Status.PrimaryHostname)
		cliutils.LineInfo("export KUBECONFIG=%s\n", kubeConfigPath)
	default:
		zap.L().Warn("Unsupported service config. Skipping...", zap.Any("cfg", cfg))
	}

	return nil
}
