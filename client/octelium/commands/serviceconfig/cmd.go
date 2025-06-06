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
	"os"
	"path"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "config",
	Short: "Set Service Config",
	Example: `
octelium set service-config svc1
octelium set svc-cfg svc1.ns1
	`,
	Aliases: []string{"cfg", "service-config", "svc-cfg", "service-cfg"},
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

	conn, err := client.GetGRPCClientConn(cmd.Context(), i.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()

	c := userv1.NewMainServiceClient(conn)

	_, err = cliutils.ParseServiceNamespace(args[0])
	if err != nil {
		return err
	}

	resp, err := c.SetServiceConfigs(cmd.Context(), &userv1.SetServiceConfigsRequest{
		Name: args[0],
	})
	if err != nil {
		return err
	}

	for _, cfg := range resp.Configs {
		if err := setConfig(cmd.Context(), cfg); err != nil {
			return err
		}
	}

	if len(resp.Configs) > 0 {
		cliutils.LineNotify("Service configuration successfully applied\n")
	} else {
		cliutils.LineNotify("This Service does not need a configuration to be set\n")
	}

	return nil
}

func setConfig(ctx context.Context, cfg *userv1.SetServiceConfigsResponse_Config) error {
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

		if err := os.WriteFile(path.Join(kubeHome, "config"), cfg.GetKubeconfig().Content, 0644); err != nil {
			return err
		}

	default:
		return errors.Errorf("Unsupported service config: %+v", cfg)
	}

	return nil
}
