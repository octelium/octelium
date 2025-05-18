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

package service

import (
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/spf13/cobra"
)

type args struct {
	Port    uint16
	Backend string
	Type    string
}

var example = `
octeliumctl create svc example.com/network-1 --name svc1 --backend https://example.com
octeliumctl create service example.com/net-2 --name svc2 --backend postgres://my-db.private.local
octeliumctl create svc example.com/net-3/svc-3 --backend tcp://custom-app:9090
`

var Cmd = &cobra.Command{
	Use:     "service",
	Short:   "Create Service",
	Example: example,
	Long:    "Create a Service. This command is currently extremely trivial compared to the declarative approach used by `octeliumctl apply`.",
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"svc", "services"},

	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVar(&cmdArgs.Backend, "upstream", "", "Service's upstream URL")
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
	c := corev1.NewMainServiceClient(conn)

	_, err = cliutils.ParseServiceNamespace(i.FirstArg())
	if err != nil {
		return err
	}

	req := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: i.FirstArg(),
		},
		Spec: &corev1.Service_Spec{
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: cmdArgs.Backend,
					},
				},
			},
		},
	}

	_, err = c.CreateService(cmd.Context(), req)
	if err != nil {
		return err
	}

	cliutils.LineInfo("Service `%s` successfully created\n", i.FirstArg())

	return nil
}
