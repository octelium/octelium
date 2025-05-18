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

package user

import (
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/spf13/cobra"
)

type args struct {
	Name        string
	Type        string
	ClusterAddr string
}

var Cmd = &cobra.Command{
	Use:   "user",
	Short: "Create a User",
	Example: `
octeliumctl create user alice
octeliumctl create user --domain octelium.example.com --type WORKLOAD container1
	`,

	Args:    cobra.ExactArgs(1),
	Aliases: []string{"usr", "users"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Name, "name", "n", "", "User name")
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Type, "type", "t", "HUMAN", `The type of the User.
The current values are available: "HUMAN" for humans and "WORKLOAD" for workloads`)
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
	if err != nil {
		return err
	}
	defer conn.Close()

	c := corev1.NewMainServiceClient(conn)

	usr := &corev1.User{
		Metadata: &metav1.Metadata{
			Name: i.FirstArg(),
		},
		Spec: &corev1.User_Spec{
			Type: func() corev1.User_Spec_Type {
				switch cmdArgs.Type {
				case "HUMAN":
					return corev1.User_Spec_HUMAN
				case "WORKLOAD":
					return corev1.User_Spec_WORKLOAD
				default:
					return corev1.User_Spec_TYPE_UNKNOWN
				}
			}(),
		},
	}

	if _, err := c.CreateUser(cmd.Context(), usr); err != nil {
		return err
	}

	cliutils.LineInfo("User `%s` successfully created\n", usr.Metadata.Name)

	return nil
}
