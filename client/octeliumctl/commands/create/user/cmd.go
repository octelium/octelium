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
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type args struct {
	Type string
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
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Type, "type", "t", "HUMAN",
		`The type of the User (Can take the values: "HUMAN" for humans or "WORKLOAD" for workloads)`)
}

func doCmd(cmd *cobra.Command, args []string) error {
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	typ, err := getType()
	if err != nil {
		return err
	}

	conn, err := client.GetGRPCClientConn(cmd.Context(), i.Domain)
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
			Type: typ,
		},
	}

	if _, err := c.CreateUser(cmd.Context(), usr); err != nil {
		return err
	}

	cliutils.LineInfo("User `%s` successfully created\n", usr.Metadata.Name)

	return nil
}

func getType() (corev1.User_Spec_Type, error) {
	switch cmdArgs.Type {
	case "HUMAN":
		return corev1.User_Spec_HUMAN, nil
	case "WORKLOAD":
		return corev1.User_Spec_WORKLOAD, nil
	default:
		return corev1.User_Spec_TYPE_UNKNOWN, errors.Errorf(
			"Invalid User type: %s. It must be either `HUMAN` or `WORKLOAD`", cmdArgs.Type)
	}
}
