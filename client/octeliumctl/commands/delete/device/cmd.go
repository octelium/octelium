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

package device

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/spf13/cobra"
)

type args struct {
	Name string
}

var Cmd = &cobra.Command{
	Use:   "device",
	Short: "Delete a Device",
	Example: `
octeliumctl delete device usr1-linux-p4wbr
octeliumctl del dev usr1-linux-p4wbr
	`,

	Aliases: []string{"dev", "devices"},
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {

}

func doCmd(cmd *cobra.Command, args []string) error {
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	ctx := context.Background()

	conn, err := client.GetGRPCClientConn(ctx, i.Domain)
	if err != nil {
		return err
	}

	defer conn.Close()
	c := corev1.NewMainServiceClient(conn)

	if _, err := c.DeleteDevice(ctx, &metav1.DeleteOptions{Name: i.FirstArg()}); err != nil {
		return err
	}

	cliutils.LineInfo("Device `%s` successfully deleted\n", i.FirstArg())

	return nil
}
