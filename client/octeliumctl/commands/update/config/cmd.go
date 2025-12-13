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

package config

import (
	"io"
	"os"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type args struct {
	Value    string
	FromFile string
}

var example = `
octeliumctl update config my-config
octeliumctl update cfg --file /path/to/config/file my-cfg-1
octeliumctl update conf -f /path/to/config/file my-cfg-1
octeliumctl update conf --value SOME_VALUE cfg-02
echo $MY_VALUE | octeliumctl update config my-config --file -
`

var Cmd = &cobra.Command{
	Use:     "config",
	Short:   "Update Config",
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"cfg", "conf"},
	Example: example,

	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVar(&cmdArgs.Value, "value", "", "Config value")
	Cmd.PersistentFlags().StringVarP(&cmdArgs.FromFile, "file", "f", "", "Get Config value from file path")
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

	c := corev1.NewMainServiceClient(conn)

	var value []byte

	req, err := c.GetConfig(ctx, &metav1.GetOptions{
		Name: i.FirstArg(),
	})
	if err != nil {
		return err
	}

	value, err = getValue()
	if err != nil {
		return err
	}

	req.Data = &corev1.Config_Data{
		Type: &corev1.Config_Data_ValueBytes{
			ValueBytes: value,
		},
	}

	if _, err := c.UpdateConfig(cmd.Context(), req); err != nil {
		return err
	}

	cliutils.LineInfo("Config `%s` successfully updated\n", i.FirstArg())

	return nil
}

func getValue() ([]byte, error) {
	if cmdArgs.FromFile != "" {
		if cmdArgs.FromFile == "-" {
			return io.ReadAll(os.Stdin)

		} else {
			return os.ReadFile(cmdArgs.FromFile)
		}
	}

	if cmdArgs.Value != "" {
		return []byte(cmdArgs.Value), nil
	}

	return nil, errors.Errorf("Either --file or --value must be provided")
}
