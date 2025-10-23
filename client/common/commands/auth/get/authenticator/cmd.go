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

package authenticator

import (
	"fmt"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/printer"
	"github.com/spf13/cobra"
)

var cmdArgs args

type args struct {
	Out string
}

func init() {
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "", "Output format")
}

var Cmd = &cobra.Command{
	Use:   "authenticator",
	Short: "List your Authenticators",
	Example: `
 octelium auth get authn
 octelium auth get authenticator -o json
 octelium auth get authenticators -o yaml
	 `,
	Aliases: []string{"authn"},
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

func doCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	c, err := cliutils.NewAuthClient(ctx, i.Domain, nil)
	if err != nil {
		return err
	}

	itmList, err := c.C().ListAuthenticator(ctx, &authv1.ListAuthenticatorOptions{})
	if err != nil {
		return err
	}

	if cmdArgs.Out != "" {
		out, err := cliutils.OutFormatPrint(cmdArgs.Out, itmList)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(out))
		return nil
	}

	PrintServiceList(itmList.Items)
	return nil
}

func PrintServiceList(itmList []*authv1.Authenticator) {
	if len(itmList) == 0 {
		cliutils.LineInfo("No Authenticators Found\n")
		return
	}

	p := printer.NewPrinter("Name", "Display Name", "Type")
	for _, itm := range itmList {
		p.AppendRow(itm.Metadata.Name, itm.Spec.DisplayName, itm.Status.Type.String())
	}

	p.Render()
}
