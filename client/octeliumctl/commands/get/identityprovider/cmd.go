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

package identityprovider

import (
	"fmt"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/printer"
	"github.com/spf13/cobra"
)

type args struct {
	Out string
}

const example = `
octeliumctl get idp
octeliumctl get identityprovider -o json
octeliumctl get identityprovider -o yaml
`

var Cmd = &cobra.Command{
	Use:     "identityprovider",
	Aliases: []string{"idp", "identityproviders"},
	Short:   "List/get IdentityProviders",
	Example: example,
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "", "Output format")
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

	if i.FirstArg() != "" {
		res, err := c.GetIdentityProvider(cmd.Context(), &metav1.GetOptions{
			Name: i.FirstArg(),
		})
		if err != nil {
			return err
		}
		out, err := cliutils.OutFormatPrint(cmdArgs.Out, res)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(out))
		return nil
	}

	itmList, err := c.ListIdentityProvider(cmd.Context(), &corev1.ListIdentityProviderOptions{
		Common: cliutils.GetCommonListOptions(cmd),
	})
	if err != nil {
		return err
	}

	if len(itmList.Items) == 0 {
		cliutils.LineInfo("No IdentityProviders found\n")
		return nil
	}

	if cmdArgs.Out != "" {
		out, err := cliutils.OutFormatPrint(cmdArgs.Out, itmList)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(out))
		return nil
	}

	p := printer.NewPrinter("Name", "Type", "Age", "Disabled")

	for _, itm := range itmList.Items {
		p.AppendRow(itm.Metadata.Name, itm.Status.Type.String(),
			cliutils.GetResourceAge(itm), cliutils.PrintBoolean(itm.Spec.IsDisabled))
	}

	p.Render()

	return nil
}
