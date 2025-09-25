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

package namespace

import (
	"fmt"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/printer"
	"github.com/spf13/cobra"
)

type args struct {
	Out string
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "", "Output format")
}

var Cmd = &cobra.Command{
	Use:   "namespace",
	Short: "List Namespaces",
	Example: `
octelium get namespace
octelium get ns -o json
octelium get namespaces --domain octelium.example.com -o yaml
	`,
	Aliases: []string{"namespaces", "ns"},
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
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

	netList, err := c.ListNamespace(cmd.Context(), &userv1.ListNamespaceOptions{
		Common: cliutils.GetCommonListOptions(cmd),
	})
	if err != nil {
		return err
	}

	if cmdArgs.Out != "" {
		out, err := cliutils.OutFormatPrint(cmdArgs.Out, netList)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(out))
		return nil
	}

	PrintNamespaceList(netList.Items)

	return nil
}

func PrintNamespaceList(nsList []*userv1.Namespace) {
	if len(nsList) == 0 {
		cliutils.LineInfo("No Namespaces Found\n")
		return
	}

	p := printer.NewPrinter("Name", "Description")
	for _, net := range nsList {
		p.AppendRow(net.Metadata.Name, net.Metadata.Description)
	}

	p.Render()
}
