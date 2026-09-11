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

package region

import (
	"fmt"
	"strings"

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
octeliumctl get region
octeliumctl get region -o json
octeliumctl get rgn -o yaml
`

var Cmd = &cobra.Command{
	Use:     "region",
	Short:   "List/get Regions",
	Aliases: []string{"rgn", "regions"},
	Example: example,
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "", "Output format (json|yaml)")
}

func doCmd(cmd *cobra.Command, args []string) error {
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	if err := cliutils.ValidateOutFormat(cmdArgs.Out); err != nil {
		return err
	}

	conn, err := client.GetGRPCClientConn(cmd.Context(), i.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()

	c := corev1.NewMainServiceClient(conn)

	if i.FirstArg() != "" {
		res, err := c.GetRegion(cmd.Context(), &metav1.GetOptions{
			Name: i.FirstArg(),
		})
		if err != nil {
			return err
		}

		if cmdArgs.Out != "" {
			out, err := cliutils.OutFormatPrint(cmdArgs.Out, res)
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", string(out))
			return nil
		}

		printList([]*corev1.Region{res}, nil)

		return nil
	}

	itmList, err := c.ListRegion(cmd.Context(), &corev1.ListRegionOptions{
		Common: cliutils.GetCommonListOptions(cmd),
	})
	if err != nil {
		return err
	}

	if len(itmList.GetItems()) == 0 {
		cliutils.LineInfo("No Regions found\n")
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

	printList(itmList.GetItems(), itmList.GetListResponseMeta())

	return nil
}

func printList(itmList []*corev1.Region, listMeta *metav1.ListResponseMeta) {
	p := printer.NewPrinter("Name", "Ingress Addresses", "Age")

	for _, itm := range itmList {

		p.AppendRow(itm.GetMetadata().GetName(),
			strings.Join(itm.GetStatus().GetIngressAddresses(), ", "),
			cliutils.GetResourceAge(itm))
	}

	p.Render()

	cliutils.PrintListMeta(len(itmList), listMeta)
}
