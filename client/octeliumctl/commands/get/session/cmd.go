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

package session

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
	Out  string
	User string
}

const example = `
octeliumctl get session
octeliumctl get sess usr1-0vgiqs75psre
octeliumctl get sessions -o json
octeliumctl get sessions -o yaml
octeliumctl get sess --user alice
`

var Cmd = &cobra.Command{
	Use:     "session",
	Short:   "List/get Sessions",
	Aliases: []string{"sess", "sessions"},
	Example: example,
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "", "Output format (json|yaml)")
	Cmd.PersistentFlags().StringVar(&cmdArgs.User, "user", "", "Filter the list by a User")
}

func doCmd(cmd *cobra.Command, args []string) error {

	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	if err := cliutils.ValidateOutFormat(cmdArgs.Out); err != nil {
		return err
	}

	ctx := cmd.Context()

	conn, err := client.GetGRPCClientConn(ctx, i.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()

	c := corev1.NewMainServiceClient(conn)

	if i.FirstArg() != "" {
		res, err := c.GetSession(ctx, &metav1.GetOptions{
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

		printList([]*corev1.Session{res}, nil)

		return nil
	}

	var usrRef *metav1.ObjectReference
	if cmdArgs.User != "" {
		usrRef = &metav1.ObjectReference{
			Name: cmdArgs.User,
		}
	}

	itmList, err := c.ListSession(ctx, &corev1.ListSessionOptions{
		Common:  cliutils.GetCommonListOptions(cmd),
		UserRef: usrRef,
	})
	if err != nil {
		return err
	}

	if len(itmList.GetItems()) == 0 {
		cliutils.LineInfo("No Sessions found\n")
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

func printList(itmList []*corev1.Session, listMeta *metav1.ListResponseMeta) {
	p := printer.NewPrinter("Name", "User", "Type", "Expires In", "Age", "State", "Connected")

	for _, itm := range itmList {

		p.AppendRow(itm.GetMetadata().GetName(),
			itm.GetStatus().GetUserRef().GetName(),
			func() string {
				ret := itm.GetStatus().GetType().String()
				switch itm.GetStatus().GetType() {
				case corev1.Session_Status_CLIENTLESS:
					if itm.GetStatus().GetIsBrowser() {
						ret = fmt.Sprintf("%s (Browser)", ret)
					}
				}

				return ret
			}(),
			cliutils.PrintExpiresAt(itm.GetSpec().GetExpiresAt()),
			cliutils.GetResourceAge(itm),
			itm.GetSpec().GetState().String(),
			cliutils.PrintBoolean(itm.GetStatus().GetIsConnected()))
	}

	p.Render()

	cliutils.PrintListMeta(len(itmList), listMeta)
}
