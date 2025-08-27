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
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/printer"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	"github.com/spf13/cobra"
)

type args struct {
	Out string
}

const example = `
octeliumctl get session
octeliumctl get sess root-cavzne
octeliumctl get sessions -o json
octeliumctl get sessions -o yaml
`

var Cmd = &cobra.Command{
	Use:     "session",
	Short:   "List/get Sessions",
	Aliases: []string{"sess", "sessions"},
	Example: example,
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
		out, err := cliutils.OutFormatPrint(cmdArgs.Out, res)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(out))
		return nil
	}

	itmList, err := c.ListSession(ctx, &corev1.ListSessionOptions{
		Common: cliutils.GetCommonListOptions(cmd),
	})
	if err != nil {
		return err
	}

	if len(itmList.Items) == 0 {
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

	p := printer.NewPrinter("Name", "User", "Type", "Expires In", "Age", "State", "Connected")

	for _, itm := range itmList.Items {

		p.AppendRow(itm.Metadata.Name,
			itm.Status.UserRef.Name,
			func() string {
				ret := itm.Status.Type.String()
				switch itm.Status.Type {
				case corev1.Session_Status_CLIENTLESS:
					if itm.Status.IsBrowser {
						ret = fmt.Sprintf("%s (Browser)", ret)
					}
				}

				return ret
			}(),
			utils_types.HumanDuration(itm.Spec.ExpiresAt.AsTime().Sub(time.Now())),
			cliutils.GetResourceAge(itm), itm.Spec.State.String(),
			cliutils.PrintBoolean(itm.Status.IsConnected))
	}

	p.Render()

	return nil
}
