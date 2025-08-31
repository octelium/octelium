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

package service

import (
	"fmt"
	"strings"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/printer"
	"github.com/spf13/cobra"
)

var cmdArgs args

type args struct {
	Out       string
	Namespace string
}

func init() {
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Namespace, "namespace", "n", "", "Filter by Namespace")
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "", "Output format")
}

var Cmd = &cobra.Command{
	Use:   "service",
	Short: "List/get Services",
	Example: `
octelium get svc
octelium get service --namespace ns1 -o json
octelium get services -n ns2 -o yaml
	`,
	Aliases: []string{"svc", "services"},
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
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

	c := userv1.NewMainServiceClient(conn)

	if i.FirstArg() != "" {
		res, err := c.GetService(cmd.Context(), &metav1.GetOptions{
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

	svcList, err := c.ListService(ctx,
		&userv1.ListServiceOptions{
			Namespace: cmdArgs.Namespace,
			Common:    cliutils.GetCommonListOptions(cmd),
		})
	if err != nil {
		return err
	}

	if cmdArgs.Out != "" {
		out, err := cliutils.OutFormatPrint(cmdArgs.Out, svcList)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(out))
		return nil
	}

	PrintServiceList(svcList.Items)
	return nil
}

func PrintServiceList(svcList []*userv1.Service) {
	if len(svcList) == 0 {
		cliutils.LineInfo("No Services Found\n")
		return
	}

	p := printer.NewPrinter("Name", "Namespace", "Port", "Type", "Addresses", "Description", "TLS", "Public")
	for _, svc := range svcList {
		p.AppendRow(getName(svc), getNamespace(svc),
			fmt.Sprintf("%d", svc.Spec.Port),
			svc.Spec.Type.String(), strings.Join(svc.Status.Addresses, ", "),
			svc.Metadata.Description, cliutils.PrintBoolean(svc.Spec.IsTLS), cliutils.PrintBoolean(svc.Spec.IsPublic))
	}

	p.Render()
}

func getName(svc *userv1.Service) string {
	if svc.Status.PrimaryHostname != "" {
		return svc.Status.PrimaryHostname
	}

	svcNs, _ := cliutils.ParseServiceNamespace(svc.Metadata.Name)
	return svcNs.Service
}

func getNamespace(svc *userv1.Service) string {
	svcNs, _ := cliutils.ParseServiceNamespace(svc.Metadata.Name)
	return svcNs.Namespace
}
