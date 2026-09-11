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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/printer"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/spf13/cobra"
)

type args struct {
	Out       string
	Namespace string
}

const example = `
octeliumctl get svc
octeliumctl get service
octeliumctl get svc --namespace default
octeliumctl get services -o json
octeliumctl get services -o yaml
`

var Cmd = &cobra.Command{
	Use:     "service",
	Short:   "List/get Services",
	Example: example,
	Aliases: []string{"svc", "services"},
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "", "Output format (json|yaml)")
	Cmd.PersistentFlags().StringVar(&cmdArgs.Namespace, "namespace", "", "Filter the list by a Namespace")
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
		res, err := c.GetService(cmd.Context(), &metav1.GetOptions{
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

		printList([]*corev1.Service{res}, nil)

		return nil
	}

	var nsRef *metav1.ObjectReference
	if cmdArgs.Namespace != "" {
		nsRef = &metav1.ObjectReference{
			Name: cmdArgs.Namespace,
		}
	}

	svcList, err := c.ListService(cmd.Context(), &corev1.ListServiceOptions{
		NamespaceRef: nsRef,
		Common:       cliutils.GetCommonListOptions(cmd),
	})
	if err != nil {
		return err
	}

	if len(svcList.GetItems()) == 0 {
		cliutils.LineInfo("No Services found\n")
		return nil
	}

	if cmdArgs.Out != "" {
		out, err := cliutils.OutFormatPrint(cmdArgs.Out, svcList)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", string(out))
		return nil
	}

	printList(svcList.GetItems(), svcList.GetListResponseMeta())

	return nil
}

func printList(itmList []*corev1.Service, listMeta *metav1.ListResponseMeta) {
	p := printer.NewPrinter("Name", "Namespace", "Mode", "Port", "Age", "Public", "Anonymous", "Addresses", "TLS")

	for _, itm := range itmList {
		p.AppendRow(itm.GetStatus().GetPrimaryHostname(),
			itm.GetStatus().GetNamespaceRef().GetName(),
			itm.GetSpec().GetMode().String(),
			fmt.Sprintf("%d", ucorev1.ToService(itm).RealPort()),
			cliutils.GetResourceAge(itm),
			cliutils.PrintBoolean(itm.GetSpec().GetIsPublic()),
			cliutils.PrintBoolean(itm.GetSpec().GetIsAnonymous()),
			getServiceAddrs(itm),
			cliutils.PrintBoolean(itm.GetSpec().GetIsTLS()))
	}

	p.Render()

	cliutils.PrintListMeta(len(itmList), listMeta)
}

func getServiceAddrs(svc *corev1.Service) string {

	addrs := svc.GetStatus().GetAddresses()

	if len(addrs) == 0 {
		return ""
	}

	addrStrs := []string{}

	for _, addr := range addrs {
		if addr.GetDualStackIP().GetIpv4() != "" {
			addrStrs = append(addrStrs, addr.GetDualStackIP().GetIpv4())
		}

		if addr.GetDualStackIP().GetIpv6() != "" {
			addrStrs = append(addrStrs, addr.GetDualStackIP().GetIpv6())
		}
	}

	return strings.Join(addrStrs, ", ")
}
