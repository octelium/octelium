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
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "", "Output format")
	Cmd.PersistentFlags().StringVar(&cmdArgs.Namespace, "namespace", "", "Filter the list by a Namespace")
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

	if len(svcList.Items) == 0 {
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

	p := printer.NewPrinter("Name", "Namespace", "Mode", "Port", "Age", "Public", "Anonymous", "Addresses", "TLS")
	for _, svc := range svcList.Items {

		p.AppendRow(svc.Status.PrimaryHostname, svc.Status.NamespaceRef.Name, svc.Spec.Mode.String(),
			fmt.Sprintf("%d", ucorev1.ToService(svc).RealPort()), cliutils.GetResourceAge(svc),
			cliutils.PrintBoolean(svc.Spec.IsPublic), cliutils.PrintBoolean(svc.Spec.IsAnonymous),
			getServiceAddrs(svc), cliutils.PrintBoolean(svc.Spec.IsTLS))
	}

	p.Render()

	return nil
}

func getServiceAddrs(svc *corev1.Service) string {

	addrs := svc.Status.Addresses

	if len(addrs) == 0 {
		return ""
	}

	addrStrs := []string{}

	for _, addr := range addrs {
		if addr.DualStackIP.Ipv4 != "" {
			addrStrs = append(addrStrs, addr.DualStackIP.Ipv4)
		}

		if addr.DualStackIP.Ipv6 != "" {
			addrStrs = append(addrStrs, addr.DualStackIP.Ipv6)
		}
	}

	return strings.Join(addrStrs, ", ")
}
