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
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const example = `
 octeliumctl update authenticator --approve fido-123456
 octeliumctl update authn --reject totp-123456
 `

var Cmd = &cobra.Command{
	Use:     "authenticator",
	Short:   "Update an Authenticator",
	Example: example,
	Aliases: []string{"authn", "authenticators", "authen"},
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

type args struct {
	Approve bool
	Reject  bool
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().BoolVar(&cmdArgs.Approve, "approve", false, "Approve the Authenticator")
	Cmd.PersistentFlags().BoolVar(&cmdArgs.Reject, "reject", false, "Reject the Authenticator")

	Cmd.MarkFlagsMutuallyExclusive("approve", "reject")
}

func doCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	if !cmdArgs.Approve && !cmdArgs.Reject {
		return errors.Errorf("You must set either the --approve or the --reject flag")
	}

	conn, err := client.GetGRPCClientConn(ctx, i.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()

	c := corev1.NewMainServiceClient(conn)

	authn, err := c.GetAuthenticator(ctx, &metav1.GetOptions{
		Name: i.FirstArg(),
	})
	if err != nil {
		return err
	}

	switch {
	case cmdArgs.Approve:
		authn.Spec.State = corev1.Authenticator_Spec_ACTIVE
	case cmdArgs.Reject:
		authn.Spec.State = corev1.Authenticator_Spec_REJECTED
	}

	_, err = c.UpdateAuthenticator(ctx, authn)
	if err != nil {
		return err
	}

	cliutils.LineNotify("Authenticator %s successfully updated\n", i.FirstArg())

	return nil
}
