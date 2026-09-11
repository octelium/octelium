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

package credential

import (
	"time"

	"github.com/karrick/tparse/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const example = `
octeliumctl update credential --expire-in 30days my-cred
octeliumctl update cred --max-authn 10 my-cred
octeliumctl update cred --policy my-policy --policy my-other-policy my-cred
octeliumctl update cred --disable my-cred
octeliumctl update cred --enable my-cred
`

var Cmd = &cobra.Command{
	Use:     "credential",
	Short:   "Update a Credential",
	Example: example,
	Aliases: []string{"cred", "creds", "credentials"},
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

type args struct {
	ExpiresIn          string
	MaxAuthentications uint32
	Policies           []string
	Disable            bool
	Enable             bool
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVar(&cmdArgs.ExpiresIn, "expire-in", "", "Set the duration after which the Credential expires (e.g. `2hours`, `30days`, `6hours`, `1week`)")
	Cmd.PersistentFlags().Uint32Var(&cmdArgs.MaxAuthentications, "max-authn", 0, "Maximum number of authentications")
	Cmd.PersistentFlags().StringSliceVar(&cmdArgs.Policies, "policy", nil,
		`Policy attached to Sessions created by this Credential. This overrides the currently attached Policies. Use the flag multiple times to add more Policies.`)
	Cmd.PersistentFlags().BoolVar(&cmdArgs.Disable, "disable", false, "Disable the Credential")
	Cmd.PersistentFlags().BoolVar(&cmdArgs.Enable, "enable", false, "Enable the Credential")

	Cmd.MarkFlagsMutuallyExclusive("disable", "enable")
}

func doCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	if !cmd.Flags().Changed("expire-in") && !cmd.Flags().Changed("max-authn") &&
		!cmd.Flags().Changed("policy") && !cmdArgs.Disable && !cmdArgs.Enable {
		return errors.Errorf(
			"You must set at least one of the --expire-in, --max-authn, --policy, --disable or --enable flags")
	}

	conn, err := client.GetGRPCClientConn(ctx, i.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()

	c := corev1.NewMainServiceClient(conn)

	cred, err := c.GetCredential(ctx, &metav1.GetOptions{
		Name: i.FirstArg(),
	})
	if err != nil {
		return err
	}

	if cmdArgs.ExpiresIn != "" {
		t, err := tparse.AddDuration(time.Now(), cmdArgs.ExpiresIn)
		if err != nil {
			return err
		}
		cred.Spec.ExpiresAt = pbutils.Timestamp(t)
	}

	if cmd.Flags().Changed("max-authn") {
		cred.Spec.MaxAuthentications = cmdArgs.MaxAuthentications
	}

	if cmd.Flags().Changed("policy") {
		cred.Spec.Authorization = func() *corev1.Credential_Spec_Authorization {
			if len(cmdArgs.Policies) < 1 {
				return nil
			}
			return &corev1.Credential_Spec_Authorization{
				Policies: cmdArgs.Policies,
			}
		}()
	}

	switch {
	case cmdArgs.Disable:
		cred.Spec.IsDisabled = true
	case cmdArgs.Enable:
		cred.Spec.IsDisabled = false
	}

	if _, err := c.UpdateCredential(ctx, cred); err != nil {
		return err
	}

	cliutils.LineNotify("Credential %s successfully updated\n", i.FirstArg())

	return nil
}
