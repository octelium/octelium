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
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/commands/auth/authcommon"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var cmdArgs args

type args struct {
	DisplayName string
	Type        string
}

func init() {
	Cmd.PersistentFlags().StringVar(&cmdArgs.DisplayName, "display-name", "", "Display Name")
	Cmd.PersistentFlags().StringVar(&cmdArgs.Type, "type", "", `Authenticator Type. It must be set to "totp" or "tpm"`)
}

var Cmd = &cobra.Command{
	Use:   "authenticator",
	Short: "Create an Authenticator",
	Example: `
  octelium auth create authn --type tpm
  octelium auth create authenticator --totp --display-name Phone Authenticator
	  `,
	Aliases: []string{"authn"},
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

func doCmd(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()
	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	c, err := cliutils.NewAuthClient(ctx, i.Domain, nil)
	if err != nil {
		return err
	}

	typ := func() authv1.Authenticator_Status_Type {
		switch cmdArgs.Type {
		case "totp":
			return authv1.Authenticator_Status_TOTP
		case "tpm":
			return authv1.Authenticator_Status_TPM
		}
		return authv1.Authenticator_Status_TYPE_UNKNOWN
	}()
	if typ == authv1.Authenticator_Status_TYPE_UNKNOWN {
		return errors.Errorf("Unknown Authenticator type")
	}

	authn, err := c.C().CreateAuthenticator(ctx, &authv1.CreateAuthenticatorRequest{
		DisplayName: cmdArgs.DisplayName,
		Type:        typ,
	})
	if err != nil {
		return err
	}

	cliutils.LineInfo("Authenticator %s is now created. Registering it... \n", authn.Metadata.Name)

	authenticatorRef := umetav1.GetObjectReference(authn)

	preChallenge, err := authcommon.GetPreChallenge(ctx, authn)
	if err != nil {
		return err
	}
	beginResp, err := c.C().RegisterAuthenticatorBegin(ctx, &authv1.RegisterAuthenticatorBeginRequest{
		AuthenticatorRef: authenticatorRef,
		PreChallenge:     preChallenge,
	})
	if err != nil {
		if grpcerr.AlreadyExists(err) {
			return nil
		}
		return err
	}

	resp, err := authcommon.Register(ctx, beginResp.ChallengeRequest)
	if err != nil {
		return err
	}

	_, err = c.C().RegisterAuthenticatorFinish(ctx, &authv1.RegisterAuthenticatorFinishRequest{
		AuthenticatorRef:  authenticatorRef,
		ChallengeResponse: resp,
	})
	if err != nil {
		return err
	}

	cliutils.LineInfo("Authenticator is now registered \n")

	return nil
}
