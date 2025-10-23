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
	"context"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/commands/auth/authcommon"
	"github.com/octelium/octelium/octelium-go/authc"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var cmdArgs args

type args struct {
}

func init() {
}

var Cmd = &cobra.Command{
	Use:   "authenticator",
	Short: "Authenticate with an Authenticator",
	Example: `
octelium auth authn totp-123456
octelium auth authenticator totp-abcdef
		`,
	Aliases: []string{"authn"},
	Args:    cobra.ExactArgs(1),
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

	return DoAuthenticate(ctx, i.Domain, c, &metav1.ObjectReference{
		Name: i.FirstArg(),
	})
}

func DoAuthenticate(ctx context.Context, domain string, c *authc.Client, authnRef *metav1.ObjectReference) error {

	authn, err := c.C().GetAuthenticator(ctx, &metav1.GetOptions{
		Name: authnRef.Name,
		Uid:  authnRef.Uid,
	})
	if err != nil {
		return err
	}

	if !authn.Status.IsRegistered {
		return errors.Errorf("The Authenticator is not registered")
	}

	authenticatorRef := umetav1.GetObjectReference(authn)

	beginResp, err := c.C().AuthenticateAuthenticatorBegin(ctx, &authv1.AuthenticateAuthenticatorBeginRequest{
		AuthenticatorRef: authenticatorRef,
	})
	if err != nil {
		if grpcerr.AlreadyExists(err) {
			return nil
		}
		return err
	}

	resp, err := authcommon.Authenticate(ctx, beginResp.ChallengeRequest)
	if err != nil {
		return err
	}

	sessToken, err := c.C().AuthenticateWithAuthenticator(ctx, &authv1.AuthenticateWithAuthenticatorRequest{
		AuthenticatorRef:  authenticatorRef,
		ChallengeResponse: resp,
	})
	if err != nil {
		return err
	}

	if err := cliutils.GetDB().SetSessionToken(domain, sessToken); err != nil {
		return err
	}

	return nil
}
