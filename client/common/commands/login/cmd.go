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

package login

import (
	"fmt"
	"os"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type args struct {
	Token             string
	IsWeb             bool
	Assertion         string
	AssertionProvider string
	Scopes            []string
}

var cmdArgs args

func init() {
	cobra.EnableTraverseRunHooks = true
	Cmd.PersistentFlags().StringVar(&cmdArgs.Token, "auth-token", "", "Authentication Token")
	Cmd.PersistentFlags().BoolVar(&cmdArgs.IsWeb, "web", false, "Authenticate using the web Portal")
	Cmd.PersistentFlags().StringVar(&cmdArgs.Assertion, "assertion", "", "Authenticate using an assertion. Refer to the docs for more details.")
	/*
		Cmd.PersistentFlags().StringVar(&cmdArgs.AssertionProvider, "assertion-provider", "",
			"The name of the IdentityProvider used to authenticate the assertion")
	*/

	Cmd.MarkFlagsMutuallyExclusive("auth-token", "web", "assertion")
	// Cmd.MarkFlagsRequiredTogether("assertion", "assertion-provider")

	Cmd.PersistentFlags().StringSliceVar(&cmdArgs.Scopes, "scope", nil,
		`
Scope is a way to limit the access to certain Services and Octelium APIs that works similarly to OAuth2.
This flag is used ONLY while authenticating using the --auth-token or --assertion flags.
You can use this flag also using the login subcommand.
For example, you can only limit the Session to access the Service "svc1.ns1" only using the scope "service:svc1.ns1"
You can also limit yourself to access only Services belonging to the Namespace "ns2" using the scope "service:ns2/*"
You can also use multiple scopes in the same command as follows "--scope service:svc1 --scope service:ns3/*"
`)
}

var Cmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to a Cluster",
	Example: `
octeliumctl login --auth-token <AUTHENTICATION_TOKEN>
octeliumctl login --domain octelium.example.com
	`,

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if os.Getenv("OCTELIUM_AUTH_PROXY_SOCKET") != "" {
			return errors.Errorf("Cannot use login command in proxy mode")
		}
		return nil
	},

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

	opts := &authenticator.AuthenticateOpts{
		Domain:    i.Domain,
		AuthToken: cmdArgs.Token,
		IsWeb:     cmdArgs.IsWeb,
		Scopes:    cmdArgs.Scopes,
	}

	if cmdArgs.Assertion != "" {
		opts.Assertion = &authenticator.AuthenticateOptsAssertion{
			Arg: cmdArgs.Assertion,
		}
	}

	if err := authenticator.Authenticate(ctx, opts); err != nil {
		return err
	}

	conn, err := client.GetGRPCClientConn(ctx, i.Domain)
	if err != nil {
		return err
	}

	st, err := userv1.NewMainServiceClient(conn).GetStatus(ctx, &userv1.GetStatusRequest{})
	if err != nil {
		return nil
	}

	arg := st.User.Metadata.Name
	if st.User.Metadata.DisplayName != "" {
		arg = fmt.Sprintf("%s (%s)", arg, st.User.Metadata.DisplayName)
	}

	cliutils.LineInfo("You are now authenticated as %s\n", arg)

	return nil
}
