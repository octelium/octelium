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
	"fmt"
	"strings"
	"time"

	"github.com/karrick/tparse/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type args struct {
	User string

	ExpiresIn string
	IsOneTime bool
	Rotate    bool

	Type               string
	SessionType        string
	Policies           []string
	Scopes             []string
	MaxAuthentications uint32
	Out                string
}

var Cmd = &cobra.Command{
	Use:   "credential",
	Short: "Create a Credential",
	Example: `
octeliumctl create credential --user usr1 my-cred
octeliumctl create cred --user usr1 --expire-in 3months my-cred
octeliumctl create credential --user usr2 --expire-in 15minutes --one-time
octeliumctl create cred --user usr3 --expire-in 30days
	`,

	Aliases: []string{"cred", "creds", "credentials"},
	Args:    cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().BoolVar(&cmdArgs.Rotate, "rotate", false, "Generate new token for an already created Credential (i.e. rotate the Credential)")
	Cmd.PersistentFlags().StringVar(&cmdArgs.User, "user", "", "User name")
	Cmd.PersistentFlags().StringVar(&cmdArgs.ExpiresIn, "expire-in", "", "Set the duration after which the Credential expires (e.g. `2hours`, `30days`, `6hours`, `1week`)")
	Cmd.PersistentFlags().BoolVar(&cmdArgs.IsOneTime, "one-time", false, "Use this Credential only once for authentication and then delete it")

	Cmd.PersistentFlags().Uint32Var(&cmdArgs.MaxAuthentications, "max-authn", 0, "Maximum number of authentications. Overrides one-time if set")

	Cmd.PersistentFlags().StringVar(&cmdArgs.Type, "type", "", `Credential type (Can take the values: "auth-token", "oauth2" or "access-token"). By default it is an Authentication Token`)
	Cmd.PersistentFlags().StringVar(&cmdArgs.SessionType, "session-type", "", `Session type (Can take the values: "client" or "clientless")`)

	Cmd.PersistentFlags().StringSliceVar(&cmdArgs.Scopes, "scope", nil,
		`Scope applied to Sessions created by this Credential. Use the flag multiple times to add more Scopes.`)
	Cmd.PersistentFlags().StringSliceVar(&cmdArgs.Policies, "policy", nil,
		`Policy attached to Sessions created by this Credential. Use the flag multiple times to add more Policies.`)
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "", "Output format")
}

func doCmd(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()
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

	doGenerateToken := func(credRef *metav1.ObjectReference) error {

		tokenResp, err := c.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: credRef,
		})
		if err != nil {
			return err
		}

		if cmdArgs.Out != "" {
			out, err := cliutils.OutFormatPrint(cmdArgs.Out, tokenResp)
			if err != nil {
				return err
			}
			fmt.Printf("%s\n", string(out))
			return nil
		}

		switch tokenResp.Type.(type) {
		case *corev1.CredentialToken_AuthenticationToken_:
			cliutils.LineNotify("Authentication Token: ")
			cliutils.LineInfo("%s\n", tokenResp.GetAuthenticationToken().AuthenticationToken)
		case *corev1.CredentialToken_Oauth2Credentials:

			cliutils.LineNotify("Client ID: ")
			cliutils.LineInfo("%s\n", tokenResp.GetOauth2Credentials().ClientID)

			cliutils.LineNotify("Client Secret: ")
			cliutils.LineInfo("%s\n", tokenResp.GetOauth2Credentials().ClientSecret)
		case *corev1.CredentialToken_AccessToken_:
			cliutils.LineNotify("Access Token: ")
			cliutils.LineInfo("%s\n", tokenResp.GetAccessToken().AccessToken)
		}
		return nil
	}

	if cmdArgs.Rotate {
		if i.FirstArg() == "" {
			return errors.Errorf("Credential name must be set")
		}

		return doGenerateToken(&metav1.ObjectReference{
			Name: i.FirstArg(),
		})
	}

	var expiresAt *timestamppb.Timestamp
	if cmdArgs.ExpiresIn != "" {
		t, err := tparse.AddDuration(time.Now(), cmdArgs.ExpiresIn)
		if err != nil {
			return err
		}
		expiresAt = pbutils.Timestamp(t)
	}

	req := &corev1.Credential{
		Metadata: &metav1.Metadata{
			Name: i.FirstArg(),
		},
		Spec: &corev1.Credential_Spec{
			User: cmdArgs.User,
			MaxAuthentications: func() uint32 {
				if cmdArgs.MaxAuthentications > 0 {
					return cmdArgs.MaxAuthentications
				}

				if cmdArgs.IsOneTime {
					return 1
				}
				return 0
			}(),
			Authorization: func() *corev1.Credential_Spec_Authorization {
				if len(cmdArgs.Policies) < 1 {
					return nil
				}
				return &corev1.Credential_Spec_Authorization{
					Policies: cmdArgs.Policies,
				}
			}(),
			ExpiresAt: expiresAt,
			Type: func() corev1.Credential_Spec_Type {
				switch cmdArgs.Type {
				case "oauth2":
					return corev1.Credential_Spec_OAUTH2
				case "access", "access-token":
					return corev1.Credential_Spec_ACCESS_TOKEN
				case "auth-token":
					return corev1.Credential_Spec_AUTH_TOKEN
				default:
					return corev1.Credential_Spec_AUTH_TOKEN
				}
			}(),
		},
	}

	if req.Metadata.Name == "" {

		typ := func() string {
			switch req.Spec.Type {
			case corev1.Credential_Spec_ACCESS_TOKEN:
				return "access-token"
			case corev1.Credential_Spec_AUTH_TOKEN:
				return "auth-token"
			case corev1.Credential_Spec_OAUTH2:
				return "oauth2"
			default:
				return strings.ToLower(req.Spec.Type.String())
			}
		}()
		req.Metadata.Name = fmt.Sprintf("%s-%s-%s",
			req.Spec.User,
			typ,
			utilrand.GetRandomStringLowercase(4))
	}

	switch req.Spec.Type {
	case corev1.Credential_Spec_AUTH_TOKEN, corev1.Credential_Spec_ACCESS_TOKEN:
		req.Spec.SessionType = func() corev1.Session_Status_Type {
			switch cmdArgs.SessionType {
			case "client":
				return corev1.Session_Status_CLIENT
			case "clientless":
				return corev1.Session_Status_CLIENTLESS
			default:
				return corev1.Session_Status_CLIENT
			}
		}()
	default:
		req.Spec.SessionType = corev1.Session_Status_CLIENTLESS
	}
	cred, err := c.CreateCredential(ctx, req)
	if err != nil {
		return err
	}

	if cmdArgs.Out == "" {
		cliutils.LineInfo("Credential %s successfully created\n", req.Metadata.Name)
	}

	return doGenerateToken(umetav1.GetObjectReference(cred))
}
