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

package secret

import (
	"io"
	"os"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type args struct {
	Value string

	FromFile    string
	Type        string
	CertPath    string
	CertKeyPath string
}

var example = `
octeliumctl create secret my-api-token
octeliumctl create secret -f /path/to/secret/file secret1
octeliumctl create secret --file ~/.ssh/id_ed25519
octeliumctl create secret --value TOP_SECRET secret2
echo $MY_SECRET | octeliumctl create secret my-secret --file -
octeliumctl create secret mtls-k8s-01 --cert /PATH/TO/CERTIFICATE_CHAIN.PEM --cert-key /PATH/TO/CERTIFICATE_PRIVATE_KEY.PEM
`

var Cmd = &cobra.Command{
	Use:     "secret",
	Short:   "Create Secret",
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"sec", "secrets"},
	Example: example,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVar(&cmdArgs.Value, "value", "", "Secret value")
	Cmd.PersistentFlags().StringVarP(&cmdArgs.FromFile, "file", "f", "", "Get Secret value from file path")
	Cmd.PersistentFlags().StringVar(&cmdArgs.Type, "type", "value", `Secret type. By default it is set to "value". It can also set to "cert" for TLS certificate`)
	Cmd.PersistentFlags().StringVar(&cmdArgs.CertPath, "cert", "", `Certificate file path. Needs --type to be set to "cert"`)
	Cmd.PersistentFlags().StringVar(&cmdArgs.CertKeyPath, "cert-key", "", `Certificate private key file path. Needs --type to be set to "cert"`)
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

	var value []byte

	req := &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: i.FirstArg(),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{},
	}

	if cmdArgs.Type == "cert" {
		if cmdArgs.CertPath == "" || cmdArgs.CertKeyPath == "" {
			return errors.Errorf("Both certificate file path and its private key file path must be set")
		}

		crt, err := os.ReadFile(cmdArgs.CertPath)
		if err != nil {
			return err
		}
		key, err := os.ReadFile(cmdArgs.CertKeyPath)
		if err != nil {
			return err
		}

		ucorev1.ToSecret(req).SetCertificate(string(crt), string(key))

	} else {
		value, err = getValue()
		if err != nil {
			return err
		}

		req.Data = &corev1.Secret_Data{
			Type: &corev1.Secret_Data_ValueBytes{
				ValueBytes: value,
			},
		}
	}

	if _, err := c.CreateSecret(cmd.Context(), req); err != nil {
		return err
	}

	cliutils.LineInfo("Secret `%s` successfully created\n", i.FirstArg())

	return nil
}

func getValue() ([]byte, error) {
	if cmdArgs.FromFile != "" {
		if cmdArgs.FromFile == "-" {
			return io.ReadAll(os.Stdin)

		} else {
			return os.ReadFile(cmdArgs.FromFile)
		}
	}

	if cmdArgs.Value != "" {
		return []byte(cmdArgs.Value), nil
	}

	return cliutils.GetSecretPrompt()
}
