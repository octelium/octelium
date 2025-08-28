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

package cert

import (
	"context"
	"fmt"
	"os"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octops/commands/initcmd"
	"github.com/spf13/cobra"
	k8scorev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type args struct {
	KubeConfigFilePath string
	KubeContext        string
	CertPath           string
	KeyPath            string
	Namespace          string
}

var examples = `
octops crt example.com --cert /path/to/tls.crt --key /path/to/tls.key
octops cert octelium.example.com --kubeconfig /path/to/kueconfig --cert /path/to/tls.crt --key /path/to/tls.key
octops certificate sub.octelium.example.com  --kubeconfig /path/to/kueconfig --cert /path/to/tls.crt --key /path/to/tls.key
`

var Cmd = &cobra.Command{
	Use:     "certificate [DOMAIN]",
	Short:   "Set/rotate the TLS certificate for the Octelium Cluster",
	Args:    cobra.ExactArgs(1),
	Aliases: []string{"cert", "crt"},
	Example: examples,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVar(&cmdArgs.KubeConfigFilePath, "kubeconfig", "", "kubeconfig file path")
	Cmd.PersistentFlags().StringVar(&cmdArgs.KubeContext, "kubecontext", "", "kubecontext")

	Cmd.PersistentFlags().StringVar(&cmdArgs.CertPath, "cert", "", "TLS PEM certificate file path")
	Cmd.PersistentFlags().StringVar(&cmdArgs.KeyPath, "key", "", "TLS cert key file path")
	Cmd.PersistentFlags().StringVar(&cmdArgs.Namespace, "namespace", "", "Set a Cluster TLS certificate for a certain Octelium Namespace")
}

func doCmd(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()

	cfg, err := initcmd.BuildConfigFromFlags("", cmdArgs.KubeConfigFilePath)
	if err != nil {
		return err
	}

	k8sC, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	if err := cliutils.RunPromptConfirm("Are you sure that you want to set/update the Cluster TLS certificate"); err != nil {
		return err
	}

	tlsCrt, err := os.ReadFile(cmdArgs.CertPath)
	if err != nil {
		return err
	}

	tlsKey, err := os.ReadFile(cmdArgs.KeyPath)
	if err != nil {
		return err
	}

	secret := &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: func() string {
				if cmdArgs.Namespace != "" {
					return fmt.Sprintf("cert-ns-%s", cmdArgs.Namespace)
				}
				return "cert-cluster"
			}(),
			Namespace: "octelium",
		},
		Type: k8scorev1.SecretTypeTLS,
		Data: map[string][]byte{
			k8scorev1.TLSCertKey:       tlsCrt,
			k8scorev1.TLSPrivateKeyKey: tlsKey,
		},
	}

	if _, err := createOrUpdate(ctx, k8sC, secret); err != nil {
		return err
	}

	return nil
}

func createOrUpdate(ctx context.Context, c kubernetes.Interface, itm *k8scorev1.Secret) (*k8scorev1.Secret, error) {
	ret, err := c.CoreV1().Secrets(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.CoreV1().Secrets(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	oldItem.Data = itm.Data
	oldItem.StringData = itm.StringData
	oldItem.ObjectMeta.OwnerReferences = itm.OwnerReferences
	oldItem.Type = itm.Type

	return c.CoreV1().Secrets(itm.Namespace).Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}
