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

package uninstall

import (
	"github.com/manifoldco/promptui"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octops/commands/initcmd"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type args struct {
	KubeConfigFilePath string
	KubeContext        string
	Version            string
}

var examples = `
octops uninstall example.com
octops uninstall octelium.example.com --kubeconfig /path/to/kueconfig
octops uninstall sub.octelium.example.com  --kubeconfig /path/to/kueconfig
`

var Cmd = &cobra.Command{
	Use:     "uninstall [DOMAIN]",
	Short:   "Uninstall your Octelium Cluster",
	Args:    cobra.ExactArgs(1),
	Example: examples,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().StringVar(&cmdArgs.KubeConfigFilePath, "kubeconfig", "", "kubeconfig file path")
	Cmd.PersistentFlags().StringVar(&cmdArgs.KubeContext, "kubecontext", "", "kubecontext")
}

func doCmd(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()

	clusterDomain := args[0]

	cfg, err := initcmd.BuildConfigFromFlags("", cmdArgs.KubeConfigFilePath)
	if err != nil {
		return err
	}

	k8sC, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	if err := cliutils.RunPromptConfirm("CONFIRM TO PROCEED WITH THE TOTAL REMOVAL OF THE CLUSTER"); err != nil {
		return err
	}

	prompt := &promptui.Prompt{
		Label: "Please enter the Octelium Cluster domain to confirm the Uninstallation",
		Templates: &promptui.PromptTemplates{
			Prompt: "{{ . | bold }} ",
		},

		Validate: func(s string) error {
			if s != clusterDomain {
				return errors.Errorf("Cluster domain does not match")
			}
			return nil
		},
	}

	if _, err := prompt.Run(); err != nil {
		return err
	}

	if err := k8sC.CoreV1().Namespaces().Delete(ctx, "octelium", v1.DeleteOptions{}); err != nil {
		return err
	}

	cliutils.LineNotify("The Cluster has been uninstalled.\n")

	return nil

}
