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

package upgrade

import (
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octops/commands/initcmd"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
)

type args struct {
	KubeConfigFilePath string
	KubeContext        string
	Version            string
}

var examples = `
octops upgrade example.com
octops upgrade octelium.example.com --kubeconfig /path/to/kueconfig
octops upgrade sub.octelium.example.com  --kubeconfig /path/to/kueconfig
`

var Cmd = &cobra.Command{
	Use:     "upgrade [DOMAIN]",
	Short:   "Upgrade your Octelium Cluster",
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
	Cmd.PersistentFlags().StringVar(&cmdArgs.Version, "version", "", `The desired Octelium Cluster version. By default it is set to "latest"`)
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

	if err := cliutils.RunPromptConfirm("Confirm to proceed with the Cluster upgrade"); err != nil {
		return err
	}

	if err := createGenesis(ctx, k8sC, clusterDomain, cmdArgs.Version); err != nil {
		return err
	}

	return nil

}
