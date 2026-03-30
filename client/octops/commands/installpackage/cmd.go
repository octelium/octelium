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

package installpackage

import (
	"context"
	"fmt"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octops/commands/initcmd"
	"github.com/octelium/octelium/client/octops/commands/install"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type args struct {
	KubeConfigFilePath string
	KubeContext        string
	Version            string
	Upgrade            bool
	Package            string
}

var examples = `
octops install-package example.com --package octeliumee
octops install-package octelium.example.com --package cordium --kubeconfig /path/to/kueconfig
`

var Cmd = &cobra.Command{
	Use:     "install-package [DOMAIN]",
	Short:   "Install or upgrade an Octelium Cluster package",
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
	Cmd.PersistentFlags().StringVar(&cmdArgs.Version, "version", "", `Package version. By default it is set to "latest"`)
	Cmd.PersistentFlags().StringVar(&cmdArgs.Package, "package", "", `Package name. Currently the values "octeliumee", "cordium" are available`)
	Cmd.PersistentFlags().BoolVar(&cmdArgs.Upgrade, "upgrade", false, `Upgrade an already installed package`)
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

	domain := args[0]

	switch cmdArgs.Package {
	case "octeliumee", "cordium":
	case "":
		return errors.Errorf(`You must provide a package name. Currently the values "octeliumee", "cordium" are available`)
	default:
		return errors.Errorf("Invalid package name: %s", cmdArgs.Package)
	}

	genesisCmd := func() string {
		if cmdArgs.Upgrade {
			return "upgrade"
		}
		return "init"
	}()

	if err := createGenesis(ctx, k8sC, domain, genesisCmd, cmdArgs.Version, cmdArgs.Package); err != nil {
		return err
	}

	if cmdArgs.Upgrade {
		cliutils.LineNotify(`Upgrading the package "%s" has started...`, cmdArgs.Package)
	} else {
		cliutils.LineNotify(`Installing the package "%s" has started...`, cmdArgs.Package)
	}

	return nil

}

func createGenesis(ctx context.Context, c kubernetes.Interface, domain, cmd, version, pkg string) error {

	_, err := c.BatchV1().Jobs("octelium").Create(ctx,
		getGenesisJob(domain, cmd, version, pkg),
		metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func getGenesisJob(domain, cmd, version, pkg string) *batchv1.Job {
	labels := map[string]string{
		"app":                         "octelium",
		"octelium.com/component":      "genesis",
		"octelium.com/component-type": "cluster",
	}

	if pkg == "" {
		pkg = "octelium"
	}

	if cmd == "" {
		cmd = "init"
	}

	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("octelium-genesis-%s-%s-%s",
				cmd, pkg, utilrand.GetRandomStringLowercase(6)),
			Namespace: "octelium",
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: install.GetGenesisPodSpec(domain, cmd, version, "octelium-nocturne", pkg, ""),
			},
		},
	}
}
