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
	"context"

	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/go-version"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octops/commands/initcmd"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

type args struct {
	KubeConfigFilePath string
	KubeContext        string
	Version            string
	CheckMode          bool
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

	Cmd.PersistentFlags().BoolVar(&cmdArgs.CheckMode, "check", false,
		"Just check whether there is a more recent latest release without actually upgrading")
	Cmd.PersistentFlags().StringVar(&cmdArgs.Version, "version", "", `The desired Octelium Cluster version. By default it is set to "latest"`)
}

func doCmd(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()

	clusterDomain := args[0]

	if cmdArgs.CheckMode {
		return doCheck(ctx, clusterDomain)
	}

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

	cliutils.LineNotify("Upgrading the Cluster has started.\n")

	return nil

}

func doCheck(ctx context.Context, domain string) error {

	conn, err := client.GetGRPCClientConn(ctx, domain)
	if err != nil {
		return err
	}
	defer conn.Close()

	c := corev1.NewMainServiceClient(conn)

	rgn, err := c.GetRegion(ctx, &metav1.GetOptions{
		Name: "default",
	})
	if err != nil {
		return err
	}

	resp, err := resty.New().SetDebug(ldflags.IsDev()).
		R().
		Get("https://raw.githubusercontent.com/octelium/octelium/refs/heads/main/unsorted/latest_release")
	if err != nil {
		return err
	}

	if !resp.IsSuccess() {
		return errors.Errorf("Could not get latest Cluster version release")
	}

	latestVersion, err := version.NewSemver(string(resp.Body()))
	if err != nil {
		return err
	}

	zap.L().Debug("Latest release", zap.String("version", latestVersion.String()))

	currentVersion, err := version.NewSemver(rgn.Status.Version)
	if err != nil {
		return errors.Errorf("Could not parse current Cluster version. Not a semVer release: %s", rgn.Status.Version)
	}

	zap.L().Debug("Current release", zap.String("version", currentVersion.String()))

	if latestVersion.LessThanOrEqual(currentVersion) {
		cliutils.LineNotify("No Cluster upgraded is needed.\n")
		return nil
	}

	return nil
}
