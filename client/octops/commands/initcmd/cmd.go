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

package initcmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/octops/commands/install"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type args struct {
	KubeConfigFilePath string
	KubeContext        string
	BootstrapFile      string
	Version            string
	// ExternalIPs        []string
}

var examples = `
octops init example.com --bootstrap /path/to/bootstrap.yaml
octops init octelium.example.com --kubeconfig /path/to/kueconfig --bootstrap /path/to/bootstrap.yaml
octops init sub.octelium.example.com  --kubeconfig /path/to/kueconfig --bootstrap /path/to/bootstrap.yaml
`

var Cmd = &cobra.Command{
	Use:   "init [DOMAIN]",
	Short: "Initialize and install an Octelium Cluster",
	Long: `
Initialize and install an Octelium Cluster on top of a Kubernetes cluster using a bootstrap file`,
	Args:    cobra.ExactArgs(1),
	Example: examples,
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {

	Cmd.PersistentFlags().StringVar(&cmdArgs.KubeConfigFilePath, "kubeconfig", "", "kubeconfig file path (Default path is $HOME/.kube/config)")
	Cmd.PersistentFlags().StringVar(&cmdArgs.KubeContext, "kubecontext", "", "kubecontext")
	Cmd.PersistentFlags().StringVar(&cmdArgs.Version, "version", "", "The desired Octelium Cluster version to be installed")

	Cmd.PersistentFlags().StringVarP(&cmdArgs.BootstrapFile, "bootstrap", "", "",
		`Bootstrap configuration file path`,
	)

	Cmd.MarkFlagRequired("bootstrap")
}

func BuildConfigFromFlags(context, kubeconfigPath string) (*rest.Config, error) {
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: mustGetKubeConfigFilePath(kubeconfigPath)},
		&clientcmd.ConfigOverrides{
			CurrentContext: context,
		}).ClientConfig()
}

func mustGetKubeConfigFilePath(kubeConfigPath string) string {
	ret, _ := getKubeConfigFilePath(kubeConfigPath)
	return ret
}

func getKubeConfigFilePath(kubeConfigPath string) (string, error) {
	if kubeConfigPath != "" {
		_, err := os.Stat(kubeConfigPath)
		if err == nil {
			return kubeConfigPath, nil
		}
		if os.IsNotExist(err) {
			return "", errors.Errorf("The kubeconfig path `%s` does not exist", kubeConfigPath)
		}
	}
	if val := os.Getenv("KUBECONFIG"); val != "" {
		return val, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	{
		kubeConfigPath := path.Join(homeDir, ".kube", "config")
		if _, err := os.Stat(kubeConfigPath); err == nil {
			return kubeConfigPath, nil
		}
	}

	return "", errors.Errorf("Please set the kubeconfig file path")
}

func doCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	clusterDomain := args[0]

	zap.S().Debugf("Chosen cluster domain: %s", clusterDomain)

	cfg, err := BuildConfigFromFlags("", cmdArgs.KubeConfigFilePath)
	if err != nil {
		return err
	}
	zap.S().Debug("getting k8sC")

	k8sC, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	region := &corev1.Region{
		Kind: ucorev1.KindRegion,
		Metadata: &metav1.Metadata{
			Name: "default",
		},
		Spec:   &corev1.Region_Spec{},
		Status: &corev1.Region_Status{},
	}

	if val := strings.TrimSpace(os.Getenv("OCTELIUM_REGION_EXTERNAL_IP")); val != "" && govalidator.IsIP(val) {
		zap.L().Debug("Adding region external IP", zap.String("addr", val))
		extIPsBytes, err := json.Marshal([]string{val})
		if err != nil {
			return err
		}

		if region.Metadata.SystemLabels == nil {
			region.Metadata.SystemLabels = make(map[string]string)
		}

		region.Metadata.SystemLabels["external-ips"] = string(extIPsBytes)
	}

	bootstrap := &cbootstrapv1.Config{}
	var bootstrapBytes []byte
	if cmdArgs.BootstrapFile == "-" {
		bootstrapBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		bootstrapBytes, err = os.ReadFile(cmdArgs.BootstrapFile)
		if err != nil {
			return err
		}
	}

	if err := pbutils.UnmarshalYAML(bootstrapBytes, bootstrap); err != nil {
		return err
	}

	if err := validateBootstrap(bootstrap); err != nil {
		return errors.Errorf("Bootstrap validation error: %+v", err)
	}

	return install.DoInstall(ctx, &install.Opts{
		ClusterDomain:     clusterDomain,
		Region:            region,
		Bootstrap:         bootstrap,
		K8sC:              k8sC,
		Version:           cmdArgs.Version,
		AuthTokenSavePath: os.Getenv("OCTELIUM_AUTH_TOKEN_SAVE_PATH"),
	})
}

func validateBootstrap(bs *cbootstrapv1.Config) error {
	if bs == nil || bs.Spec == nil {
		return errors.Errorf("Nil bootstrap spec")
	}

	if bs.Spec.PrimaryStorage == nil || bs.Spec.PrimaryStorage.GetPostgresql() == nil {
		return errors.Errorf("No Postgres primaryStorage info")
	}

	pgSpec := bs.Spec.PrimaryStorage.GetPostgresql()
	if pgSpec.Host == "" {
		return errors.Errorf("Empty postgres host")
	}
	if pgSpec.Username == "" {
		return errors.Errorf("Empty postgres user")
	}
	if pgSpec.Password == "" {
		return errors.Errorf("Empty postgres password")
	}
	if pgSpec.Port != 0 && !govalidator.IsPort(fmt.Sprintf("%d", pgSpec.Port)) {
		return errors.Errorf("Invalid postgres port")
	}

	switch {
	case govalidator.IsHost(pgSpec.Host):
	default:
		return errors.Errorf("Invalid postgres host")
	}

	if bs.Spec.SecondaryStorage == nil || bs.Spec.SecondaryStorage.GetRedis() == nil {
		return errors.Errorf("No Redis redisStorage info")
	}

	redisSpec := bs.Spec.SecondaryStorage.GetRedis()
	if redisSpec.Host == "" {
		return errors.Errorf("Empty redis host")
	}
	if redisSpec.Password == "" {
		return errors.Errorf("Empty redis password")
	}
	if redisSpec.Port != 0 && !govalidator.IsPort(fmt.Sprintf("%d", redisSpec.Port)) {
		return errors.Errorf("Invalid redis port")
	}

	switch {
	case govalidator.IsHost(redisSpec.Host):
	default:
		return errors.Errorf("Invalid redis host")
	}

	return nil
}
