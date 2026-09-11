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

package apply

import (
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/resources"
	"github.com/octelium/octelium/client/common/rscdiff"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type args struct {
	DoDelete         bool
	ResourceIncludes []string
	ResourceExcludes []string
	IncludeSecret    bool
}

var examples = `
# Apply changes from a single file
octeliumctl apply /path/to/file.yaml

# Apply changes from a root directory, all yaml files and sub-directories are automatically included
octeliumctl apply /path/to/directory

# Apply changes from multiple files and directories at once
octeliumctl apply /path/to/file.yaml /path/to/directory

# Apply from stdin
cat /path/to/file.yaml | octeliumctl apply -

# Only include changes in User and Group types
octeliumctl apply --include User --include Group /path/to/file.yaml

# Exclude changes in Services
octeliumctl apply --exclude Service /path/to/file.yaml

# Include Secrets in addition to the default Resource kinds
octeliumctl apply --include-secret /path/to/directory

# Synchronize the Cluster to the desired state and delete the Resources that are not described in it
octeliumctl apply --prune /path/to/directory
`

var Cmd = &cobra.Command{
	Use:   "apply [FILE_OR_DIRECTORY]...",
	Short: "Apply the desired state to the Cluster",
	Long: `
Declaratively apply the desired state to the Cluster. This command
accepts both single yaml files and directories. For the case of directories, all yaml files and sub-directories will be recursively searched for resources.
`,

	Example: examples,
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().BoolVar(&cmdArgs.DoDelete, "prune", false,
		`Delete the Resources that exist in the Cluster but are not described in the desired state.
This synchronizes the Cluster to the described state instead of only creating and updating Resources. Disabled by default`)
	Cmd.PersistentFlags().StringSliceVar(&cmdArgs.ResourceIncludes, "include", nil,
		`Only include these Resource kinds. This overrides the default list of included kinds.
Use the flag multiple times to include more kinds`)
	Cmd.PersistentFlags().StringSliceVar(&cmdArgs.ResourceExcludes, "exclude", nil,
		`Exclude these Resource kinds from the list of included kinds.
Use the flag multiple times to exclude more kinds`)
	Cmd.PersistentFlags().BoolVar(&cmdArgs.IncludeSecret, "include-secret", false,
		"Include Secret Resources. This by default is disabled in order to not encourage defining your Secrets inside configs that are meant to be stored in git repos for example")
}

func doCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	allKinds, err := getResourceKinds()
	if err != nil {
		return err
	}

	zap.L().Debug("All available resource kinds set for diff", zap.Strings("kinds", allKinds))

	rscList, err := loadResources(i.Args())
	if err != nil {
		return err
	}

	cc, err := getClusterConfig(rscList)
	if err != nil {
		return err
	}

	warnSkippedResources(rscList, allKinds)

	conn, err := client.GetGRPCClientConn(ctx, i.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()
	c := corev1.NewMainServiceClient(conn)

	totalDiffResp, err := rscdiff.DiffCoreResources(ctx, allKinds, conn, rscList, cmdArgs.DoDelete)
	if err != nil {
		return err
	}

	if totalDiffResp.CountCreated+totalDiffResp.CountUpdated+totalDiffResp.CountDeleted > 0 {
		cliutils.LineNotify("Cluster Core resources successfully applied\n")
		if totalDiffResp.CountCreated > 0 {
			cliutils.LineInfo(" %d resources created\n", totalDiffResp.CountCreated)
		}
		if totalDiffResp.CountUpdated > 0 {
			cliutils.LineInfo(" %d resources updated\n", totalDiffResp.CountUpdated)
		}
		if totalDiffResp.CountDeleted > 0 {
			cliutils.LineInfo(" %d resources deleted\n", totalDiffResp.CountDeleted)
		}
	} else {
		cliutils.LineNotify("No applied changes in Cluster Core resources\n")
	}

	if cc != nil {
		curCC, err := c.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
		if err != nil {
			return err
		}
		if !pbutils.IsEqual(cc.Spec, curCC.Spec) ||
			!pbutils.IsEqual(getCmpMetadata(cc), getCmpMetadata(curCC)) {
			if _, err := c.UpdateClusterConfig(ctx, cc); err != nil {
				return err
			}
			cliutils.LineNotify("\n ClusterConfig updated\n")
		}
	}

	return nil
}

func loadResources(paths []string) ([]umetav1.ResourceObjectI, error) {
	var ret []umetav1.ResourceObjectI

	for _, path := range paths {
		itms, err := resources.LoadCoreResources(path)
		if err != nil {
			return nil, err
		}

		ret = append(ret, itms...)
	}

	if len(ret) == 0 {
		return nil, errors.Errorf("Could not find any Resources in: %s", strings.Join(paths, ", "))
	}

	return ret, nil
}

func getClusterConfig(rscList []umetav1.ResourceObjectI) (*corev1.ClusterConfig, error) {
	var ret *corev1.ClusterConfig

	for _, itm := range rscList {
		if itm.GetKind() != ucorev1.KindClusterConfig {
			continue
		}

		if ret != nil {
			return nil, errors.Errorf("The ClusterConfig Resource is defined more than once")
		}

		ret = itm.(*corev1.ClusterConfig)
	}

	return ret, nil
}

func getCmpMetadata(itm *corev1.ClusterConfig) *metav1.Metadata {
	md := itm.GetMetadata()
	return &metav1.Metadata{
		DisplayName: md.GetDisplayName(),
		Labels:      md.GetLabels(),
		Description: md.GetDescription(),
		Annotations: md.GetAnnotations(),
		Tags:        md.GetTags(),
		PicURL:      md.GetPicURL(),
	}
}

func warnSkippedResources(rscList []umetav1.ResourceObjectI, kinds []string) {
	for _, itm := range rscList {
		if itm.GetKind() == ucorev1.KindClusterConfig || isInList(kinds, itm.GetKind()) {
			continue
		}

		cliutils.LineWarn("Skipping the %s `%s`. Its kind is not included in this apply operation\n",
			itm.GetKind(), itm.GetMetadata().GetName())
	}
}

func getResourceKinds() ([]string, error) {
	includes := cmdArgs.ResourceIncludes
	excludes := cmdArgs.ResourceExcludes

	for _, itm := range append(append([]string{}, includes...), excludes...) {
		if !isInList(supportedResourceNames, itm) {
			return nil, errors.Errorf("Invalid Resource kind: %s. The supported kinds are: %s",
				itm, strings.Join(supportedResourceNames, ", "))
		}
	}

	if len(includes) == 0 {
		includes = defaultResourceNames
	}

	if cmdArgs.IncludeSecret {
		includes = append([]string{ucorev1.KindSecret}, includes...)
	}

	return getResourceNames(includes, excludes), nil
}

var supportedResourceNames = []string{
	ucorev1.KindSecret,
	ucorev1.KindConfig,
	ucorev1.KindPolicy,
	ucorev1.KindIdentityProvider,
	ucorev1.KindNamespace,
	ucorev1.KindGroup,
	ucorev1.KindUser,
	ucorev1.KindService,
	ucorev1.KindCredential,
}

var defaultResourceNames = []string{
	ucorev1.KindConfig,
	ucorev1.KindPolicy,
	ucorev1.KindIdentityProvider,
	ucorev1.KindNamespace,
	ucorev1.KindGroup,
	ucorev1.KindUser,
	ucorev1.KindService,
	ucorev1.KindCredential,
}

func getResourceNames(includes []string, excludes []string) []string {
	var ret []string

	for _, itm := range supportedResourceNames {
		if isInList(includes, itm) && !isInList(excludes, itm) {
			ret = append(ret, itm)
		}
	}

	return ret
}

func isInList(lst []string, arg string) bool {
	for _, itm := range lst {
		if itm == arg {
			return true
		}
	}
	return false
}
