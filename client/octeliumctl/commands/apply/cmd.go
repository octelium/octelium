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
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/resources"
	"github.com/octelium/octelium/client/common/rscdiff"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
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

# Apply from stdin
cat /path/to/file.yaml | octeliumctl apply -


# Only include changes in User and Group types
octeliumctl apply --include User --include Group /path/to/file.yaml

# Exclude changes in Services
octeliumctl apply --exclude Service /path/to/file.yaml
`

var Cmd = &cobra.Command{
	Use:   "apply [FILE_OR_DIRECTORY]",
	Short: "Apply the desired state to the Cluster",
	Long: `
Declaratively apply the desired state to the Cluster. This command
accepts both single yaml files and directories. For the case of directories, all yaml files and sub-directories will be recursively searched for resources.
`,

	Example: examples,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

var cmdArgs args

func init() {
	Cmd.PersistentFlags().BoolVar(&cmdArgs.DoDelete, "prune", false,
		"Delete all resource objects that do not exist in the current desired resources as described in file/directory path but do exist in the Cluster. In other words, this synchronizes the current described state in the file/directory path and prunes all additional resources that exist on the Cluster but not in the current desired configuration. Disabled by default.")
	Cmd.PersistentFlags().StringSliceVar(&cmdArgs.ResourceIncludes, "include", nil,
		`
Only include this resource kind. This overrides the default list of included Resources:
["User", "Group", "Policy", "Service", "Namespace", "Credential", "IdentityProvider"]`)
	Cmd.PersistentFlags().StringSliceVar(&cmdArgs.ResourceExcludes, "exclude", nil,
		"Exclude this resource kind from the default list of included Resources")
	Cmd.PersistentFlags().BoolVar(&cmdArgs.IncludeSecret, "include-secret", false,
		"Include Secret resources. This by default is disabled in order to not encourage defining your Secrets inside configs that are meant to be stored in git repos for example")
}

func doCmd(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	i, err := cliutils.GetCLIInfo(cmd, args)
	if err != nil {
		return err
	}

	conn, err := client.GetGRPCClientConn(ctx, i.Domain)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := corev1.NewMainServiceClient(conn)

	resources, err := resources.LoadCoreResources(i.FirstArg())
	if err != nil {
		return err
	}

	doDelete := cmdArgs.DoDelete

	allKinds := getResourceNames(getIncludes(), getExcludes())
	if cmdArgs.IncludeSecret {
		allKinds = append([]string{ucorev1.KindSecret}, allKinds...)
		allKinds = deduplicateItems(allKinds)
	}

	zap.L().Debug("All available resource kinds set for diff", zap.Strings("kinds", allKinds))

	totalDiffResp := &rscdiff.DiffCtlResponse{}

	for _, kindRsc := range allKinds {
		if resp, err := rscdiff.DiffCoreResource(ctx, kindRsc, conn, resources, doDelete); err != nil {
			return err
		} else {
			totalDiffResp.CountCreated += resp.CountCreated
			totalDiffResp.CountUpdated += resp.CountUpdated
			totalDiffResp.CountDeleted += resp.CountDeleted
		}
	}

	cc := func() *corev1.ClusterConfig {
		for _, itm := range resources {
			if itm.GetKind() == ucorev1.KindClusterConfig {
				return itm.(*corev1.ClusterConfig)
			}
		}
		return nil
	}()

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
		curCC, err := client.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
		if err != nil {
			return err
		}
		if !pbutils.IsEqual(cc.Spec, curCC.Spec) {
			if _, err := client.UpdateClusterConfig(ctx, cc); err != nil {
				return err
			}
			cliutils.LineNotify("\n ClusterConfig updated\n")
		}
	}

	return nil
}

func getIncludes() []string {
	if len(deduplicateItems(cmdArgs.ResourceIncludes)) > 0 {
		return deduplicateItems(cmdArgs.ResourceIncludes)
	}
	return allResourceNames
}

func getExcludes() []string {
	if len(deduplicateItems(cmdArgs.ResourceExcludes)) > 0 {
		return deduplicateItems(cmdArgs.ResourceExcludes)
	}
	return nil
}

var allResourceNames = []string{
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
	if len(includes) > 0 {
		for _, itm := range includes {
			if isInList(allResourceNames, itm) {
				ret = append(ret, itm)
			}
		}
	}

	if len(excludes) > 0 {
		for _, itm := range excludes {
			if isInList(allResourceNames, itm) && isInList(ret, itm) {
				ret = deleteItem(ret, itm)
			}
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

func deleteItem(lst []string, arg string) []string {
	for i, itm := range lst {
		if itm == arg {
			ret := append(lst[:i], lst[i+1:]...)
			return ret
		}
	}
	return lst
}

func deduplicateItems(lst []string) []string {
	var ret []string
	for _, itm := range lst {
		if !isInList(ret, itm) {
			ret = append(ret, itm)
		}
	}
	return ret
}
