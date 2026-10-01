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

package validate

import (
	"strings"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/resources"
	"github.com/octelium/octelium/client/octeliumctl/commands/apply"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var examples = `
# Validate a single file
octeliumctl validate /path/to/file.yaml

# Validate a root directory, all yaml files and sub-directories are automatically included
octeliumctl validate /path/to/directory

# Validate multiple files and directories at once
octeliumctl validate /path/to/file.yaml /path/to/directory

# Validate from stdin
cat /path/to/file.yaml | octeliumctl validate -
`

var Cmd = &cobra.Command{
	Use:   "validate [FILE_OR_DIRECTORY]...",
	Short: "Validate the desired state without applying it to the Cluster",
	Long: `
Validate the desired state locally without connecting to the Cluster. This command
accepts the same files and directories as "octeliumctl apply" and strictly checks that every Resource can be parsed and applied.
Unknown fields, invalid enum values, invalid field types, unsupported kinds and Resources that are defined more than once are all treated as errors.
All the errors are reported at once and the command exits with an error if any is found.
Note that the Resources are not validated by the Cluster itself in this mode.
`,

	Example: examples,
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

func doCmd(cmd *cobra.Command, args []string) error {

	rscList, validationErrs, err := validateResources(args)
	if err != nil {
		return err
	}

	for _, validationErr := range validationErrs {
		cliutils.LineError("%s\n", validationErr)
	}

	if len(validationErrs) > 0 {
		return errors.Errorf("Validation failed with %d errors", len(validationErrs))
	}

	if len(rscList) == 0 {
		return errors.Errorf("Could not find any Resources in: %s", strings.Join(args, ", "))
	}

	cliutils.LineNotify("All %d Resources are valid\n", len(rscList))

	return nil
}

func validateResources(paths []string) ([]umetav1.ResourceObjectI, []error, error) {
	var ret []umetav1.ResourceObjectI
	var validationErrs []error

	for _, path := range paths {
		itms, errs, err := resources.ValidateCoreResources(path)
		if err != nil {
			return nil, nil, err
		}

		ret = append(ret, itms...)
		validationErrs = append(validationErrs, errs...)
	}

	validationErrs = append(validationErrs, apply.ValidateResources(ret)...)

	return ret, validationErrs, nil
}
