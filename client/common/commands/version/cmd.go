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

package version

import (
	"encoding/json"
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/octelium/octelium/client/common/cliutils"
)

var cmdArgs args

type args struct {
	Out string
}

func init() {
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "yaml", "Output format")
}

var Cmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd()
	},
}

type OcteliumVersion struct {
	cliutils.OcteliumCommonVersion
}

func doCmd() error {

	i := &OcteliumVersion{
		OcteliumCommonVersion: *cliutils.GetOcteliumCommonVersion(),
	}

	switch cmdArgs.Out {
	case "json":
		out, err := json.MarshalIndent(i, "", "    ")
		if err != nil {
			return err
		}

		fmt.Printf("%s", out)
	case "yaml":
		out, err := yaml.Marshal(i)
		if err != nil {
			return err
		}

		fmt.Printf("%s", out)
	default:
		return errors.Errorf("Invalid format `%s`. It must be either yaml or json", cmdArgs.Out)
	}

	return nil
}
