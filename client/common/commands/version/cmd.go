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
	"context"
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/ghodss/yaml"
	"github.com/go-resty/resty/v2"
	"github.com/hashicorp/go-version"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var cmdArgs args

type args struct {
	Out       string
	CheckMode bool
}

func init() {
	Cmd.PersistentFlags().StringVarP(&cmdArgs.Out, "out", "o", "yaml", "Output format")
	Cmd.PersistentFlags().BoolVar(&cmdArgs.CheckMode, "check", false,
		"Check whether there is a more recent latest release for Octelium CLIs")
}

var Cmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	RunE: func(cmd *cobra.Command, args []string) error {
		return doCmd(cmd, args)
	},
}

type OcteliumVersion struct {
	cliutils.OcteliumCommonVersion
}

func doCmd(cmd *cobra.Command, args []string) error {

	ctx := cmd.Context()
	if cmdArgs.CheckMode {
		return doCheckClient(ctx)
	}

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

func doCheckClient(ctx context.Context) error {

	latestVersion, err := getLatestVersion(ctx)
	if err != nil {
		return err
	}

	currentVersion, err := version.NewSemver(ldflags.SemVer)
	if err != nil {
		return err
	}

	if latestVersion.LessThanOrEqual(currentVersion) {
		cliutils.LineNotify("Your client version is up-to-date.\n")
		cliutils.LineNotify("Current Client Version: %s\n", currentVersion.String())
		cliutils.LineNotify("Latest Client Version: %s\n", latestVersion.String())
		return nil
	}

	cliutils.LineNotify("Current Client Version: %s\n", currentVersion.String())
	cliutils.LineNotify("Latest Client Version: %s\n", latestVersion.String())

	cliutils.LineNotify("Your Octelium CLIs can be upgraded using the following command:\n")

	switch runtime.GOOS {
	case "linux", "darwin":
		cliutils.LineNotify("curl -fsSL https://octelium.com/install.sh | bash\n")
	case "windows":
		cliutils.LineNotify("iwr https://octelium.com/install.ps1 -useb | iex\n")
	default:
		return errors.Errorf("Unsupported OS platform")
	}

	return nil
}

func getLatestVersion(ctx context.Context) (*version.Version, error) {
	resp, err := resty.New().SetDebug(ldflags.IsDev()).
		R().
		SetContext(ctx).
		Get("https://raw.githubusercontent.com/octelium/octelium/refs/heads/main/unsorted/latest_release")
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, errors.Errorf("Could not get latest Octelium version release")
	}

	return version.NewSemver(string(resp.Body()))
}
