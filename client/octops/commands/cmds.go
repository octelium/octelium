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

package commands

import (
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/commands/version"
	"github.com/octelium/octelium/client/octops/commands/cert"
	"github.com/octelium/octelium/client/octops/commands/initcmd"
	"github.com/octelium/octelium/client/octops/commands/uninstall"
	"github.com/octelium/octelium/client/octops/commands/upgrade"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "octops",
	Short: "Octelium Cluster operations",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return cliutils.PreRun(cmd, args)
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		return cliutils.PostRun(cmd, args)
	},
}

func InitCmds() {
	Cmd.AddCommand(initcmd.Cmd)
	Cmd.AddCommand(upgrade.Cmd)
	Cmd.AddCommand(cert.Cmd)
	Cmd.AddCommand(version.Cmd)
	Cmd.AddCommand(uninstall.Cmd)
}

func init() {

}
