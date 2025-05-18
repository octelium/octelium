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
	"github.com/octelium/octelium/client/common/commands/auth"
	"github.com/octelium/octelium/client/common/commands/login"
	"github.com/octelium/octelium/client/common/commands/logout"
	"github.com/octelium/octelium/client/common/commands/version"
	"github.com/octelium/octelium/client/octelium/commands/connect"
	"github.com/octelium/octelium/client/octelium/commands/disconnect"
	"github.com/octelium/octelium/client/octelium/commands/get"
	"github.com/octelium/octelium/client/octelium/commands/serviceconfig"
	"github.com/octelium/octelium/client/octelium/commands/status"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "octelium",
	Short: "Octelium enables you to connect to Octelium Clusters, access and serve Services",

	// SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return cliutils.PreRun(cmd, args)
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		return cliutils.PostRun(cmd, args)
	},
}

func InitCmds() {
	Cmd.AddCommand(connect.Cmd)
	Cmd.AddCommand(disconnect.Cmd)
	Cmd.AddCommand(get.Cmd)
	Cmd.AddCommand(version.Cmd)
	Cmd.AddCommand(status.Cmd)
	Cmd.AddCommand(serviceconfig.Cmd)
	Cmd.AddCommand(auth.Cmd)

	Cmd.AddCommand(login.Cmd)
	Cmd.AddCommand(logout.Cmd)

	get.AddSubcommands()
	auth.AddSubcommands()
}

func init() {
	Cmd.PersistentFlags().String("domain", "", "The Cluster Domain")
	Cmd.PersistentFlags().String("homedir", "", "Override Octelium home directory")
	Cmd.PersistentFlags().Bool("logout", false, `Log out after executing the command. This is useful when using commands such as "octelium connect" inside ephemeral environments such as containers`)
}
