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

package auth

import (
	"os"

	"github.com/octelium/octelium/client/common/commands/auth/authenticator"
	"github.com/octelium/octelium/client/common/commands/auth/create"
	"github.com/octelium/octelium/client/common/commands/auth/delete"
	"github.com/octelium/octelium/client/common/commands/auth/device"
	"github.com/octelium/octelium/client/common/commands/auth/get"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	cobra.EnableTraverseRunHooks = true
}

var Cmd = &cobra.Command{
	Use: "auth",

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if os.Getenv("OCTELIUM_AUTH_PROXY_SOCKET") != "" {
			return errors.Errorf("Cannot use auth commands in proxy mode")
		}
		return nil
	},

	Short: "Authentication-related operations to the Cluster",
}

func AddSubcommands() {
	Cmd.AddCommand(device.Cmd)
	if ldflags.IsDev() {
		Cmd.AddCommand(create.Cmd)
		Cmd.AddCommand(delete.Cmd)
		Cmd.AddCommand(get.Cmd)
		Cmd.AddCommand(authenticator.Cmd)

		create.AddSubcommands()
		delete.AddSubcommands()
		get.AddSubcommands()
	}
}
