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

package delete

import (
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/authenticator"
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/credential"
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/device"
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/group"
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/identityprovider"
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/namespace"
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/policy"
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/secret"
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/service"
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/session"
	"github.com/octelium/octelium/client/octeliumctl/commands/delete/user"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete a Cluster resource",
	Aliases: []string{"del", "rm"},
}

func AddSubcommands() {
	Cmd.AddCommand(service.Cmd)
	Cmd.AddCommand(user.Cmd)
	Cmd.AddCommand(secret.Cmd)
	Cmd.AddCommand(namespace.Cmd)
	Cmd.AddCommand(group.Cmd)
	Cmd.AddCommand(policy.Cmd)
	Cmd.AddCommand(session.Cmd)
	Cmd.AddCommand(credential.Cmd)
	Cmd.AddCommand(device.Cmd)
	Cmd.AddCommand(authenticator.Cmd)
	Cmd.AddCommand(identityprovider.Cmd)
}
