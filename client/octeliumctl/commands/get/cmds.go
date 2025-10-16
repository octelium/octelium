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

package get

import (
	"github.com/octelium/octelium/client/octeliumctl/commands/get/authenticator"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/clusterconfig"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/credential"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/device"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/gateway"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/group"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/identityprovider"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/namespace"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/policy"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/region"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/secret"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/service"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/session"
	"github.com/octelium/octelium/client/octeliumctl/commands/get/user"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:   "get",
	Short: "List or get Cluster resources",
}

func AddSubcommands() {
	Cmd.AddCommand(service.Cmd)
	Cmd.AddCommand(user.Cmd)
	Cmd.AddCommand(namespace.Cmd)
	Cmd.AddCommand(session.Cmd)
	Cmd.AddCommand(secret.Cmd)
	Cmd.AddCommand(device.Cmd)
	Cmd.AddCommand(group.Cmd)
	Cmd.AddCommand(credential.Cmd)
	Cmd.AddCommand(policy.Cmd)
	Cmd.AddCommand(identityprovider.Cmd)
	Cmd.AddCommand(clusterconfig.Cmd)
	Cmd.AddCommand(region.Cmd)
	Cmd.AddCommand(gateway.Cmd)
	Cmd.AddCommand(authenticator.Cmd)
}

func init() {
	Cmd.PersistentFlags().Uint32("page", 1, "List page")
	Cmd.PersistentFlags().Uint32("items-per-page", 0, "Items per page")
	Cmd.PersistentFlags().Bool("order-by-name", false, "Order the list by name")
	Cmd.PersistentFlags().Bool("order-reverse", false, "Reverse the order of the list")
}
