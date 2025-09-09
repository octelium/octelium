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
	"github.com/octelium/octelium/client/octelium/commands/get/namespace"
	"github.com/octelium/octelium/client/octelium/commands/get/service"
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use: "get",
}

func AddSubcommands() {
	Cmd.AddCommand(service.Cmd)
	Cmd.AddCommand(namespace.Cmd)
}

func init() {
	Cmd.PersistentFlags().Uint32("page", 1, "List page")
	Cmd.PersistentFlags().Uint32("items-per-page", 0, "Items per page")
	Cmd.PersistentFlags().Bool("order-by-name", false, "Order the list by name")
	Cmd.PersistentFlags().Bool("order-reverse", false, "Reverse the order of the list")
}
