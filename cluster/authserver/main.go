/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"context"

	"github.com/octelium/octelium/cluster/authserver/authserver"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/spf13/cobra"
)

var grpcCmd = &cobra.Command{
	Use: "grpc",
	RunE: func(cmd *cobra.Command, args []string) error {
		return authserver.Run(cmd.Context(), true)

	},
}

var httpCmd = &cobra.Command{
	Use: "http",
	RunE: func(cmd *cobra.Command, args []string) error {
		return authserver.Run(cmd.Context(), false)

	},
}

var rootCmd = &cobra.Command{
	Use:  "authserver",
	Long: `authserver`,
}

func init() {
	components.SetComponentNamespace(components.ComponentNamespaceOctelium)
	components.SetComponentType(components.AuthServer)
}

func main() {
	components.RunComponent(func(ctx context.Context) error {
		rootCmd.SetContext(ctx)

		rootCmd.AddCommand(grpcCmd)
		rootCmd.AddCommand(httpCmd)
		return rootCmd.Execute()
	}, nil)
}
