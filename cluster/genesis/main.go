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

	"github.com/octelium/octelium/cluster/common/commoninit"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/genesis/genesis"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:  "genesis",
	Long: `genesis`,
}

var initCmd = &cobra.Command{
	Use: "init",
	RunE: func(cmd *cobra.Command, args []string) error {

		g, err := genesis.NewGenesis()
		if err != nil {
			return err
		}

		if err := g.RunInit(context.Background(), &genesis.InitOpts{
			EnableSPIFFECSI:   cmdArgs.EnableSPIFFECSIDriver,
			SPIFFECSIDriver:   cmdArgs.SPIFFECSIDriver,
			SPIFFETrustDomain: cmdArgs.SPIFFETrustDomain,
		}); err != nil {
			return err
		}

		return nil
	},
}

var upgradeCmd = &cobra.Command{
	Use: "upgrade",
	RunE: func(cmd *cobra.Command, args []string) error {
		g, err := genesis.NewGenesis()
		if err != nil {
			return err
		}

		if err := g.RunUpgrade(context.Background(), &genesis.UpgradeOpts{
			EnableSPIFFECSI: cmdArgs.EnableSPIFFECSIDriver,
			SPIFFECSIDriver: cmdArgs.SPIFFECSIDriver,
		}); err != nil {
			return err
		}

		return nil
	},
}

var cmdArgs args

type args struct {
	EnableSPIFFECSIDriver bool
	SPIFFECSIDriver       string
	SPIFFETrustDomain     string
}

func init() {
	initCmd.PersistentFlags().BoolVar(&cmdArgs.EnableSPIFFECSIDriver, "enable-spiffe-csi", false, "Enable SPIFFE CSI Driver")
	initCmd.PersistentFlags().StringVar(&cmdArgs.SPIFFECSIDriver, "spiffe-csi-driver", "", "SPIFFE CSI Driver name")
	initCmd.PersistentFlags().StringVar(&cmdArgs.SPIFFETrustDomain, "spiffe-trust-domain", "", "SPIFFE trust domain")
}

func init() {
	upgradeCmd.PersistentFlags().BoolVar(&cmdArgs.EnableSPIFFECSIDriver, "enable-spiffe-csi", false, "Enable SPIFFE CSI Driver")
	upgradeCmd.PersistentFlags().StringVar(&cmdArgs.SPIFFECSIDriver, "spiffe-csi-driver", "", "SPIFFE CSI Driver name")
	upgradeCmd.PersistentFlags().StringVar(&cmdArgs.SPIFFETrustDomain, "spiffe-trust-domain", "", "SPIFFE trust domain")
}

func init() {
	components.SetComponentNamespace(components.ComponentNamespaceOctelium)
	components.SetComponentType(components.Genesis)
}

func main() {
	components.RunComponent(func(ctx context.Context) error {
		rootCmd.AddCommand(initCmd)
		rootCmd.AddCommand(upgradeCmd)

		if err := commoninit.Run(ctx, nil); err != nil {
			return err
		}

		if err := rootCmd.Execute(); err != nil {
			return err
		}

		return nil
	}, nil)

}
