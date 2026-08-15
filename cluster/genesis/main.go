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

		if err := g.RunInit(context.Background(), &genesis.InitOpts{}); err != nil {
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

		if err := g.RunUpgrade(context.Background(), &genesis.UpgradeOpts{}); err != nil {
			return err
		}

		return nil
	},
}

var cmdArgs args

type args struct {
	EnableSPIFFECSIDriver   bool
	SPIFFECSIDriver         string
	SPIFFETrustDomain       string
	EnableIngressFrontProxy bool
	CNIConfDir              string
	MultusConfDir           string
}

func setDeprecatedFlags(cmd *cobra.Command) {
	f := cmd.PersistentFlags()

	f.BoolVar(&cmdArgs.EnableSPIFFECSIDriver, "enable-spiffe-csi", false, "Deprecated. Set via the bootstrap Config instead")
	f.StringVar(&cmdArgs.SPIFFECSIDriver, "spiffe-csi-driver", "", "Deprecated. Set via the bootstrap Config instead")
	f.StringVar(&cmdArgs.SPIFFETrustDomain, "spiffe-trust-domain", "", "Deprecated. Set via the bootstrap Config instead")
	f.BoolVar(&cmdArgs.EnableIngressFrontProxy, "ingress-front-proxy", false, "Deprecated. Set via the bootstrap Config instead")
	f.StringVar(&cmdArgs.CNIConfDir, "cni-conf-dir", "", "Deprecated. Set via the bootstrap Config instead")
	f.StringVar(&cmdArgs.MultusConfDir, "multus-conf-dir", "", "Deprecated. Set via the bootstrap Config instead")

	for _, name := range []string{"enable-spiffe-csi", "spiffe-csi-driver", "spiffe-trust-domain",
		"ingress-front-proxy", "cni-conf-dir", "multus-conf-dir"} {
		f.MarkHidden(name)
	}
}

func init() {
	setDeprecatedFlags(initCmd)
	setDeprecatedFlags(upgradeCmd)
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
