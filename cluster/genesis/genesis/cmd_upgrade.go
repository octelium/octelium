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

package genesis

import (
	"context"
	"os"

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/components"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.uber.org/zap"
)

func (g *Genesis) RunUpgrade(ctx context.Context) error {

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	initResources, err := g.loadClusterInitResources(ctx, vutils.K8sNS)
	if err != nil {
		return err
	}

	g.octeliumC = octeliumC

	clusterCfg, err := g.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	regionName := func() string {
		if initResources.Region == nil ||
			initResources.Region.Metadata == nil ||
			initResources.Region.Metadata.Name == "" {
			return "default"
		}
		return initResources.Region.Metadata.Name
	}()
	os.Setenv("OCTELIUM_REGION_NAME", regionName)

	regionV, err := g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Name: regionName})
	if err != nil {
		return err
	}

	zap.L().Debug("upgrading rscServer")

	if err := components.CreateRscServer(ctx, g.k8sC, clusterCfg); err != nil {
		return err
	}

	zap.L().Debug("waiting for readiness of rscServer")

	if err := checkRscServer(ctx, g.k8sC); err != nil {
		return err
	}

	zap.L().Debug("Installing components")

	if err := g.installComponents(ctx, regionV); err != nil {
		return err
	}

	if err := g.installOcteliumResources(ctx, clusterCfg, regionV); err != nil {
		return err
	}

	region, err := g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Uid: regionV.Metadata.Uid})
	if err != nil {
		return err
	}

	region.Status.Version = ldflags.GetVersion()

	_, err = g.octeliumC.CoreC().UpdateRegion(ctx, region)
	if err != nil {
		return err
	}

	return nil
}
