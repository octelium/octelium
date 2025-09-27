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
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/components"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
)

func (g *Genesis) RunUpgrade(ctx context.Context) error {

	zap.L().Info("Starting upgrade...")
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

	if err := g.updateServicesUpgradeUID(ctx, regionV); err != nil {
		zap.L().Warn("Could not updateServicesUpgradeUID", zap.Error(err))
	}

	if err := g.installBuiltinPolicies(ctx); err != nil {
		zap.L().Warn("Could not install builtin Policies", zap.Error(err))
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

	zap.L().Info("Upgrade successfully completed...")

	return nil
}

func (g *Genesis) updateServicesUpgradeUID(ctx context.Context, rgn *corev1.Region) error {

	zap.L().Debug("Starting updateServicesUpgradeUID")
	svcList, err := g.getAllServices(ctx, rgn)
	if err != nil {
		return err
	}

	idKey := utilrand.GetRandomStringCanonical(12)
	zap.L().Debug("Starting upgrading Region's Services via idKey",
		zap.Int("len", len(svcList)), zap.String("idKey", idKey))

	for _, svc := range svcList {
	doFn:
		if svc.Metadata.SystemLabels == nil {
			svc.Metadata.SystemLabels = make(map[string]string)
		}

		svc.Metadata.SystemLabels[vutils.UpgradeIDKey] = idKey

		zap.L().Debug("Upgrading the Service idKey", zap.String("svc", svc.Metadata.Name))

		if _, err := g.octeliumC.CoreC().UpdateService(ctx, svc); err != nil {
			switch {
			case grpcerr.IsResourceChanged(err):
				zap.L().Debug("resourceChanged err. Trying again...", zap.Any("svc", svc))
				svc, err = g.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
					Uid: svc.Metadata.Uid,
				})
				if err != nil {
					zap.L().Warn("Could not upgrade Service idKey after resourceChanged err",
						zap.Any("svc", svc), zap.Error(err))
					continue
				}
				time.Sleep(100 * time.Millisecond)
				goto doFn
			case grpcerr.IsNotFound(err):
			default:
				zap.L().Warn("Could not upgrade Service idKey", zap.Any("svc", svc), zap.Error(err))
				continue
			}
		}
	}

	zap.L().Debug("updateServicesUpgradeUID done")

	return nil
}

func (g *Genesis) getAllServices(ctx context.Context, rgn *corev1.Region) ([]*corev1.Service, error) {
	var ret []*corev1.Service

	hasMore := true
	page := 0
	for hasMore {
		svcList, err := g.octeliumC.CoreC().ListService(ctx, &rmetav1.ListOptions{
			Paginate:     true,
			Page:         uint32(page),
			ItemsPerPage: 500,
			Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldEQValStr("status.regionRef.uid", rgn.Metadata.Uid),
			},
		})
		if err != nil {
			return nil, err
		}

		ret = append(ret, svcList.Items...)

		if svcList.ListResponseMeta != nil {
			hasMore = svcList.ListResponseMeta.HasMore

			if hasMore {
				page += 1
				zap.L().Debug("The list of Services has more pages", zap.Any("meta", svcList.ListResponseMeta))
			}
		} else {
			hasMore = false
		}
	}

	return ret, nil
}
