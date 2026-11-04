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
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

type UpgradeOpts struct{}

func (g *Genesis) RunUpgrade(ctx context.Context, o *UpgradeOpts) error {
	if err := g.waitForConcurrentGenesis(ctx); err != nil {
		return err
	}

	zap.L().Info("Starting upgrade...")
	if o == nil {
		o = &UpgradeOpts{}
	}

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
	regionV, err := g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Name: regionName})
	if err != nil {
		return err
	}
	if err := g.validateUpgradeTarget(ctx, initResources, clusterCfg, regionV); err != nil {
		return err
	}
	if err := g.reconcileInstallationTarget(ctx, clusterCfg, regionV, true); err != nil {
		return err
	}
	os.Setenv("OCTELIUM_REGION_NAME", regionName)

	zap.L().Debug("upgrading rscServer")

	if err := components.CreateRscServer(ctx, &components.CommonOpts{
		K8sC:          g.k8sC,
		ClusterConfig: clusterCfg,
	}); err != nil {
		return err
	}

	zap.L().Debug("waiting for readiness of rscServer")

	if err := checkRscServer(ctx, g.k8sC); err != nil {
		return err
	}

	zap.L().Debug("Installing components")

	if err := g.installComponents(ctx,
		regionV, &components.CommonOpts{
			K8sC:          g.k8sC,
			ClusterConfig: clusterCfg,
		}); err != nil {
		return err
	}

	isDefaultRegion := ucorev1.ToRegion(regionV).IsDefault()

	if isDefaultRegion {
		if err := g.upgradeClusterResources(ctx, clusterCfg, regionV); err != nil {
			return err
		}
	} else {
		zap.L().Debug("Skipping upgrading the Cluster resources outside the default Region",
			zap.String("region", regionName))
	}

	if err := g.updateServicesUpgradeUID(ctx, regionV); err != nil {
		return err
	}

	if isDefaultRegion {
		if err := g.doPostUpgrade(ctx); err != nil {
			return err
		}
	}

	if err := g.finishUpgrade(ctx, regionV.Metadata.Uid); err != nil {
		return err
	}

	zap.L().Info("Upgrade successfully completed...")

	return nil
}

func (g *Genesis) upgradeClusterResources(ctx context.Context, clusterCfg *corev1.ClusterConfig, region *corev1.Region) error {
	if err := g.installOcteliumResources(ctx, clusterCfg, region, false); err != nil {
		return err
	}

	if err := retryUpgrade(ctx, g.createSSHServiceSeedSecret); err != nil {
		return errors.Wrap(err, "Could not ensure SSH Service seed")
	}

	return nil
}

func (g *Genesis) updateServicesUpgradeUID(ctx context.Context, rgn *corev1.Region) error {

	zap.L().Debug("Starting updateServicesUpgradeUID")
	svcList, err := g.getAllServices(ctx, rgn)
	if err != nil {
		return errors.Wrap(err, "Could not list Services for upgrade")
	}

	idKey := utilrand.GetRandomStringCanonical(12)
	if g.pod != nil {
		if owner := k8smetav1.GetControllerOf(g.pod); owner != nil && owner.Kind == "Job" && owner.UID != "" {
			idKey = string(owner.UID)
		}
	}
	zap.L().Debug("Starting upgrading Region's Services via idKey",
		zap.Int("len", len(svcList)), zap.String("idKey", idKey))

	for _, svc := range svcList {
		zap.L().Debug("Upgrading the Service idKey", zap.String("svc", svc.Metadata.Name))

		err := retryUpgrade(ctx, func(ctx context.Context) error {
			current, err := g.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			if grpcerr.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if current.GetStatus().GetRegionRef().GetUid() != rgn.Metadata.Uid || current.Metadata.SystemLabels[vutils.UpgradeIDKey] == idKey {
				return nil
			}
			current = proto.Clone(current).(*corev1.Service)
			if current.Metadata.SystemLabels == nil {
				current.Metadata.SystemLabels = make(map[string]string)
			}
			current.Metadata.SystemLabels[vutils.UpgradeIDKey] = idKey
			_, err = g.octeliumC.CoreC().UpdateService(ctx, current)
			if grpcerr.IsNotFound(err) {
				return nil
			}
			return err
		})
		if err != nil {
			return errors.Wrapf(err, "Could not update upgrade marker for Service %s", svc.Metadata.Name)
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
		var svcList *corev1.ServiceList
		err := retryUpgrade(ctx, func(ctx context.Context) error {
			var err error
			svcList, err = g.octeliumC.CoreC().ListService(ctx, &rmetav1.ListOptions{
				Paginate:     true,
				Page:         uint32(page),
				ItemsPerPage: 500,
				Filters: []*rmetav1.ListOptions_Filter{
					urscsrv.FilterFieldEQValStr("status.regionRef.uid", rgn.Metadata.Uid),
				},
			})
			return err
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

func (g *Genesis) doPostUpgrade(ctx context.Context) error {
	var authnList *corev1.AuthenticatorList
	if err := retryUpgrade(ctx, func(ctx context.Context) error {
		var err error
		authnList, err = g.octeliumC.CoreC().ListAuthenticator(ctx, &rmetav1.ListOptions{})
		return err
	}); err != nil {
		return errors.Wrap(err, "Could not list Authenticators for upgrade")
	}

	for _, itm := range authnList.Items {
		if itm.GetSpec().GetState() != corev1.Authenticator_Spec_STATE_UNKNOWN {
			continue
		}
		err := retryUpgrade(ctx, func(ctx context.Context) error {
			current, err := g.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{Uid: itm.Metadata.Uid})
			if grpcerr.IsNotFound(err) {
				return nil
			}
			if err != nil {
				return err
			}
			if current.GetSpec().GetState() != corev1.Authenticator_Spec_STATE_UNKNOWN {
				return nil
			}
			current = proto.Clone(current).(*corev1.Authenticator)
			if current.Spec == nil {
				current.Spec = &corev1.Authenticator_Spec{}
			}
			current.Spec.State = corev1.Authenticator_Spec_ACTIVE
			_, err = g.octeliumC.CoreC().UpdateAuthenticator(ctx, current)
			if grpcerr.IsNotFound(err) {
				return nil
			}
			return err
		})
		if err != nil {
			return errors.Wrapf(err, "Could not migrate Authenticator %s", itm.Metadata.Name)
		}
	}

	return nil
}

func (g *Genesis) finishUpgrade(ctx context.Context, regionUID string) error {
	versionInfo := &corev1.Region_Status_VersionInfo{
		Package: "octelium",
		SetAt:   pbutils.Now(),
		Version: ldflags.GetVersion(),
		Id:      os.Getenv("OCTELIUM_INSTALL_ID"),
	}
	err := retryUpgrade(ctx, func(ctx context.Context) error {
		region, err := g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Uid: regionUID})
		if err != nil {
			return err
		}
		updated := proto.Clone(region).(*corev1.Region)
		if updated.Status == nil {
			updated.Status = &corev1.Region_Status{}
		}
		updated.Status.Version = versionInfo.Version
		if updated.Status.VersionInfoMap == nil {
			updated.Status.VersionInfoMap = make(map[string]*corev1.Region_Status_VersionInfo)
		}
		updated.Status.VersionInfoMap["octelium"] = versionInfo
		vutils.SetRegionPublicHostName(updated)
		if proto.Equal(region, updated) {
			return nil
		}
		_, err = g.octeliumC.CoreC().UpdateRegion(ctx, updated)
		return err
	})
	return errors.Wrap(err, "Could not publish upgraded Region version")
}

func retryUpgrade(ctx context.Context, fn func(context.Context) error) error {
	var lastErr error
	err := wait.ExponentialBackoffWithContext(ctx, retry.DefaultRetry, func(ctx context.Context) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		lastErr = fn(ctx)
		if lastErr == nil {
			return true, nil
		}
		switch status.Code(lastErr) {
		case codes.OutOfRange, codes.Unavailable, codes.ResourceExhausted, codes.Aborted, codes.DeadlineExceeded:
			return false, nil
		}
		if errors.Is(lastErr, context.DeadlineExceeded) {
			return false, nil
		}
		return false, lastErr
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil && lastErr != nil {
		return lastErr
	}
	return err
}
