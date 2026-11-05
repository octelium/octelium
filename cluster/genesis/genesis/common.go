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
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/components"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

func (g *Genesis) installComponents(ctx context.Context,
	region *corev1.Region, opts *components.CommonOpts,
) error {
	regionName := region.Metadata.Name
	clusterCfg, err := g.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	region, err = g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Name: regionName})
	if err != nil {
		return err
	}

	if opts == nil {
		opts = &components.CommonOpts{}
	}

	opts.OcteliumC = g.octeliumC
	opts.K8sC = g.k8sC
	opts.ClusterConfig = clusterCfg
	opts.Region = region

	zap.L().Debug("Starting installComponents",
		zap.Bool("spiffe", components.IsSPIFFEEnabled(opts)),
		zap.Bool("ingressProxyMode", components.IsIngressFrontProxyEnabled(opts)))

	{
		err = components.CreateGatewayAgent(ctx, opts)
		if err != nil {
			return err
		}

		if err := waitGatewayAgentReady(ctx, g.k8sC); err != nil {
			return err
		}

		if err := waitGatewayAgentsRegistered(ctx, g.k8sC); err != nil {
			return err
		}
	}

	{
		err = components.CreateNocturne(ctx, opts)
		if err != nil {
			return err
		}

		if err := k8sutils.WaitReadinessDeployment(ctx, g.k8sC, "octelium-nocturne"); err != nil {
			return err
		}
	}
	{
		if err := components.CreateOctovigil(ctx, opts); err != nil {
			return err
		}

		if err := k8sutils.WaitReadinessDeployment(ctx, g.k8sC, "octelium-octovigil"); err != nil {
			return err
		}
	}

	if ucorev1.ToRegion(region).IsDefault() {
		if err := components.CreateIngress(ctx, opts); err != nil {
			return err
		}
	}

	if err := components.InstallCommon(ctx, opts); err != nil {
		return err
	}

	return nil
}

func checkRscServer(ctx context.Context, k8sC kubernetes.Interface) error {
	return k8sutils.WaitReadinessDeployment(ctx, k8sC, "octelium-rscserver")
}

func waitForNodesReadiness(ctx context.Context, k8sC kubernetes.Interface) error {
	return k8sutils.WaitForNodesReadiness(ctx, k8sC)
}

func waitGatewayAgentReady(ctx context.Context, k8sC kubernetes.Interface) error {
	if ldflags.IsTest() {
		return nil
	}
	return k8sutils.WaitReadiness(ctx, 2*time.Second, 20000*time.Second, func(ctx context.Context) (bool, error) {
		ready, err := gatewayAgentReadiness(ctx, k8sC)
		if err != nil || ready {
			return ready, err
		}
		_, err = listDataPlaneNodes(ctx, k8sC)
		return false, err
	})
}

func gatewayAgentReadiness(ctx context.Context, k8sC kubernetes.Interface) (bool, error) {
	ds, err := k8sC.AppsV1().DaemonSets(vutils.K8sNS).Get(ctx, "octelium-gwagent", k8smetav1.GetOptions{})
	if err != nil {
		return false, err
	}
	return ds.Status.DesiredNumberScheduled > 0 && k8sutils.IsDaemonSetReady(ds), nil
}

func listDataPlaneNodes(ctx context.Context, k8sC kubernetes.Interface) (*k8scorev1.NodeList, error) {
	nodeList, err := k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{
		LabelSelector: vutils.NodeLabelDataPlane + "=",
	})
	if err != nil {
		return nil, err
	}

	if len(nodeList.Items) == 0 {
		return nil, errors.Errorf(
			"No Kubernetes node is labeled as an Octelium data-plane node. At least one node must be labeled via: kubectl label nodes <NODE_NAME> %s=",
			vutils.NodeLabelDataPlane)
	}

	return nodeList, nil
}

func waitGatewayAgentsRegistered(ctx context.Context, k8sC kubernetes.Interface) error {
	if ldflags.IsTest() {
		return nil
	}

	zap.L().Debug("Checking that all Gateway Agents are registered")

	doCheck := func(ctx context.Context) (bool, error) {
		ready, err := gatewayAgentReadiness(ctx, k8sC)
		if err != nil || !ready {
			return false, err
		}
		nodeList, err := listDataPlaneNodes(ctx, k8sC)
		if err != nil {
			return false, err
		}

		for _, node := range nodeList.Items {
			if node.Labels[vutils.NodeLabelGatewayRegistered] != "true" {
				zap.L().Debug("Gateway Agent is not registered yet on the data-plane node",
					zap.String("node", node.Name))
				return false, nil
			}
		}

		zap.L().Debug("All Gateway Agents are now registered",
			zap.Int("nodes", len(nodeList.Items)))

		return true, nil
	}

	return k8sutils.WaitReadiness(ctx, 2*time.Second, 1800*time.Second, doCheck)
}

func (g *Genesis) ensureNamespace(ctx context.Context, desired *corev1.Namespace) error {
	if desired.GetMetadata().GetName() == "" {
		return errors.Errorf("Namespace name is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	desired = proto.Clone(desired).(*corev1.Namespace)
	if desired.Spec == nil {
		desired.Spec = &corev1.Namespace_Spec{}
	}
	if desired.Status == nil {
		desired.Status = &corev1.Namespace_Status{}
	}
	_, err := createInitResource(ctx, desired, g.octeliumC.CoreC().GetNamespace, g.octeliumC.CoreC().CreateNamespace)
	return err
}

func (g *Genesis) ensureService(ctx context.Context, desired *corev1.Service) error {
	if desired.GetMetadata().GetName() == "" {
		return errors.Errorf("Service name is required")
	}
	desired = proto.Clone(desired).(*corev1.Service)
	if desired.Spec == nil {
		desired.Spec = &corev1.Service_Spec{}
	}
	if desired.Status == nil {
		desired.Status = &corev1.Service_Status{}
	}
	srv := admin.NewServer(&admin.Opts{OcteliumC: g.octeliumC, IsEmbedded: true})
	err := retry.OnError(retry.DefaultRetry, grpcerr.IsResourceChanged, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		created := false
		existing, err := createInitResource(ctx, desired, g.octeliumC.CoreC().GetService,
			func(ctx context.Context, service *corev1.Service, _ ...grpc.CallOption) (*corev1.Service, error) {
				result, err := srv.DoCreateService(ctx, service, service.Metadata.IsSystem)
				created = err == nil
				return result, err
			})
		if err != nil {
			return err
		}
		if created || !desired.Metadata.IsSystem {
			return nil
		}
		if !existing.GetMetadata().GetIsSystem() {
			return errors.Errorf("Service %s is not a system Service. Refusing to replace it", desired.Metadata.Name)
		}
		updated := proto.Clone(existing).(*corev1.Service)
		updated.Spec = proto.Clone(desired.Spec).(*corev1.Service_Spec)
		if updated.Status == nil {
			updated.Status = &corev1.Service_Status{}
		}
		updated.Status.ManagedService = nil
		if desired.Status.ManagedService != nil {
			updated.Status.ManagedService = proto.Clone(desired.Status.ManagedService).(*corev1.Service_Status_ManagedService)
		}
		mergeServiceMetadata(updated.Metadata, desired.Metadata)
		if proto.Equal(existing, updated) {
			return nil
		}
		_, err = g.octeliumC.CoreC().UpdateService(ctx, updated)
		return err
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func mergeServiceMetadata(existing, desired *metav1.Metadata) {
	if existing.DisplayName == "" {
		existing.DisplayName = desired.DisplayName
	}
	if existing.Description == "" {
		existing.Description = desired.Description
	}
	existing.IsUserHidden = desired.IsUserHidden
	existing.IsSystemHidden = desired.IsSystemHidden
	for key, value := range desired.SystemLabels {
		if existing.SystemLabels == nil {
			existing.SystemLabels = make(map[string]string)
		}
		existing.SystemLabels[key] = value
	}
}
