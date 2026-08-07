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
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/components"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
		zap.Bool("spiffe", opts.EnableSPIFFECSI),
		zap.Bool("ingressProxyMode", opts.EnableIngressFrontProxy))

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

	if err := components.CreateIngress(ctx, opts); err != nil {
		return err
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
	return k8sutils.WaitReadinessDaemonsetWithNS(ctx, k8sC, "octelium-gwagent", "octelium")
}

func waitGatewayAgentsRegistered(ctx context.Context, k8sC kubernetes.Interface) error {
	if ldflags.IsTest() {
		return nil
	}

	zap.L().Debug("Checking that all Gateway Agents are registered")

	doCheck := func() (bool, error) {
		nodeList, err := k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{
			LabelSelector: vutils.NodeLabelDataPlane,
		})
		if err != nil {
			return false, err
		}

		if len(nodeList.Items) == 0 {
			return false, errors.Errorf(
				"No Kubernetes node is labeled as an Octelium data-plane node. At least one node must be labeled via: kubectl label nodes <NODE_NAME> %s=",
				vutils.NodeLabelDataPlane)
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

	for i := range 900 {
		isDone, err := doCheck()
		if err != nil && !k8sutils.ShouldRetry(err) {
			return err
		}

		if isDone {
			return nil
		}

		zap.L().Debug("Gateway Agents are still not registered on all data-plane nodes. Trying again...",
			zap.Int("attempt", i+1))

		time.Sleep(2 * time.Second)
	}

	return errors.Errorf("Timed out waiting for the Gateway Agents to be registered on all data-plane nodes")
}
