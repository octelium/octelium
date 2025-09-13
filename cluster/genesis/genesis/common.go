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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/components"
	"k8s.io/client-go/kubernetes"
)

func (g *Genesis) installComponents(ctx context.Context, region *corev1.Region) error {
	regionName := region.Metadata.Name
	clusterCfg, err := g.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	region, err = g.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{Name: regionName})
	if err != nil {
		return err
	}

	{
		err = components.CreateGatewayAgent(ctx, g.k8sC, clusterCfg, region)
		if err != nil {
			return err
		}

		if err := waitGatewayAgentReady(ctx, g.k8sC); err != nil {
			return err
		}
	}

	{
		err = components.CreateNocturne(ctx, g.k8sC, clusterCfg, region)
		if err != nil {
			return err
		}

		if err := k8sutils.WaitReadinessDeployment(ctx, g.k8sC, "octelium-nocturne"); err != nil {
			return err
		}
	}
	{
		if err := components.CreateOctovigil(ctx, g.k8sC, clusterCfg); err != nil {
			return err
		}

		if err := k8sutils.WaitReadinessDeployment(ctx, g.k8sC, "octelium-octovigil"); err != nil {
			return err
		}
	}

	if err := components.CreateIngress(ctx, g.k8sC, clusterCfg, region); err != nil {
		return err
	}

	if err := components.InstallCommon(ctx, g.k8sC, clusterCfg, region); err != nil {
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
