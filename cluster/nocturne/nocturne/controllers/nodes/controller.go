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

package nodecontroller

import (
	"context"
	"slices"

	"go.uber.org/zap"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"

	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/grpcerr"

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	corev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewController(
	k8sC kubernetes.Interface,
	octeliumC octeliumc.ClientInterface,
	nodeInformer coreinformers.NodeInformer) {

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			ctx := context.Background()

			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}

			if err := taintNode(ctx, k8sC, octeliumC, node); err != nil {
				zap.L().Warn("Could not taint Gateway node",
					zap.String("node", node.Name), zap.Error(err))
			}

			if err := untaintNode(ctx, k8sC, node); err != nil {
				zap.L().Warn("Could not untaint Gateway node",
					zap.String("node", node.Name), zap.Error(err))
			}
		},

		UpdateFunc: func(old, new any) {

			ctx := context.Background()

			oldNode, ok := old.(*corev1.Node)
			if !ok {
				return
			}
			newNode, ok := new.(*corev1.Node)
			if !ok {
				return
			}

			if oldNode.ResourceVersion == newNode.ResourceVersion {
				return
			}

			if err := taintNode(ctx, k8sC, octeliumC, newNode); err != nil {
				zap.L().Warn("Could not taint Gateway node",
					zap.String("node", newNode.Name), zap.Error(err))
			}

			if err := untaintNode(ctx, k8sC, newNode); err != nil {
				zap.L().Warn("Could not untaint Gateway node",
					zap.String("node", newNode.Name), zap.Error(err))
			}

		},

		DeleteFunc: func(obj any) {
			ctx := context.Background()

			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}

			if err := deleteGWs(ctx, octeliumC, node); err != nil {
				zap.L().Warn("Could not deleteGWs", zap.String("node", node.Name), zap.Error(err))
			}
		},
	})
}

func deleteGWs(ctx context.Context, octeliumC octeliumc.ClientInterface, node *corev1.Node) error {
	gwList, err := octeliumC.CoreC().ListGateway(ctx, &rmetav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, gw := range gwList.Items {
		if gw.Status.NodeRef != nil && gw.Status.NodeRef.Uid == string(node.UID) {
			zap.L().Debug("Deleting Gateway after node deletion",
				zap.String("gw", gw.Metadata.Name), zap.String("node", node.Name))
			if _, err := octeliumC.CoreC().DeleteGateway(ctx, &rmetav1.DeleteOptions{Uid: gw.Metadata.Uid}); err != nil {
				if grpcerr.IsNotFound(err) {
					continue
				}

				return err
			}
		}
	}

	return nil
}

func hasGateway(ctx context.Context, octeliumC octeliumc.ClientInterface, n *corev1.Node) (bool, error) {
	gwList, err := octeliumC.CoreC().ListGateway(ctx, &rmetav1.ListOptions{})
	if err != nil {
		return false, err
	}

	for _, gw := range gwList.Items {
		if gw.Status.NodeRef != nil && gw.Status.NodeRef.Uid == string(n.UID) {
			return true, nil
		}
	}

	return false, nil
}

// taintNode sets the gateway-init taint on a data-plane node whose Gateway Agent
// has not registered yet, so that the k8s scheduler defers scheduling Service
// pods on it until the Multus CNI conf needed by those pods has been written.
// The taint is removed by the Gateway Agent itself once the Gateway is ready.
//
// Genesis only taints the data-plane nodes that exist at installation time. This
// covers the data-plane nodes that are added afterwards during runtime, whether
// manually or by a cluster autoscaler.
//
// Nodes that additionally serve as control-plane nodes are skipped since the
// Cluster's own control-plane components do not tolerate the taint.
func taintNode(ctx context.Context, k8sC kubernetes.Interface,
	octeliumC octeliumc.ClientInterface, n *corev1.Node) error {

	if _, ok := n.Labels[vutils.NodeLabelDataPlane]; !ok {
		return nil
	}

	if _, ok := n.Labels[vutils.NodeLabelControlPlane]; ok {
		return nil
	}

	if n.Labels[vutils.NodeLabelGatewayRegistered] == "true" {
		return nil
	}

	if slices.ContainsFunc(n.Spec.Taints, func(taint corev1.Taint) bool {
		return taint.Key == vutils.NodeTaintGatewayInit
	}) {
		return nil
	}

	hasGW, err := hasGateway(ctx, octeliumC, n)
	if err != nil {
		return err
	}
	if hasGW {
		return nil
	}

	zap.L().Info("Setting the gateway-init taint on the newly added data-plane node",
		zap.String("node", n.Name))

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := k8sC.CoreV1().Nodes().Get(ctx, n.Name, k8smetav1.GetOptions{})
		if err != nil {
			return err
		}

		if slices.ContainsFunc(node.Spec.Taints, func(taint corev1.Taint) bool {
			return taint.Key == vutils.NodeTaintGatewayInit
		}) {
			return nil
		}

		node.Spec.Taints = append(node.Spec.Taints, corev1.Taint{
			Key:    vutils.NodeTaintGatewayInit,
			Value:  "true",
			Effect: corev1.TaintEffectNoSchedule,
		})

		_, err = k8sC.CoreV1().Nodes().Update(ctx, node, k8smetav1.UpdateOptions{})
		return err
	})
}

func untaintNode(ctx context.Context, k8sC kubernetes.Interface, n *corev1.Node) error {

	if n.Labels[vutils.NodeLabelGatewayRegistered] != "true" {
		return nil
	}

	if !slices.ContainsFunc(n.Spec.Taints, func(taint corev1.Taint) bool {
		return taint.Key == vutils.NodeTaintGatewayInit
	}) {
		return nil
	}

	zap.L().Info("Removing the gateway-init taint, most probably added by the cloud provider",
		zap.String("node", n.Name))

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := k8sC.CoreV1().Nodes().Get(ctx, n.Name, k8smetav1.GetOptions{})
		if err != nil {
			return err
		}

		taints := slices.DeleteFunc(slices.Clone(node.Spec.Taints),
			func(taint corev1.Taint) bool {
				return taint.Key == vutils.NodeTaintGatewayInit
			})

		if len(taints) == len(node.Spec.Taints) {
			return nil
		}

		node.Spec.Taints = taints

		_, err = k8sC.CoreV1().Nodes().Update(ctx, node, k8smetav1.UpdateOptions{})
		return err
	})
}
