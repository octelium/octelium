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

	"go.uber.org/zap"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/octelium/octelium/cluster/common/octeliumc"
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

func untaintNode(ctx context.Context, k8sC kubernetes.Interface, n *corev1.Node) error {

	if n.Labels["octelium.com/gateway-registered"] != "true" {
		return nil
	}

	for i, taint := range n.Spec.Taints {
		if taint.Key == "octelium.com/gateway-init" {
			zap.L().Info("Removing the gateway-init, most probably added by the cloud provider",
				zap.String("node", n.Name))
			n.Spec.Taints = append(n.Spec.Taints[:i], n.Spec.Taints[i+1:]...)
			_, err := k8sC.CoreV1().Nodes().Update(ctx, n, k8smetav1.UpdateOptions{})
			if err != nil {
				return err
			}
		}
	}
	return nil
}
