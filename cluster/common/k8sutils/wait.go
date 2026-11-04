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

package k8sutils

import (
	"context"
	"time"

	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func WaitReadinessDeploymentWithNS(ctx context.Context, k8sC kubernetes.Interface, name string, ns string) error {
	if ldflags.IsTest() {
		return nil
	}

	zap.L().Debug("Checking readiness for deployment",
		zap.String("deployment", name), zap.String("namespace", ns))

	deploymentReady := func(rs *appsv1.ReplicaSet, dep *appsv1.Deployment) bool {
		expectedReady := *dep.Spec.Replicas - MaxUnavailable(*dep)
		if !(rs.Status.ReadyReplicas >= expectedReady) {
			return false
		}
		return true
	}

	doCheck := func(ctx context.Context) (bool, error) {
		dep, err := k8sC.AppsV1().Deployments(ns).Get(ctx, name, k8smetav1.GetOptions{})
		if err != nil {
			return false, err
		}

		newReplicaSet, err := GetNewReplicaSetWithContext(ctx, dep, k8sC.AppsV1())
		if err != nil || newReplicaSet == nil {
			return false, err
		}

		return deploymentReady(newReplicaSet, dep), nil
	}

	return WaitReadiness(ctx, 2*time.Second, 20000*time.Second, doCheck)

}

func WaitReadinessDeployment(ctx context.Context, k8sC kubernetes.Interface, name string) error {
	return WaitReadinessDeploymentWithNS(ctx, k8sC, name, vutils.K8sNS)
}

func shouldRetry(err error) bool {
	return k8serr.IsConflict(err) || k8sretry.IsTransient(err)
}

func ShouldRetry(err error) bool {
	return shouldRetry(err)
}

func WaitReadinessDaemonsetWithNS(ctx context.Context, k8sC kubernetes.Interface, name, ns string) error {
	if ldflags.IsTest() {
		return nil
	}

	doCheck := func(ctx context.Context) (bool, error) {
		dep, err := k8sC.AppsV1().DaemonSets(ns).Get(ctx, name, k8smetav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if dep.Status.NumberReady == dep.Status.DesiredNumberScheduled {
			return true, nil
		}

		return false, nil
	}

	return WaitReadiness(ctx, 2*time.Second, 20000*time.Second, doCheck)

}

func WaitForNodesReadiness(ctx context.Context, k8sC kubernetes.Interface) error {
	if ldflags.IsTest() {
		return nil
	}

	zap.L().Debug("Checking for nodes to become ready...")

	doCheck := func(ctx context.Context) (bool, error) {
		nodes, err := k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{})
		if err != nil {
			return false, err
		}
		if len(nodes.Items) == 0 {
			zap.L().Warn("No nodes available! Trying again...")
			return false, nil
		}
		for _, node := range nodes.Items {
			isReady := false
			for _, condition := range node.Status.Conditions {
				if condition.Type == k8scorev1.NodeReady {
					isReady = condition.Status == k8scorev1.ConditionTrue
					break
				}
			}
			if !isReady {
				zap.L().Info("Node is not ready yet...", zap.String("node", node.Name))
				return false, nil
			}
		}

		zap.L().Debug("All nodes are ready...")
		return true, nil
	}

	return WaitReadiness(ctx, 3*time.Second, 4500*time.Second, doCheck)
}

func WaitReadiness(ctx context.Context, interval, timeout time.Duration, check func(context.Context) (bool, error)) error {
	return k8sretry.Wait(ctx, interval, timeout, func(ctx context.Context) (bool, error) {
		ready, err := check(ctx)
		if k8serr.IsNotFound(err) {
			return false, nil
		}
		return ready, err
	})
}
