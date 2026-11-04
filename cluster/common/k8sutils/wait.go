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
	"github.com/pkg/errors"
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

	doCheck := func(ctx context.Context) (bool, error) {
		dep, err := k8sC.AppsV1().Deployments(ns).Get(ctx, name, k8smetav1.GetOptions{})
		if err != nil {
			return false, err
		}

		return deploymentReadiness(dep)
	}

	return WaitReadiness(ctx, 2*time.Second, 20000*time.Second, doCheck)

}

func deploymentReadiness(dep *appsv1.Deployment) (bool, error) {
	if dep == nil || dep.DeletionTimestamp != nil || dep.Status.ObservedGeneration < dep.Generation {
		return false, nil
	}
	replicas := int32(1)
	if dep.Spec.Replicas != nil {
		replicas = *dep.Spec.Replicas
	}
	if dep.Status.UpdatedReplicas == replicas && dep.Status.Replicas == replicas && dep.Status.AvailableReplicas == replicas {
		return true, nil
	}
	if !dep.Spec.Paused {
		for _, condition := range dep.Status.Conditions {
			if condition.Type == appsv1.DeploymentProgressing && condition.Status == k8scorev1.ConditionFalse && condition.Reason == "ProgressDeadlineExceeded" {
				return false, errors.Errorf("Deployment %s/%s exceeded its progress deadline: %s", dep.Namespace, dep.Name, condition.Message)
			}
		}
	}
	return false, nil
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

		return IsDaemonSetReady(dep), nil
	}

	return WaitReadiness(ctx, 2*time.Second, 20000*time.Second, doCheck)

}

func IsDaemonSetReady(ds *appsv1.DaemonSet) bool {
	if ds == nil || ds.DeletionTimestamp != nil || ds.Status.ObservedGeneration == 0 || ds.Status.ObservedGeneration < ds.Generation {
		return false
	}
	desired := ds.Status.DesiredNumberScheduled
	if ds.Status.NumberReady != desired || ds.Status.NumberAvailable != desired {
		return false
	}
	return ds.Spec.UpdateStrategy.Type == appsv1.OnDeleteDaemonSetStrategyType || ds.Status.UpdatedNumberScheduled == desired
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
