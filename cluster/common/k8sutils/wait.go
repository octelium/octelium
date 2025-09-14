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

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
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

	doCheck := func() (bool, error) {
		dep, err := k8sC.AppsV1().Deployments(ns).Get(ctx, name, k8smetav1.GetOptions{})
		if err != nil {
			return false, err
		}

		newReplicaSet, err := GetNewReplicaSet(dep, k8sC.AppsV1())
		if err != nil || newReplicaSet == nil {
			return false, err
		}

		return deploymentReady(newReplicaSet, dep), nil
	}

	for i := 0; i < 10000; i++ {
		isDone, err := doCheck()
		if err != nil && !shouldRetry(err) {
			return err
		}

		if isDone {
			return nil
		}

		zap.L().Debug("Deployment is not ready",
			zap.String("deployment", name), zap.String("namespace", ns), zap.Int("attempt", i+1))

		time.Sleep(2 * time.Second)
	}
	return errors.Errorf("deployment: %s is still not ready", name)
}

func WaitReadinessDeployment(ctx context.Context, k8sC kubernetes.Interface, name string) error {
	return WaitReadinessDeploymentWithNS(ctx, k8sC, name, vutils.K8sNS)
}

func shouldRetry(err error) bool {
	return k8serr.IsConflict(err) ||
		k8serr.IsServerTimeout(err) ||
		k8serr.IsUnexpectedServerError(err) ||
		k8serr.IsTooManyRequests(err) ||
		k8serr.IsTimeout(err)
}

func ShouldRetry(err error) bool {
	return shouldRetry(err)
}

func WaitReadinessDaemonsetWithNS(ctx context.Context, k8sC kubernetes.Interface, name, ns string) error {
	if ldflags.IsTest() {
		return nil
	}

	doCheck := func() (bool, error) {
		dep, err := k8sC.AppsV1().DaemonSets(ns).Get(ctx, name, k8smetav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if dep.Status.NumberReady == dep.Status.DesiredNumberScheduled {
			return true, nil
		}

		return false, nil
	}

	for {
		isDone, err := doCheck()
		if err != nil && !shouldRetry(err) {
			return err
		}

		if isDone {
			return nil
		}

		zap.L().Debug("Daemonset is still not ready, trying again...", zap.String("name", name))

		time.Sleep(2 * time.Second)
	}
}

func WaitForNodesReadiness(ctx context.Context, k8sC kubernetes.Interface) error {
	if ldflags.IsTest() {
		return nil
	}

	zap.L().Debug("Checking for nodes to become ready...")

	doCheck := func() (bool, error) {
		nodes, err := k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{})
		if err != nil {
			return false, err
		}
		if len(nodes.Items) == 0 {
			zap.L().Warn("No nodes available! Trying again...")
			return false, nil
		}
		for _, node := range nodes.Items {
			for _, condition := range node.Status.Conditions {
				if condition.Type == "Ready" && condition.Status != "True" {
					zap.L().Info("Node is not ready yet...", zap.String("node", node.Name))
					return false, nil
				}
			}
		}

		zap.L().Debug("All nodes are ready...")
		return true, nil
	}

	for i := 0; i < 1500; i++ {
		isReady, err := doCheck()
		if err != nil {
			return err
		}
		if isReady {
			return nil
		}

		time.Sleep(3 * time.Second)
	}

	return errors.Errorf("Could not check of all Kubernetes node readiness")
}
