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
	"strings"
	"time"

	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/pkg/errors"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var errGenesisBusy = errors.New("Another genesis operation is still running")

func genesisPodNamespace() (string, error) {
	if namespace := os.Getenv("OCTELIUM_GENESIS_POD_NAMESPACE"); namespace != "" {
		return namespace, nil
	}
	data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (g *Genesis) loadPodIdentity(ctx context.Context) error {
	name := os.Getenv("OCTELIUM_GENESIS_POD_NAME")
	if name == "" {
		var err error
		name, err = os.Hostname()
		if err != nil {
			return err
		}
	}
	pod, err := g.k8sC.CoreV1().Pods(g.podNamespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		g.pod = pod
	}
	return err
}

func isTransientGenesisError(err error) bool {
	return k8sretry.IsTransient(err)
}

func (g *Genesis) waitForConcurrentGenesis(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var lastErr error
	err := k8sretry.Wait(ctx, 500*time.Millisecond, 2*time.Minute, func(ctx context.Context) (bool, error) {
		if g.pod == nil && g.podNamespace != "" {
			lastErr = g.loadPodIdentity(ctx)
			if lastErr != nil {
				return false, lastErr
			}
		}
		lastErr = g.checkConcurrentGenesis(ctx)
		if lastErr == nil {
			return true, nil
		}
		if errors.Is(lastErr, errGenesisBusy) {
			return false, nil
		}
		return false, lastErr
	})
	if err != nil && lastErr != nil {
		return errors.Wrapf(err, "Could not verify genesis concurrency: %s", lastErr)
	}
	return err
}

func (g *Genesis) checkConcurrentGenesis(ctx context.Context) error {
	var own *metav1.OwnerReference
	if g.pod != nil {
		pod, err := g.k8sC.CoreV1().Pods(g.pod.Namespace).Get(ctx, g.pod.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if pod.UID != g.pod.UID || pod.DeletionTimestamp != nil || pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
			return errors.Errorf("This genesis Pod is terminating or no longer owns its Pod identity")
		}
		own = metav1.GetControllerOf(pod)
		if own == nil || own.Kind != "Job" {
			return errors.Errorf("Genesis must run as a Kubernetes Job")
		}
		job, err := g.k8sC.BatchV1().Jobs(pod.Namespace).Get(ctx, own.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if job.UID != own.UID || job.DeletionTimestamp != nil || (job.Spec.Suspend != nil && *job.Spec.Suspend) {
			return errors.Errorf("This genesis Job is suspended, terminating or has been replaced")
		}
		for _, condition := range job.Status.Conditions {
			if (condition.Type == batchv1.JobComplete || condition.Type == batchv1.JobFailed) && condition.Status == corev1.ConditionTrue {
				return errors.Errorf("This genesis Job has already finished")
			}
		}
	}
	for _, namespace := range []string{"default", "octelium"} {
		pods, err := g.k8sC.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "octelium.com/component=genesis"})
		if err != nil {
			return err
		}
		for _, pod := range pods.Items {
			if g.pod != nil && pod.UID == g.pod.UID && pod.Namespace == g.pod.Namespace && pod.Name == g.pod.Name {
				continue
			}
			if pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed {
				return errors.Wrapf(errGenesisBusy, "Genesis Pod %s/%s may still be running", pod.Namespace, pod.Name)
			}
		}
		jobs, err := g.k8sC.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{LabelSelector: "octelium.com/component=genesis"})
		if err != nil {
			return err
		}
		for _, job := range jobs.Items {
			if own != nil && g.pod.Namespace == namespace && own.Name == job.Name && own.UID == job.UID {
				continue
			}
			if job.Spec.Suspend != nil && *job.Spec.Suspend {
				continue
			}
			completions := int32(1)
			if job.Spec.Completions != nil {
				completions = *job.Spec.Completions
			}
			if job.Status.Active == 0 && job.Status.Succeeded > 0 && job.Status.Succeeded >= completions {
				continue
			}
			finished := false
			for _, condition := range job.Status.Conditions {
				if (condition.Type == batchv1.JobComplete || condition.Type == batchv1.JobFailed) && condition.Status == corev1.ConditionTrue {
					finished = true
				}
			}
			if !finished {
				return errors.Wrapf(errGenesisBusy, "Genesis Job %s/%s is still active", job.Namespace, job.Name)
			}
		}
	}
	return nil
}
