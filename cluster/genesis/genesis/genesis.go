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

	nadclientset "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Genesis struct {
	k8sC             kubernetes.Interface
	octeliumC        octeliumc.ClientInterface
	nadC             nadclientset.Interface
	initializationID string
	inputBindingKey  []byte
	rscServer        *rscserver.Server
	pod              *k8scorev1.Pod
	podNamespace     string
}

func NewGenesis() (*Genesis, error) {
	ret := &Genesis{}

	cfg, err := k8sutils.GetInClusterConfig()
	if err != nil {
		return nil, err
	}

	k8sClientSet, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	nadC, err := nadclientset.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	ret.k8sC = k8sClientSet
	ret.nadC = nadC
	ret.podNamespace, err = genesisPodNamespace()
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (g *Genesis) RemoveAll(ctx context.Context) error {

	err := g.deleteNamespaces(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (g *Genesis) deleteNamespaces(ctx context.Context) error {
	err := g.k8sC.CoreV1().Namespaces().Delete(ctx, vutils.K8sNS, k8smetav1.DeleteOptions{})
	if err != nil && !k8serr.IsNotFound(err) {
		return err
	}
	return nil
}

func (g *Genesis) initRegion(cr *LoadedClusterResource) (*corev1.Region, error) {

	if cr.Region != nil {
		region := cr.Region

		if region.Metadata == nil {
			region.Metadata = &metav1.Metadata{
				Name: "default",
			}
		}
		region.Metadata.IsSystem = true
		if region.Metadata.Name == "" {
			region.Metadata.Name = "default"
		}

		if region.Spec == nil {
			region.Spec = &corev1.Region_Spec{}
		}
		if region.Status == nil {
			region.Status = &corev1.Region_Status{}
		}
		region.Status.Version = ldflags.GetVersion()
		region.Status.VersionInfoMap = make(map[string]*corev1.Region_Status_VersionInfo)
		region.Status.VersionInfoMap["octelium"] = &corev1.Region_Status_VersionInfo{
			Package: "octelium",
			SetAt:   pbutils.Now(),
			Version: ldflags.GetVersion(),
		}

		zap.L().Debug("Initialized Region from loaded init", zap.Any("region", region))

		return region, nil
	}

	ret := &corev1.Region{
		Metadata: &metav1.Metadata{
			Name:     "default",
			IsSystem: true,
		},
		Spec: &corev1.Region_Spec{},
		Status: &corev1.Region_Status{

			Version: ldflags.GetVersion(),
		},
	}

	zap.L().Debug("Initialized Region", zap.Any("region", ret))

	return ret, nil
}

func (g *Genesis) createPostgresSecret(ctx context.Context, dataMap map[string][]byte) error {
	zap.L().Debug("Creating postgres k8s secret")
	return g.createStorageSecret(ctx, &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      "octelium-postgres",
			Namespace: vutils.K8sNS,
		},
		Data: dataMap,
	})
}

func (g *Genesis) createRedisSecret(ctx context.Context, dataMap map[string][]byte) error {
	zap.L().Debug("Creating redis k8s secret")
	return g.createStorageSecret(ctx, &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      "octelium-redis",
			Namespace: vutils.K8sNS,
		},
		Data: dataMap,
	})
}

type LoadedClusterResource struct {
	Bootstrap *cbootstrapv1.Config
	Region    *corev1.Region
	Domain    string
}

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
	pod, err := g.k8sC.CoreV1().Pods(g.podNamespace).Get(ctx, name, k8smetav1.GetOptions{})
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
	var own *k8smetav1.OwnerReference
	if g.pod != nil {
		pod, err := g.k8sC.CoreV1().Pods(g.pod.Namespace).Get(ctx, g.pod.Name, k8smetav1.GetOptions{})
		if err != nil {
			return err
		}
		if pod.UID != g.pod.UID || pod.DeletionTimestamp != nil || pod.Status.Phase == k8scorev1.PodSucceeded || pod.Status.Phase == k8scorev1.PodFailed {
			return errors.Errorf("This genesis Pod is terminating or no longer owns its Pod identity")
		}
		own = k8smetav1.GetControllerOf(pod)
		if own == nil || own.Kind != "Job" {
			return errors.Errorf("Genesis must run as a Kubernetes Job")
		}
		job, err := g.k8sC.BatchV1().Jobs(pod.Namespace).Get(ctx, own.Name, k8smetav1.GetOptions{})
		if err != nil {
			return err
		}
		if job.UID != own.UID || job.DeletionTimestamp != nil || (job.Spec.Suspend != nil && *job.Spec.Suspend) {
			return errors.Errorf("This genesis Job is suspended, terminating or has been replaced")
		}
		for _, condition := range job.Status.Conditions {
			if (condition.Type == batchv1.JobComplete || condition.Type == batchv1.JobFailed) && condition.Status == k8scorev1.ConditionTrue {
				return errors.Errorf("This genesis Job has already finished")
			}
		}
	}
	for _, namespace := range []string{"default", "octelium"} {
		pods, err := g.k8sC.CoreV1().Pods(namespace).List(ctx, k8smetav1.ListOptions{LabelSelector: "octelium.com/component=genesis"})
		if err != nil {
			return err
		}
		for _, pod := range pods.Items {
			if g.pod != nil && pod.UID == g.pod.UID && pod.Namespace == g.pod.Namespace && pod.Name == g.pod.Name {
				continue
			}
			if pod.Status.Phase != k8scorev1.PodSucceeded && pod.Status.Phase != k8scorev1.PodFailed {
				return errors.Wrapf(errGenesisBusy, "Genesis Pod %s/%s may still be running", pod.Namespace, pod.Name)
			}
		}
		jobs, err := g.k8sC.BatchV1().Jobs(namespace).List(ctx, k8smetav1.ListOptions{LabelSelector: "octelium.com/component=genesis"})
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
				if (condition.Type == batchv1.JobComplete || condition.Type == batchv1.JobFailed) && condition.Status == k8scorev1.ConditionTrue {
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

func (g *Genesis) getK8sSecret(ctx context.Context, namespace, name string) (*k8scorev1.Secret, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*k8scorev1.Secret, error) {
		return g.k8sC.CoreV1().Secrets(namespace).Get(ctx, name, k8smetav1.GetOptions{})
	})
}

func (g *Genesis) getK8sConfigMap(ctx context.Context, namespace, name string) (*k8scorev1.ConfigMap, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*k8scorev1.ConfigMap, error) {
		return g.k8sC.CoreV1().ConfigMaps(namespace).Get(ctx, name, k8smetav1.GetOptions{})
	})
}
