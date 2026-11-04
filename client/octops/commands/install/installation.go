// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package install

import (
	"context"
	"strings"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	ocorev1 "github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/client/octops/internal/k8sretry"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const octeliumNS = "octelium"
const installationConfigMapName = "octelium-installation"
const installationConfigMapKey = "installation.json"

type SPIFFEOpts struct {
	CSIDriver   string
	TrustDomain string
}

func spiffeFromBootstrap(bs *cbootstrapv1.Config) *SPIFFEOpts {
	spiffe := bs.GetSpec().GetSpiffe()
	if !spiffe.GetEnable() {
		return nil
	}

	return &SPIFFEOpts{
		CSIDriver:   spiffe.GetCsiDriver().GetName(),
		TrustDomain: spiffe.GetTrustDomain(),
	}
}

func GetSPIFFE(ctx context.Context, c kubernetes.Interface) *SPIFFEOpts {
	spiffe, err := GetSPIFFEWithError(ctx, c)
	if err != nil {
		zap.L().Debug("Could not get the installation ConfigMap. Assuming defaults", zap.Error(err))
	}
	return spiffe
}

func GetSPIFFEWithError(ctx context.Context, c kubernetes.Interface) (*SPIFFEOpts, error) {
	cm, err := getK8sConfigMap(ctx, c, octeliumNS, installationConfigMapName)
	if k8serr.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	val := cm.Data[installationConfigMapKey]
	if val == "" {
		return nil, errors.Errorf("The installation ConfigMap has no installation configuration")
	}
	installation := &ocorev1.ClusterConfig_Status_Installation{}
	if err := pbutils.UnmarshalJSON([]byte(val), installation); err != nil {
		return nil, errors.Wrap(err, "Invalid installation configuration")
	}
	spiffe := installation.GetSpiffe()
	if !spiffe.GetEnable() {
		return nil, nil
	}
	return &SPIFFEOpts{CSIDriver: spiffe.GetCsiDriver().GetName(), TrustDomain: spiffe.GetTrustDomain()}, nil
}

func (o *SPIFFEOpts) getCSIDriver() string {
	if o.CSIDriver != "" {
		return o.CSIDriver
	}
	return "csi.spiffe.io"
}

func checkExistingInstallation(ctx context.Context, c kubernetes.Interface) error {
	alreadyInstalled := errors.Errorf("An existing Cluster installation was found. Use octops upgrade instead of init")
	if _, err := getK8sSecret(ctx, c, octeliumNS, "init-token"); err == nil {
		return alreadyInstalled
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	if state, err := getK8sSecret(ctx, c, octeliumNS, "octelium-genesis-init"); err == nil {
		if state.Annotations["octelium.com/genesis-init-complete"] == "true" {
			return alreadyInstalled
		}
		return nil
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	if _, err := getK8sSecret(ctx, c, octeliumNS, "octelium-init"); err == nil {
		return alreadyInstalled
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	if _, err := getK8sConfigMap(ctx, c, octeliumNS, installationConfigMapName); err == nil {
		return alreadyInstalled
	} else if !k8serr.IsNotFound(err) {
		return err
	}
	return nil
}

func getK8sSecret(ctx context.Context, c kubernetes.Interface, namespace, name string) (*corev1.Secret, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*corev1.Secret, error) {
		return c.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}

func getK8sConfigMap(ctx context.Context, c kubernetes.Interface, namespace, name string) (*corev1.ConfigMap, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*corev1.ConfigMap, error) {
		return c.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}

func getK8sJob(ctx context.Context, c kubernetes.Interface, namespace, name string) (*batchv1.Job, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*batchv1.Job, error) {
		return c.BatchV1().Jobs(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}

const targetClusterUID = "octelium.com/genesis-cluster-uid"
const targetDomain = "octelium.com/genesis-domain"
const targetRegionUID = "octelium.com/genesis-region-uid"
const targetRegionName = "octelium.com/genesis-region-name"
const targetNamespaceUID = "octelium.com/genesis-namespace-uid"

func sameDomain(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func BindGenesisJobTarget(ctx context.Context, c kubernetes.Interface, desired *batchv1.Job) (*batchv1.Job, error) {
	if desired.Namespace != octeliumNS {
		return desired, nil
	}
	cm, err := getK8sConfigMap(ctx, c, octeliumNS, installationConfigMapName)
	if err != nil && !k8serr.IsNotFound(err) {
		return nil, err
	}
	annotations := map[string]string{}
	if cm != nil {
		annotations = cm.Annotations
	}
	bound := false
	for _, key := range []string{targetClusterUID, targetDomain, targetRegionUID, targetRegionName, targetNamespaceUID} {
		_, ok := annotations[key]
		bound = bound || ok
	}
	if bound {
		for _, key := range []string{targetClusterUID, targetDomain, targetRegionUID, targetRegionName, targetNamespaceUID} {
			if annotations[key] == "" {
				return nil, errors.Errorf("The Kubernetes installation identity is incomplete: %s", key)
			}
		}
	}
	domain, region := annotations[targetDomain], annotations[targetRegionName]
	bootstrap, err := getK8sSecret(ctx, c, octeliumNS, "octelium-init")
	if err == nil {
		if value := string(bootstrap.Data["domain"]); value != "" {
			if domain != "" && !sameDomain(domain, value) {
				return nil, errors.Errorf("The bootstrap domain does not match the Kubernetes installation identity")
			}
			domain = value
		}
		if data, ok := bootstrap.Data["region"]; ok {
			stored := &ocorev1.Region{}
			if err := pbutils.Unmarshal(data, stored); err != nil {
				return nil, errors.Wrap(err, "Invalid bootstrap Region")
			}
			name := stored.GetMetadata().GetName()
			if name == "" {
				name = "default"
			}
			if region != "" && region != name {
				return nil, errors.Errorf("The bootstrap Region does not match the Kubernetes installation identity")
			}
			if uid := stored.GetMetadata().GetUid(); bound && uid != "" && uid != annotations[targetRegionUID] {
				return nil, errors.Errorf("The bootstrap Region UID does not match the Kubernetes installation identity")
			}
			region = name
		}
	} else if !k8serr.IsNotFound(err) && !k8serr.IsForbidden(err) {
		return nil, err
	}
	job := desired.DeepCopy()
	for i := range job.Spec.Template.Spec.Containers {
		container := &job.Spec.Template.Spec.Containers[i]
		requested := ""
		for _, env := range container.Env {
			if env.Name == "OCTELIUM_DOMAIN" {
				requested = env.Value
			}
			if env.Name == "OCTELIUM_REGION_NAME" && env.Value != "" && env.Value != "default" && region != "" && env.Value != region {
				return nil, errors.Errorf("The requested Region does not match the Kubernetes target Region")
			}
		}
		if domain != "" && !sameDomain(requested, domain) {
			return nil, errors.Errorf("The requested domain %q does not match the Kubernetes target domain %q", requested, domain)
		}
		expected := map[string]string{}
		if bound {
			expected["OCTELIUM_GENESIS_CLUSTER_UID"] = annotations[targetClusterUID]
			expected["OCTELIUM_GENESIS_REGION_UID"] = annotations[targetRegionUID]
			expected["OCTELIUM_GENESIS_NAMESPACE_UID"] = annotations[targetNamespaceUID]
		}
		if region != "" {
			expected["OCTELIUM_REGION_NAME"] = region
		}
		for _, key := range []string{"OCTELIUM_REGION_NAME", "OCTELIUM_GENESIS_CLUSTER_UID", "OCTELIUM_GENESIS_REGION_UID", "OCTELIUM_GENESIS_NAMESPACE_UID"} {
			value, ok := expected[key]
			if !ok {
				continue
			}
			found := false
			for i := range container.Env {
				if container.Env[i].Name == key {
					if key != "OCTELIUM_REGION_NAME" && container.Env[i].Value != "" && container.Env[i].Value != value {
						return nil, errors.Errorf("The requested genesis identity %s does not match the Kubernetes target", key)
					}
					container.Env[i] = corev1.EnvVar{Name: key, Value: value}
					found = true
				}
			}
			if !found {
				container.Env = append(container.Env, corev1.EnvVar{Name: key, Value: value})
			}
		}
	}
	return job, nil
}
