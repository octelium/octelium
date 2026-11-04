package install

import (
	"context"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/kubernetes"
)

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
			stored := &corev1.Region{}
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
					container.Env[i] = k8scorev1.EnvVar{Name: key, Value: value}
					found = true
				}
			}
			if !found {
				container.Env = append(container.Env, k8scorev1.EnvVar{Name: key, Value: value})
			}
		}
	}
	return job, nil
}
