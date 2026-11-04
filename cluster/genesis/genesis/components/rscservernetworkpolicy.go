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

package components

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumclient "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/rest"
)

func hasPolicyAPI(ctx context.Context, dc discovery.DiscoveryInterface, groupVersion, kind string) (bool, error) {
	resList, err := k8sretry.Read(ctx, func(ctx context.Context) (*metav1.APIResourceList, error) {
		if dc.RESTClient() == nil {
			return dc.ServerResourcesForGroupVersion(groupVersion)
		}
		path := "/apis/" + groupVersion
		if !strings.Contains(groupVersion, "/") {
			path = "/api/" + groupVersion
		}
		result := &metav1.APIResourceList{}
		err := dc.RESTClient().Get().AbsPath(path).Do(ctx).Into(result)
		return result, err
	})
	if k8serr.IsNotFound(err) || k8serr.IsMethodNotSupported(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, res := range resList.APIResources {
		if res.Kind == kind {
			return true, nil
		}
	}
	return false, nil
}

func detectCNI(ctx context.Context, o *CommonOpts) (string, error) {

	dsList, err := k8sretry.Read(ctx, func(ctx context.Context) (*appsv1.DaemonSetList, error) {
		return o.K8sC.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	})
	if err != nil {
		return "", err
	}

	var hasCilium bool
	var hasCalico bool

	for _, ds := range dsList.Items {
		if strings.Contains(ds.Name, "cilium") &&
			(ds.Namespace == "kube-system" ||
				strings.Contains(ds.Namespace, "cilium")) {
			hasCilium = true
		}
		if strings.Contains(ds.Name, "calico") && (ds.Namespace == "kube-system" ||
			strings.Contains(ds.Namespace, "calico") || strings.Contains(ds.Namespace, "tigera")) {
			hasCalico = true
		}
	}

	if hasCilium && hasCalico {
		zap.L().Warn(
			"Detected more than one supported CNI. Skipping the octelium-rscserver networkPolicy")
		return "", nil
	}

	switch {
	case hasCilium:
		return "cilium", nil
	case hasCalico:
		return "calico", nil
	default:
		return "", nil
	}
}

func getRscServerCiliumNetworkPolicy() *ciliumv2.CiliumNetworkPolicy {

	fromNamespace := func(ns string) api.EndpointSelector {
		return api.EndpointSelector{
			LabelSelector: &v1.LabelSelector{
				MatchLabels: map[string]string{
					"app":                         "octelium",
					"io.kubernetes.pod.namespace": ns,
				},
			},
		}
	}

	return &ciliumv2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "octelium-rscserver",
			Namespace: vutils.K8sNS,
		},
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &v1.LabelSelector{
					MatchLabels: getComponentLabels(componentRscServer),
				},
			},
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							fromNamespace(vutils.K8sNS),

							// Genesis runs in the default namespace at installation.
							fromNamespace("default"),
						},

						FromEntities: api.EntitySlice{
							api.EntityHost,
							api.EntityRemoteNode,
						},
					},
					ToPorts: []api.PortRule{
						{
							Ports: []api.PortProtocol{
								{
									Port:     "8080",
									Protocol: api.ProtoTCP,
								},
							},
						},
					},
				},
			},
		},
	}
}

func setNetworkPolicyCilium(ctx context.Context, config *rest.Config) error {
	ciliumClient, err := ciliumclient.NewForConfig(config)
	if err != nil {
		return err
	}

	policy := getRscServerCiliumNetworkPolicy()
	policyC := ciliumClient.CiliumV2().CiliumNetworkPolicies(vutils.K8sNS)
	verify := false

	return k8sretry.Do(ctx, func(ctx context.Context) error {
		curr, err := policyC.Get(ctx, policy.Name, metav1.GetOptions{})
		if err != nil {
			if !k8serr.IsNotFound(err) {
				return err
			}

			if _, err := policyC.Create(ctx, policy, metav1.CreateOptions{}); err != nil {
				verify = k8sretry.IsTransient(err)
				if !k8serr.IsAlreadyExists(err) {
					return err
				}

				return k8serr.NewConflict(schema.GroupResource{
					Group:    ciliumv2.CustomResourceDefinitionGroup,
					Resource: ciliumv2.CNPPluralName,
				}, policy.Name, err)
			}

			return nil
		}

		if verify && len(curr.Specs) == 0 {
			currentSpec, err := json.Marshal(curr.Spec)
			if err != nil {
				return err
			}
			desiredSpec, err := json.Marshal(policy.Spec)
			if err != nil {
				return err
			}
			if bytes.Equal(currentSpec, desiredSpec) {
				return nil
			}
		}
		curr = curr.DeepCopy()
		curr.Spec = policy.Spec
		curr.Specs = nil

		_, err = policyC.Update(ctx, curr, metav1.UpdateOptions{})
		verify = k8sretry.IsTransient(err)
		return err
	})
}

func deleteNetworkPolicyCalico(ctx context.Context, config *rest.Config) error {
	calicoClient, err := calicoclient.NewForConfig(config)
	if err != nil {
		return err
	}

	policies := calicoClient.ProjectcalicoV3().NetworkPolicies(vutils.K8sNS)
	policy, err := k8sretry.Read(ctx, func(ctx context.Context) (*calicov3.NetworkPolicy, error) {
		return policies.Get(ctx, "octelium-rscserver", metav1.GetOptions{})
	})
	if k8serr.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := k8sretry.Delete(ctx, policy,
		func(ctx context.Context) (*calicov3.NetworkPolicy, error) {
			return policies.Get(ctx, policy.Name, metav1.GetOptions{})
		},
		func(ctx context.Context, options metav1.DeleteOptions) error {
			return policies.Delete(ctx, policy.Name, options)
		}); err != nil {
		return err
	}

	zap.L().Info("Removed the obsolete Calico octelium-rscserver networkPolicy")

	return nil
}

func setRscServerNetworkPolicy(ctx context.Context, o *CommonOpts) error {
	config, err := k8sutils.GetInClusterConfig()
	if err != nil {
		return err
	}

	cniType, err := detectCNI(ctx, o)
	if err != nil {
		return err
	}

	if cniType == "" {
		zap.L().Debug("Could not detect CNI. Skipping setting octelium-rscserver networkPolicy")
		return nil
	}

	zap.L().Debug("Found CNI installed", zap.String("cniType", cniType))

	switch cniType {
	case "cilium":
		supported, err := hasPolicyAPI(ctx, o.K8sC.Discovery(), "cilium.io/v2", "CiliumNetworkPolicy")
		if err != nil {
			return err
		}
		if !supported {
			zap.L().Info(
				"Cilium is installed but this cluster does not serve CiliumNetworkPolicy. " +
					"Skipping the octelium-rscserver networkPolicy")
			return nil
		}

		if err := setNetworkPolicyCilium(ctx, config); err != nil {
			return err
		}

	case "calico":
		supported, err := hasPolicyAPI(ctx, o.K8sC.Discovery(), "projectcalico.org/v3", "NetworkPolicy")
		if err != nil {
			return err
		}
		if !supported {
			zap.L().Info(
				"Calico is installed but its API server, which serves projectcalico.org/v3, " +
					"is unavailable. Skipping the octelium-rscserver networkPolicy")
			return nil
		}

		zap.L().Info(
			"Calico cannot express the host network sources that the Gateway Agents reach " +
				"rscServer from. Leaving the octelium-rscserver ingress unrestricted")

		if err := deleteNetworkPolicyCalico(ctx, config); err != nil {
			return err
		}

	}

	return nil
}
