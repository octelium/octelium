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
	"context"
	"strings"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumclient "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	calicoapi "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	"go.uber.org/zap"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func detectCNI(ctx context.Context, o *CommonOpts) (string, error) {

	dsList, err := o.K8sC.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}

	for _, ds := range dsList.Items {
		if strings.Contains(ds.Name, "cilium") &&
			(ds.Namespace == "kube-system" ||
				strings.Contains(ds.Namespace, "cilium")) {
			return "cilium", nil
		}
		if strings.Contains(ds.Name, "calico") && (ds.Namespace == "kube-system" ||
			strings.Contains(ds.Namespace, "calico") || strings.Contains(ds.Namespace, "tigera")) {
			return "calico", nil
		}
	}

	return "", nil
}

func setNetworkPolicyCilium(
	ctx context.Context,
	config *rest.Config,
) error {
	ciliumClient, err := ciliumclient.NewForConfig(config)
	if err != nil {
		return err
	}

	policy := &ciliumv2.CiliumNetworkPolicy{
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
							{
								LabelSelector: &v1.LabelSelector{
									MatchLabels: map[string]string{
										"app": "octelium",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if _, err := ciliumClient.CiliumV2().CiliumNetworkPolicies(vutils.K8sNS).Create(
		ctx,
		policy,
		metav1.CreateOptions{},
	); err != nil {
		if !k8serr.IsAlreadyExists(err) {
			return err
		}
	}

	return nil
}

func setNetworkPolicyCalico(
	ctx context.Context,
	config *rest.Config,
) error {
	calicoClient, err := calicoclient.NewForConfig(config)
	if err != nil {
		return err
	}

	policy := &calicoapi.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "octelium-rscserver",
			Namespace: vutils.K8sNS,
		},
		Spec: calicoapi.NetworkPolicySpec{
			Selector: "app == 'octelium' && octelium.com/component == 'rscserver'",
			Types:    []calicoapi.PolicyType{calicoapi.PolicyTypeIngress},
			Ingress: []calicoapi.Rule{
				{
					Action: calicoapi.Allow,
					Source: calicoapi.EntityRule{
						Selector: "app == 'octelium'",
					},
					Destination: calicoapi.EntityRule{
						Ports: []numorstring.Port{
							numorstring.SinglePort(8080),
						},
					},
				},
			},
		},
	}

	if _, err := calicoClient.ProjectcalicoV3().NetworkPolicies(vutils.K8sNS).Create(
		ctx,
		policy,
		metav1.CreateOptions{},
	); err != nil {
		if !k8serr.IsAlreadyExists(err) {
			return err
		}
	}

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
		if err := setNetworkPolicyCilium(ctx, config); err != nil {
			return err
		}

	case "calico":
		if err := setNetworkPolicyCalico(ctx, config); err != nil {
			return err
		}

	}

	return nil
}
