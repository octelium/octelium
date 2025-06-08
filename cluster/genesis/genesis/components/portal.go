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

/*
import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

func getAuthServerService() *k8scorev1.Service {

	ret := &k8scorev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentAuthServer),
			Namespace: ns,
			Labels:    getComponentLabels(componentAuthServer),
		},
		Spec: k8scorev1.ServiceSpec{
			Type:     k8scorev1.ServiceTypeClusterIP,
			Selector: getComponentLabels(componentAuthServer),
			Ports: []k8scorev1.ServicePort{
				{
					Name:     "http-auth",
					Protocol: k8scorev1.ProtocolTCP,
					Port:     8080,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
				},
				{
					Name:     "grpc-auth",
					Protocol: k8scorev1.ProtocolTCP,
					Port:     9090,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 9090,
					},
				},
			},
		},
	}

	return ret
}

func getAuthServerDeployment(c *corev1.ClusterConfig) *appsv1.Deployment {

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentAuthServer),
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: nil,
			Selector: &metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentAuthServer),
			},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      getComponentLabels(componentAuthServer),
					Annotations: getAnnotations(),
				},
				Spec: k8scorev1.PodSpec{
					AutomountServiceAccountToken: utils_types.BoolToPtr(false),
					NodeSelector:                 getNodeSelectorControlPlane(c),
					ImagePullSecrets:             k8sutils.GetImagePullSecrets(),

					Containers: []k8scorev1.Container{
						{
							Resources:       getDefaultResourceRequirements(),
							Name:            componentAuthServer,
							Env:             getRedisEnv(),
							Image:           components.GetImage(components.AuthServer, ""),
							ImagePullPolicy: k8sutils.GetImagePullPolicy(),
						},
					},
				},
			},
		},
	}
	return deployment
}

func getAuthServerNetworkPolicy(c *corev1.ClusterConfig) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentAuthServer),
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentAuthServer),
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Protocol: &tcpProtocol,
							Port: &intstr.IntOrString{
								IntVal: 8080,
							},
						},
						{
							Protocol: &tcpProtocol,
							Port: &intstr.IntOrString{
								IntVal: 9090,
							},
						},
					},
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app":                         "octelium",
									"octelium.com/component-type": "cluster",
									"octelium.com/component":      componentIngressDataPlane,
								},
							},
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": ns,
								},
							},
						},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}
}

func CreateAuthServer(ctx context.Context, c kubernetes.Interface, clusterCfg *corev1.ClusterConfig) error {

	if _, err := k8sutils.CreateOrUpdateDeployment(ctx, c, getAuthServerDeployment(clusterCfg)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateService(ctx, c, getAuthServerService()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateNetworkPolicy(ctx, c, getAuthServerNetworkPolicy(clusterCfg)); err != nil {
		return err
	}

	return nil
}
*/
