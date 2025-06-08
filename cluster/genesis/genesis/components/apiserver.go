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

func getAPIServerService(c *corev1.ClusterConfig) *k8scorev1.Service {

	ret := &k8scorev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentAPIServer),
			Namespace: ns,
			Labels:    getComponentLabels(componentAPIServer),
		},
		Spec: k8scorev1.ServiceSpec{
			Type:     k8scorev1.ServiceTypeClusterIP,
			Selector: getComponentLabels(componentAPIServer),
			Ports: []k8scorev1.ServicePort{
				{
					Protocol: k8scorev1.ProtocolTCP,
					Port:     8080,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
				},
			},
		},
	}

	return ret
}

func getAPIServerDeployment(c *corev1.ClusterConfig, r *corev1.Region) *appsv1.Deployment {

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        getComponentName(componentAPIServer),
			Namespace:   ns,
			Annotations: defaultAnnotations(),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: nil,
			Selector: &metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentAPIServer),
			},
			Strategy: appsv1.DeploymentStrategy{},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      getComponentLabels(componentAPIServer),
					Annotations: getAnnotations(),
				},

				Spec: k8scorev1.PodSpec{
					AutomountServiceAccountToken: utils_types.BoolToPtr(false),
					NodeSelector:                 getNodeSelectorControlPlane(c),
					ImagePullSecrets:             k8sutils.GetImagePullSecrets(),
					Containers: []k8scorev1.Container{
						{
							Name:            componentAPIServer,
							Image:           components.GetImage(components.APIServer, ""),
							ImagePullPolicy: k8sutils.GetImagePullPolicy(),

							ReadinessProbe: &k8scorev1.Probe{
								InitialDelaySeconds: 10,
								TimeoutSeconds:      2,
								PeriodSeconds:       20,
								ProbeHandler: k8scorev1.ProbeHandler{
									Exec: &k8scorev1.ExecAction{
										Command: []string{"/bin/grpc_health_probe", "-addr=127.0.0.1:8090"},
									},
								},
							},

							LivenessProbe: &k8scorev1.Probe{
								InitialDelaySeconds: 60,
								TimeoutSeconds:      2,
								PeriodSeconds:       30,
								ProbeHandler: k8scorev1.ProbeHandler{
									Exec: &k8scorev1.ExecAction{
										Command: []string{"/bin/grpc_health_probe", "-addr=127.0.0.1:8090"},
									},
								},
							},

							Env: func() []k8scorev1.EnvVar {
								ret := []k8scorev1.EnvVar{
									{
										Name:  "OCTELIUM_REGION_NAME",
										Value: r.Metadata.Name,
									},
									{
										Name:  "OCTELIUM_REGION_UID",
										Value: r.Metadata.Uid,
									},
								}
								// ret = append(ret, getRedisEnv()...)
								return ret
							}(),
						},
					},
				},
			},
		},
	}
	return deployment
}

func getAPIServerNetworkPolicy(c *corev1.ClusterConfig) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentAPIServer),
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentAPIServer),
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

func CreateAPIServer(ctx context.Context,
	c kubernetes.Interface, clusterCfg *corev1.ClusterConfig, r *corev1.Region) error {

	if _, err := k8sutils.CreateOrUpdateDeployment(ctx, c, getAPIServerDeployment(clusterCfg, r)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateService(ctx, c, getAPIServerService(clusterCfg)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateNetworkPolicy(ctx, c, getAPIServerNetworkPolicy(clusterCfg)); err != nil {
		return err
	}

	return nil
}
*/
