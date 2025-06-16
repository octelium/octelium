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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

func getRscServerService() *k8scorev1.Service {

	ret := &k8scorev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentRscServer),
			Namespace: ns,
			Labels:    getComponentLabels(componentRscServer),
		},
		Spec: k8scorev1.ServiceSpec{
			Type:     k8scorev1.ServiceTypeClusterIP,
			Selector: getComponentLabels(componentRscServer),
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

func getRscServerDeployment(c *corev1.ClusterConfig) *appsv1.Deployment {

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentRscServer),
			Namespace: ns,
			Labels:    getComponentLabels(componentRscServer),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: nil,
			Selector: &metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentRscServer),
			},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      getComponentLabels(componentRscServer),
					Annotations: getAnnotations(),
				},
				Spec: k8scorev1.PodSpec{
					AutomountServiceAccountToken: utils_types.BoolToPtr(false),
					NodeSelector:                 getNodeSelectorControlPlane(c),

					Containers: []k8scorev1.Container{
						{
							Name: componentRscServer,
							Env: func() []k8scorev1.EnvVar {
								var ret []k8scorev1.EnvVar
								ret = append(ret, getPostgresEnv()...)
								ret = append(ret, getRedisEnv()...)

								return ret
							}(),
							ReadinessProbe: &k8scorev1.Probe{
								InitialDelaySeconds: 5,
								TimeoutSeconds:      4,
								PeriodSeconds:       20,
								FailureThreshold:    3,
								ProbeHandler: k8scorev1.ProbeHandler{
									GRPC: &k8scorev1.GRPCAction{
										Port: int32(8080),
									},
								},
							},

							LivenessProbe: &k8scorev1.Probe{
								InitialDelaySeconds: 60,
								TimeoutSeconds:      4,
								PeriodSeconds:       30,
								FailureThreshold:    3,

								ProbeHandler: k8scorev1.ProbeHandler{
									GRPC: &k8scorev1.GRPCAction{
										Port: int32(8080),
									},
								},
							},

							Image:           components.GetImage(components.RscServer, ""),
							ImagePullPolicy: k8sutils.GetImagePullPolicy(),

							Resources: k8scorev1.ResourceRequirements{
								Requests: getDefaultRequests(),
								Limits: k8scorev1.ResourceList{
									k8scorev1.ResourceMemory: resource.MustParse("1200Mi"),
									k8scorev1.ResourceCPU:    resource.MustParse("1500m"),
								},
							},
						},
					},
				},
			},
		},
	}
	return deployment
}

func getRscServerNetworkPolicy(c *corev1.ClusterConfig) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentRscServer),
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentRscServer),
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
								},
							},
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": ns,
								},
							},
						},
						{
							// Genesis could run in default or octelium namespaces
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app":                    "octelium",
									"octelium.com/component": "genesis",
								},
							},
							NamespaceSelector: &metav1.LabelSelector{},
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

func CreateRscServer(ctx context.Context, c kubernetes.Interface, clusterCfg *corev1.ClusterConfig) error {

	if _, err := k8sutils.CreateOrUpdateDeployment(ctx, c, getRscServerDeployment(clusterCfg)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateService(ctx, c, getRscServerService()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateNetworkPolicy(ctx, c, getRscServerNetworkPolicy(clusterCfg)); err != nil {
		return err
	}

	return nil
}
