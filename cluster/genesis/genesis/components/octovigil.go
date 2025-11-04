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
	"github.com/octelium/octelium/cluster/common/octovigilc"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

func getOctovigilService() *k8scorev1.Service {

	ret := &k8scorev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentOctovigil),
			Namespace: ns,
			Labels:    getComponentLabels(componentOctovigil),
		},
		Spec: k8scorev1.ServiceSpec{
			Type:     k8scorev1.ServiceTypeClusterIP,
			Selector: getComponentLabels(componentOctovigil),
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

func getOctovigilDeployment(c *corev1.ClusterConfig) *appsv1.Deployment {

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentOctovigil),
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: nil,
			Selector: &metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentOctovigil),
			},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      getComponentLabels(componentOctovigil),
					Annotations: getAnnotations(),
				},
				Spec: k8scorev1.PodSpec{
					AutomountServiceAccountToken: utils_types.BoolToPtr(false),
					NodeSelector:                 getNodeSelectorDataPlane(c),

					Containers: []k8scorev1.Container{
						{
							Name:            componentOctovigil,
							Image:           components.GetImage(components.Octovigil, ""),
							ImagePullPolicy: k8sutils.GetImagePullPolicy(),

							LivenessProbe: &k8scorev1.Probe{
								InitialDelaySeconds: 60,
								TimeoutSeconds:      4,
								PeriodSeconds:       30,
								FailureThreshold:    3,
								ProbeHandler: k8scorev1.ProbeHandler{
									GRPC: &k8scorev1.GRPCAction{
										Port: int32(octovigilc.GetPort()),
									},
								},
							},

							VolumeMounts: []k8scorev1.VolumeMount{
								{
									MountPath: "/tmp",
									Name:      "tmpfs",
								},
							},

							SecurityContext: &k8scorev1.SecurityContext{
								ReadOnlyRootFilesystem:   utils_types.BoolToPtr(true),
								AllowPrivilegeEscalation: utils_types.BoolToPtr(false),
							},
						},
					},
					Volumes: []k8scorev1.Volume{
						{
							Name: "tmpfs",
							VolumeSource: k8scorev1.VolumeSource{
								EmptyDir: &k8scorev1.EmptyDirVolumeSource{
									Medium: k8scorev1.StorageMediumMemory,
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

func getOctovigilNetworkPolicy(c *corev1.ClusterConfig) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentOctovigil),
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentOctovigil),
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
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}
}

func CreateOctovigil(ctx context.Context, c kubernetes.Interface, clusterCfg *corev1.ClusterConfig) error {

	if _, err := k8sutils.CreateOrUpdateDeployment(ctx, c, getOctovigilDeployment(clusterCfg)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateService(ctx, c, getOctovigilService()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateNetworkPolicy(ctx, c, getOctovigilNetworkPolicy(clusterCfg)); err != nil {
		return err
	}

	return nil
}
