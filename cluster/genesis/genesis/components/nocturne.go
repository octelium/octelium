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
	"github.com/octelium/octelium/cluster/common/vutils"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func getNocturneDeployment(c *corev1.ClusterConfig, r *corev1.Region) *appsv1.Deployment {

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentNocturne),
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: nil,
			Selector: &metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentNocturne),
			},
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      getComponentLabels(componentNocturne),
					Annotations: getAnnotations(),
				},
				Spec: k8scorev1.PodSpec{
					NodeSelector:       getNodeSelectorControlPlane(c),
					ServiceAccountName: getComponentName(componentNocturne),

					Containers: []k8scorev1.Container{
						{
							Name:            componentNocturne,
							Resources:       getDefaultResourceRequirements(),
							Image:           components.GetImage(components.Nocturne, ""),
							ImagePullPolicy: k8sutils.GetImagePullPolicy(),

							LivenessProbe: &k8scorev1.Probe{
								InitialDelaySeconds: 60,
								TimeoutSeconds:      4,
								PeriodSeconds:       30,
								FailureThreshold:    3,
								ProbeHandler: k8scorev1.ProbeHandler{
									GRPC: &k8scorev1.GRPCAction{
										Port: int32(vutils.HealthCheckPortMain),
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

func getNocturneRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: getComponentName(componentNocturne),
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"*", "*.*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		},
	}
}

func getNocturneServiceAccount() *k8scorev1.ServiceAccount {
	return &k8scorev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentNocturne),
			Namespace: ns,
		},
	}
}

func getNocturneRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: getComponentName(componentNocturne),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     getComponentName(componentNocturne),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      getComponentName(componentNocturne),
				Namespace: ns,
			},
		},
	}
}

func getNocturneNetworkPolicy(c *corev1.ClusterConfig) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentNocturne),
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentNocturne),
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}
}

func CreateNocturne(ctx context.Context, c kubernetes.Interface,
	clusterCfg *corev1.ClusterConfig, r *corev1.Region) error {

	if _, err := k8sutils.CreateOrUpdateServiceAccount(ctx, c, getNocturneServiceAccount()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateClusterRole(ctx, c, getNocturneRole()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateClusterRoleBinding(ctx, c, getNocturneRoleBinding()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateDeployment(ctx, c, getNocturneDeployment(clusterCfg, r)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateNetworkPolicy(ctx, c, getNocturneNetworkPolicy(clusterCfg)); err != nil {
		return err
	}

	return nil
}
