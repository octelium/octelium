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
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getNocturneDeployment(o *CommonOpts) *appsv1.Deployment {

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
					NodeSelector:       getNodeSelectorControlPlane(o.ClusterConfig),
					ServiceAccountName: getComponentName(componentNocturneRuntime),

					Containers: []k8scorev1.Container{
						{
							Name:            componentNocturne,
							Resources:       getDefaultResourceRequirements(),
							Image:           components.GetImage(components.Nocturne, ""),
							ImagePullPolicy: k8sutils.GetImagePullPolicy(),
							SecurityContext: MainSecurityContext(),

							LivenessProbe: MainLivenessProbe(),
							Env: func() []k8scorev1.EnvVar {
								ret := []k8scorev1.EnvVar{
									{
										Name:  "OCTELIUM_REGION_NAME",
										Value: o.Region.Metadata.Name,
									},
									{
										Name:  "OCTELIUM_REGION_UID",
										Value: o.Region.Metadata.Uid,
									},
								}

								if IsSPIFFEEnabled(o) {
									ret = append(ret, k8scorev1.EnvVar{
										Name:  "OCTELIUM_ENABLE_SPIFFE_CSI",
										Value: "true",
									})

									if val := GetSPIFFECSIDriver(o); val != "" {
										ret = append(ret, k8scorev1.EnvVar{
											Name:  "OCTELIUM_SPIFFE_CSI_DRIVER",
											Value: val,
										})
									}
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
	SetDeploymentSPIFFE(deployment, o)
	return deployment
}

func getNocturneRuntimeServiceAccount() *k8scorev1.ServiceAccount {
	return &k8scorev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentNocturneRuntime),
			Namespace: ns,
		},
	}
}

func getNocturneRuntimeRole() *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentNocturneRuntime),
			Namespace: ns,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"get", "list", "create", "update", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"services", "secrets"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "create", "update", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps/finalizers"},
				Verbs:     []string{"update"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list", "watch"},
			},
		},
	}
}

func getNocturneRuntimeRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentNocturneRuntime),
			Namespace: ns,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     getComponentName(componentNocturneRuntime),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      getComponentName(componentNocturneRuntime),
				Namespace: ns,
			},
		},
	}
}

func getNocturneRuntimeClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: getComponentName(componentNocturneRuntime),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"nodes"},
				Verbs:     []string{"get", "list", "watch", "update"},
			},
		},
	}
}

func getNocturneRuntimeClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: getComponentName(componentNocturneRuntime),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     getComponentName(componentNocturneRuntime),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      getComponentName(componentNocturneRuntime),
				Namespace: ns,
			},
		},
	}
}

func getNocturneLegacyRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:        getComponentName(componentNocturne),
			Annotations: getLegacyAnnotations(),
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

func getNocturneLegacyServiceAccount() *k8scorev1.ServiceAccount {
	return &k8scorev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        getComponentName(componentNocturne),
			Namespace:   ns,
			Annotations: getLegacyAnnotations(),
		},
	}
}

func getNocturneLegacyRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:        getComponentName(componentNocturne),
			Annotations: getLegacyAnnotations(),
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

func CreateNocturne(ctx context.Context, o *CommonOpts) error {

	if _, err := k8sutils.CreateOrUpdateServiceAccount(ctx, o.K8sC, getNocturneRuntimeServiceAccount()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateRole(ctx, o.K8sC, getNocturneRuntimeRole()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateRoleBinding(ctx, o.K8sC, getNocturneRuntimeRoleBinding()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateClusterRole(ctx, o.K8sC, getNocturneRuntimeClusterRole()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateClusterRoleBinding(ctx, o.K8sC, getNocturneRuntimeClusterRoleBinding()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateServiceAccount(ctx, o.K8sC, getNocturneLegacyServiceAccount()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateClusterRole(ctx, o.K8sC, getNocturneLegacyRole()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateClusterRoleBinding(ctx, o.K8sC, getNocturneLegacyRoleBinding()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateDeployment(ctx, o.K8sC, getNocturneDeployment(o)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateNetworkPolicy(ctx, o.K8sC, getNocturneNetworkPolicy(o.ClusterConfig)); err != nil {
		return err
	}

	return nil
}
