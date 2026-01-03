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
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getGatewayAgentDaemonSet(o *CommonOpts) *appsv1.DaemonSet {

	envVars := getGatewayAgentEnvVars(o.Region)
	hostPathDirectoryOrCreate := k8scorev1.HostPathDirectoryOrCreate

	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentGWAgent),
			Namespace: ns,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentGWAgent),
			},

			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      getComponentLabels(componentGWAgent),
					Annotations: getAnnotations(),
				},
				Spec: k8scorev1.PodSpec{
					ServiceAccountName: getComponentName(componentGWAgent),
					NodeSelector:       getNodeSelectorDataPlane(o.ClusterConfig),
					HostNetwork:        true,
					DNSPolicy:          k8scorev1.DNSClusterFirstWithHostNet,
					Tolerations: func() []k8scorev1.Toleration {

						return []k8scorev1.Toleration{
							{
								Key:      "octelium.com/gateway-init",
								Operator: k8scorev1.TolerationOpExists,
								Effect:   k8scorev1.TaintEffectNoSchedule,
							},
						}
					}(),
					Volumes: func() []k8scorev1.Volume {
						ret := []k8scorev1.Volume{
							{
								Name: "debian-modules",
								VolumeSource: k8scorev1.VolumeSource{
									HostPath: &k8scorev1.HostPathVolumeSource{
										Path: "/lib/modules",
										Type: &hostPathDirectoryOrCreate,
									},
								},
							},
							{
								Name: "etc-cni",
								VolumeSource: k8scorev1.VolumeSource{
									HostPath: &k8scorev1.HostPathVolumeSource{
										Path: "/etc/cni",
										Type: &hostPathDirectoryOrCreate,
									},
								},
							},
						}

						if o.EnableSPIFFECSI {
							ret = append(ret, k8sutils.GetSPIFFEVolume(o.SPIFFECSIDriver))
						}

						return ret
					}(),
					InitContainers: []k8scorev1.Container{
						{
							Name:            "octelium-node-init",
							Image:           components.GetImage(components.NodeInit, ""),
							ImagePullPolicy: k8sutils.GetImagePullPolicy(),
							Env:             *envVars,
							VolumeMounts: []k8scorev1.VolumeMount{{
								Name:      "debian-modules",
								ReadOnly:  false,
								MountPath: "/lib/modules",
							}},
							SecurityContext: &k8scorev1.SecurityContext{
								// ReadOnlyRootFilesystem:   utils_types.BoolToPtr(false),
								// AllowPrivilegeEscalation: utils_types.BoolToPtr(true),
								// RunAsNonRoot:             utils_types.BoolToPtr(false),
								// RunAsUser:                utils_types.Int64ToPtr(0),
								Privileged: utils_types.BoolToPtr(true),

								/*
									Capabilities: &k8scorev1.Capabilities{

										Add: []k8scorev1.Capability{
											"NET_ADMIN",
											"SYS_MODULE",
										},
									},

								*/
							},
						},
					},
					Containers: []k8scorev1.Container{
						{
							Name:  componentGWAgent,
							Image: components.GetImage(components.GWAgent, ""),
							Resources: k8scorev1.ResourceRequirements{
								Requests: getDefaultRequests(),
								Limits: k8scorev1.ResourceList{
									k8scorev1.ResourceMemory: resource.MustParse("1200Mi"),
									k8scorev1.ResourceCPU:    resource.MustParse("1500m"),
								},
							},
							ImagePullPolicy: k8sutils.GetImagePullPolicy(),
							Env:             *envVars,
							VolumeMounts: func() []k8scorev1.VolumeMount {
								ret := []k8scorev1.VolumeMount{
									{
										Name:      "etc-cni",
										ReadOnly:  false,
										MountPath: "/etc/cni",
									},
								}

								if o.EnableSPIFFECSI {
									ret = append(ret, k8sutils.GetSPIFFEVolumeMount())
								}

								return ret

							}(),
							LivenessProbe: &k8scorev1.Probe{
								InitialDelaySeconds: 60,
								TimeoutSeconds:      4,
								PeriodSeconds:       30,
								FailureThreshold:    3,

								ProbeHandler: k8scorev1.ProbeHandler{
									Exec: &k8scorev1.ExecAction{
										Command: []string{
											"/bin/grpc_health_probe", "-addr=localhost:10101",
										},
									},
								},
							},
							SecurityContext: &k8scorev1.SecurityContext{
								ReadOnlyRootFilesystem:   utils_types.BoolToPtr(false),
								AllowPrivilegeEscalation: utils_types.BoolToPtr(false),
								RunAsNonRoot:             utils_types.BoolToPtr(false),
								RunAsUser:                utils_types.Int64ToPtr(0),
								Capabilities: &k8scorev1.Capabilities{

									/*
										Drop: []k8scorev1.Capability{
											"all",
										},
									*/

									Add: []k8scorev1.Capability{
										"NET_ADMIN",
										"NET_RAW",
										"CHOWN",
										"MKNOD",
										"NET_BIND_SERVICE",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func getGatewayAgentEnvVars(r *corev1.Region) *[]k8scorev1.EnvVar {
	ret := []k8scorev1.EnvVar{
		{
			Name: "OCTELIUM_NODE",
			ValueFrom: &k8scorev1.EnvVarSource{
				FieldRef: &k8scorev1.ObjectFieldSelector{
					FieldPath: "spec.nodeName",
				},
			},
		},
		{
			Name:  "OCTELIUM_REGION_NAME",
			Value: r.Metadata.Name,
		},
		{
			Name: "OCTELIUM_NAMESPACE",
			ValueFrom: &k8scorev1.EnvVarSource{
				FieldRef: &k8scorev1.ObjectFieldSelector{
					FieldPath: "metadata.namespace",
				},
			},
		},

		{
			Name: "OCTELIUM_POD",
			ValueFrom: &k8scorev1.EnvVarSource{
				FieldRef: &k8scorev1.ObjectFieldSelector{
					FieldPath: "metadata.name",
				},
			},
		},
	}

	return &ret
}

func getGatewayAgentRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: getComponentName(componentGWAgent),
		},

		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"nodes", "pods"},
				Verbs:     []string{"get", "update", "watch", "list"},
			},
		},
	}
}

func getGatewayAgentServiceAccount() *k8scorev1.ServiceAccount {
	return &k8scorev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentGWAgent),
			Namespace: ns,
		},
	}
}

func getGatewayAgentRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: getComponentName(componentGWAgent),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     getComponentName(componentGWAgent),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      getComponentName(componentGWAgent),
				Namespace: ns,
			},
		},
	}
}

func CreateGatewayAgent(ctx context.Context, o *CommonOpts) error {

	if _, err := k8sutils.CreateOrUpdateServiceAccount(ctx, o.K8sC, getGatewayAgentServiceAccount()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateClusterRole(ctx, o.K8sC, getGatewayAgentRole()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateClusterRoleBinding(ctx, o.K8sC, getGatewayAgentRoleBinding()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateDaemonset(ctx, o.K8sC, getGatewayAgentDaemonSet(o)); err != nil {
		return err
	}

	return nil
}
