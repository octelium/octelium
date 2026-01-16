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
	"encoding/json"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const envoyGatewayConfigTemplate = `
admin:
    address:
        socket_address:
            address: 127.0.0.1
            port_value: 11011
dynamic_resources:
    lds_config:
        resource_api_version: V3
        api_config_source:
            api_type: GRPC
            transport_api_version: V3
            grpc_services:
                - envoy_grpc:
                      cluster_name: xds_cluster
    cds_config:
        resource_api_version: V3
        api_config_source:
            api_type: GRPC
            transport_api_version: V3
            grpc_services:
                - envoy_grpc:
                      cluster_name: xds_cluster
node:
    cluster: octelium
    id: octelium-ingress
static_resources:
    clusters:
        - name: xds_cluster
          type: STRICT_DNS
          connect_timeout: 3s
          lb_policy: round_robin
          typed_extension_protocol_options:
              envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
                  "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
                  explicit_http_config:
                      http2_protocol_options: {}
          load_assignment:
              cluster_name: xds_cluster
              endpoints:
                  - lb_endpoints:
                        - endpoint:
                              address:
                                  socket_address:
                                      address: octelium-ingress.octelium.svc
                                      port_value: 8080

`

func getEnvoyIngressDataPlaneConfigMap() *k8scorev1.ConfigMap {

	return &k8scorev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-dataplane-envoy-config",
			Namespace: ns,
		},
		Data: map[string]string{
			"config": envoyGatewayConfigTemplate,
		},
	}
}

func getIngressDataPlaneService(c *corev1.ClusterConfig, r *corev1.Region) *k8scorev1.Service {

	ret := &k8scorev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentIngressDataPlane),
			Namespace: ns,
			Labels:    getComponentLabels(componentIngressDataPlane),
		},
		Spec: k8scorev1.ServiceSpec{
			Type:     k8scorev1.ServiceTypeLoadBalancer,
			Selector: getComponentLabels(componentIngressDataPlane),
			ExternalIPs: func() []string {
				if r.Metadata.SystemLabels == nil {
					return nil
				}
				externalIPsStr, ok := r.Metadata.SystemLabels["external-ips"]
				if !ok || len(externalIPsStr) == 0 {
					return nil
				}
				var externalIPs []string
				if err := json.Unmarshal([]byte(externalIPsStr), &externalIPs); err != nil {
					return nil
				}
				return externalIPs
			}(),
			Ports: []k8scorev1.ServicePort{
				{
					Protocol: k8scorev1.ProtocolTCP,
					Port:     443,
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

func getIngressService(c *corev1.ClusterConfig) *k8scorev1.Service {

	ret := &k8scorev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentIngress),
			Namespace: ns,
			Labels:    getComponentLabels(componentIngress),
		},
		Spec: k8scorev1.ServiceSpec{
			Type:     k8scorev1.ServiceTypeClusterIP,
			Selector: getComponentLabels(componentIngress),
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

func getIngressDeployment(o *CommonOpts) *appsv1.Deployment {

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentIngress),
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: nil,
			Selector: &metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentIngress),
			},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      getComponentLabels(componentIngress),
					Annotations: getAnnotations(),
				},
				Spec: k8scorev1.PodSpec{
					AutomountServiceAccountToken: utils_types.BoolToPtr(false),
					NodeSelector:                 getNodeSelectorControlPlane(o.ClusterConfig),

					Containers: []k8scorev1.Container{
						{
							Name:            componentIngress,
							Resources:       getDefaultResourceRequirements(),
							Image:           components.GetImage(components.Ingress, ""),
							ImagePullPolicy: k8sutils.GetImagePullPolicy(),
							LivenessProbe:   MainLivenessProbe(),
							Env: func() []k8scorev1.EnvVar {
								ret := []k8scorev1.EnvVar{
									{
										Name:  "OCTELIUM_REGION_NAME",
										Value: o.Region.Metadata.Name,
									},
								}
								if o.EnableIngressFrontProxy {
									ret = append(ret, k8scorev1.EnvVar{
										Name:  "OCTELIUM_FRONT_PROXY_MODE",
										Value: "true",
									})
								}
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

func getIngressDataPlaneDeployment(c *corev1.ClusterConfig) *appsv1.Deployment {

	annotation := getAnnotations()
	if annotation == nil {
		annotation = make(map[string]string)
	}

	annotation["octelium.com/envoy-config-hash"] = vutils.Sha256SumHex(
		[]byte(getEnvoyIngressDataPlaneConfigMap().Data["config"]))

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        getComponentName(componentIngressDataPlane),
			Namespace:   ns,
			Labels:      getComponentLabels(componentIngressDataPlane),
			Annotations: defaultAnnotations(),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: nil,
			Selector: &metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentIngressDataPlane),
			},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      getComponentLabels(componentIngressDataPlane),
					Annotations: annotation,
				},

				Spec: k8scorev1.PodSpec{
					AutomountServiceAccountToken: utils_types.BoolToPtr(false),
					NodeSelector:                 getNodeSelectorDataPlane(c),
					Volumes: []k8scorev1.Volume{
						{
							Name: "envoy-config",
							VolumeSource: k8scorev1.VolumeSource{
								ConfigMap: &k8scorev1.ConfigMapVolumeSource{
									LocalObjectReference: k8scorev1.LocalObjectReference{
										Name: "ingress-dataplane-envoy-config",
									},
								},
							},
						},
					},

					Containers: []k8scorev1.Container{

						{
							Name:      "envoy",
							Image:     "envoyproxy/envoy:v1.36.4",
							Resources: getDefaultResourceRequirements(),

							Command: []string{"envoy"},
							Args: func() []string {
								ret := []string{"-c", "/etc/envoy/envoy.yaml"}

								if ldflags.IsDev() {
									ret = append(ret, "-l", "debug")
								}

								return ret
							}(),
							VolumeMounts: []k8scorev1.VolumeMount{{
								Name:      "envoy-config",
								ReadOnly:  true,
								MountPath: "/etc/envoy/envoy.yaml",
								SubPath:   "config",
							}},

							LivenessProbe: &k8scorev1.Probe{
								InitialDelaySeconds: 60,
								TimeoutSeconds:      4,
								PeriodSeconds:       30,
								FailureThreshold:    3,
								ProbeHandler: k8scorev1.ProbeHandler{
									HTTPGet: &k8scorev1.HTTPGetAction{
										Path: "/ready",
										Port: intstr.FromInt32(11012),
									},
								},
							},

							SecurityContext: &k8scorev1.SecurityContext{
								Privileged:               utils_types.BoolToPtr(false),
								AllowPrivilegeEscalation: utils_types.BoolToPtr(false),
								ReadOnlyRootFilesystem:   utils_types.BoolToPtr(true),
								RunAsNonRoot:             utils_types.BoolToPtr(true),
								RunAsUser:                utils_types.Int64ToPtr(34567),
								RunAsGroup:               utils_types.Int64ToPtr(34567),
								Capabilities: &k8scorev1.Capabilities{
									Drop: []k8scorev1.Capability{
										"all",
									},
									Add: []k8scorev1.Capability{
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

	return deployment
}

func getIngressNetworkPolicy(c *corev1.ClusterConfig) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentIngress),
			Namespace: ns,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: getComponentLabels(componentIngress),
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

func CreateIngress(ctx context.Context, o *CommonOpts) error {

	if _, err := k8sutils.CreateOrUpdateConfigMap(ctx, o.K8sC, getEnvoyIngressDataPlaneConfigMap()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateDeployment(ctx, o.K8sC, getIngressDataPlaneDeployment(o.ClusterConfig)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateService(ctx, o.K8sC, getIngressDataPlaneService(o.ClusterConfig, o.Region)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateDeployment(ctx, o.K8sC, getIngressDeployment(o)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateService(ctx, o.K8sC, getIngressService(o.ClusterConfig)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateNetworkPolicy(ctx, o.K8sC, getIngressNetworkPolicy(o.ClusterConfig)); err != nil {
		return err
	}

	return nil
}
