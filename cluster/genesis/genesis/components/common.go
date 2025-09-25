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
	"fmt"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	k8scorev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func defaultAnnotations() map[string]string {

	ret := make(map[string]string)
	ret["octelium.com/last-touched"] = vutils.NowRFC3339Nano()

	return ret
}

func getNodeSelectorDataPlane(c *corev1.ClusterConfig) map[string]string {
	return map[string]string{
		"octelium.com/node-mode-dataplane": "",
	}
}

func getNodeSelectorControlPlane(c *corev1.ClusterConfig) map[string]string {
	return map[string]string{
		"octelium.com/node-mode-controlplane": "",
	}
}

func getPostgresEnv() []k8scorev1.EnvVar {
	return []k8scorev1.EnvVar{
		{
			Name: "OCTELIUM_POSTGRES_USERNAME",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-postgres",
					},
					Key: "username",
				},
			},
		},
		{
			Name: "OCTELIUM_POSTGRES_PASSWORD",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-postgres",
					},
					Key: "postgres-password",
				},
			},
		},
		{
			Name: "OCTELIUM_POSTGRES_HOST",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-postgres",
					},
					Key: "host",
				},
			},
		},
		{
			Name: "OCTELIUM_POSTGRES_PORT",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-postgres",
					},
					Key: "port",
				},
			},
		},
		{
			Name: "OCTELIUM_POSTGRES_DATABASE",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-postgres",
					},
					Key: "database",
				},
			},
		},
		{
			Name: "OCTELIUM_POSTGRES_NOSSL",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-postgres",
					},
					Key: "no_ssl",
				},
			},
		},
	}
}

func GetPostgresEnv() []k8scorev1.EnvVar {
	return getPostgresEnv()
}

func getRedisEnv() []k8scorev1.EnvVar {
	return []k8scorev1.EnvVar{
		{
			Name: "OCTELIUM_REDIS_PASSWORD",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-redis",
					},
					Key: "password",
				},
			},
		},
		{
			Name: "OCTELIUM_REDIS_HOST",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-redis",
					},
					Key: "host",
				},
			},
		},
		{
			Name: "OCTELIUM_REDIS_PORT",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-redis",
					},
					Key: "port",
				},
			},
		},
		{
			Name: "OCTELIUM_REDIS_USERNAME",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-redis",
					},
					Key: "username",
				},
			},
		},
		{
			Name: "OCTELIUM_REDIS_DATABASE",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-redis",
					},
					Key: "database",
				},
			},
		},
		{
			Name: "OCTELIUM_REDIS_USE_TLS",
			ValueFrom: &k8scorev1.EnvVarSource{
				SecretKeyRef: &k8scorev1.SecretKeySelector{
					LocalObjectReference: k8scorev1.LocalObjectReference{
						Name: "octelium-redis",
					},
					Key: "use_tls",
				},
			},
		},
	}
}

func GetRedisEnv() []k8scorev1.EnvVar {
	return getRedisEnv()
}

var tcpProtocol = k8scorev1.ProtocolTCP
var udpProtocol = k8scorev1.ProtocolUDP

func getComponentName(arg string) string {
	return fmt.Sprintf("octelium-%s", arg)
}

const ns = "octelium"

func getComponentLabels(arg string) map[string]string {
	return map[string]string{
		"app":                         "octelium",
		"octelium.com/component":      arg,
		"octelium.com/component-type": "cluster",
	}
}

func getAnnotations() map[string]string {
	return map[string]string{
		"octelium.com/install-uid": utilrand.GetRandomStringLowercase(8),
	}
}

const componentGWAgent = "gwagent"
const componentIngress = "ingress"
const componentIngressDataPlane = "ingress-dataplane"
const componentNocturne = "nocturne"
const componentRscServer = "rscserver"
const componentOctovigil = "octovigil"

func getServiceUpstreamNetworkPolicy() *networkingv1.NetworkPolicy {

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-upstream",
			Namespace: vutils.K8sNS,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":                         "octelium",
					"octelium.com/component-type": "cluster",
					"octelium.com/component":      "svc-k8s-upstream",
				},
			},

			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{

					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"app":                         "octelium",
									"octelium.com/component-type": "cluster",
									"octelium.com/component":      "svc",
								},
							},
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"kubernetes.io/metadata.name": "octelium",
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
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "0.0.0.0/0",
								Except: []string{
									"10.0.0.0/8",
									"172.16.0.0/12",
									"192.168.0.0/16",
									"100.64.0.0/10",
									"169.254.0.0/16",
								},
							},
						},

						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "::/0",
								Except: []string{
									"fc00::/7",
								},
							},
						},
					},
				},
			},

			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
}

func InstallCommon(ctx context.Context, c kubernetes.Interface,
	clusterCfg *corev1.ClusterConfig, r *corev1.Region) error {

	if _, err := k8sutils.CreateOrUpdateNetworkPolicy(ctx, c, getServiceUpstreamNetworkPolicy()); err != nil {
		return err
	}

	return nil
}

func getDefaultRequests() k8scorev1.ResourceList {
	return k8scorev1.ResourceList{
		k8scorev1.ResourceMemory: resource.MustParse("5Mi"),
		k8scorev1.ResourceCPU:    resource.MustParse("10m"),
	}
}

func GetDefaultRequests() k8scorev1.ResourceList {
	return getDefaultRequests()
}

func getDefaultLimits() k8scorev1.ResourceList {
	return k8sutils.GetDefaultLimits()
}

func GetDefaultLimits() k8scorev1.ResourceList {
	return getDefaultLimits()
}

func getDefaultResourceRequirements() k8scorev1.ResourceRequirements {
	return k8scorev1.ResourceRequirements{
		Requests: getDefaultRequests(),
		Limits:   getDefaultLimits(),
	}
}

func GetDefaultResourceRequirements() k8scorev1.ResourceRequirements {
	return getDefaultResourceRequirements()
}
