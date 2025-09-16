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

package svccontroller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func (c *Controller) setK8sUpstream(ctx context.Context, svc *corev1.Service, ownerCM *k8scorev1.ConfigMap) error {

	if svc.Spec.Config != nil && svc.Spec.Config.Upstream != nil && svc.Spec.Config.Upstream.GetContainer() != nil {
		cfg := svc.Spec.Config

		zap.L().Debug("Setting default config k8s upstream for Service", zap.String("name", svc.Metadata.Name))

		passwordSec, err := c.setK8sUpstreamCredSecret(ctx, svc, cfg, ownerCM)
		if err != nil {
			return errors.Errorf("Could not set upstream cred secret: %+v", err)
		}

		dep, err := c.getK8sUpstreamDeployment(ctx, svc, cfg, passwordSec, ownerCM)
		if err != nil {
			return err
		}

		if _, err := k8sutils.CreateOrUpdateDeployment(ctx, c.k8sC,
			dep); err != nil {
			return err
		}

		if _, err := k8sutils.CreateOrUpdateService(ctx, c.k8sC,
			c.getK8sUpstreamService(svc, cfg, ownerCM)); err != nil {
			return err
		}
	}

	if svc.Spec.DynamicConfig != nil {
		for _, dCfg := range svc.Spec.DynamicConfig.Configs {
			if dCfg.Upstream != nil && dCfg.Upstream.GetContainer() != nil {

				cfg := dCfg
				zap.L().Debug("Setting config k8s upstream for Service",
					zap.String("name", svc.Metadata.Name), zap.String("config", cfg.Name))

				passwordSec, err := c.setK8sUpstreamCredSecret(ctx, svc, cfg, ownerCM)
				if err != nil {
					return errors.Errorf("Could not set upstream cred secret: %+v", err)
				}

				dep, err := c.getK8sUpstreamDeployment(ctx, svc, cfg, passwordSec, ownerCM)
				if err != nil {
					return err
				}
				if _, err := k8sutils.CreateOrUpdateDeployment(ctx,
					c.k8sC, dep); err != nil {
					return err
				}

				if _, err := k8sutils.CreateOrUpdateService(ctx, c.k8sC,
					c.getK8sUpstreamService(svc, cfg, ownerCM)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *Controller) getK8sUpstreamLabels(svc *corev1.Service, name string) map[string]string {
	return map[string]string{
		"app":                           "octelium",
		"octelium.com/component-type":   "cluster",
		"octelium.com/component":        "svc-k8s-upstream",
		"octelium.com/svc":              svc.Metadata.Name,
		"octelium.com/namespace":        svc.Status.NamespaceRef.Name,
		"octelium.com/svc-uid":          svc.Metadata.Uid,
		"octelium.com/svc-upstream-cfg": name,
	}
}

func (c *Controller) setK8sUpstreamCredSecret(ctx context.Context,
	svc *corev1.Service, cfg *corev1.Service_Spec_Config, ownerCM *k8scorev1.ConfigMap) (*corev1.Secret, error) {

	if cfg == nil || cfg.GetUpstream() == nil ||
		cfg.GetUpstream().GetContainer() == nil ||
		cfg.GetUpstream().GetContainer().Credentials == nil ||
		cfg.GetUpstream().GetContainer().Credentials.GetUsernamePassword() == nil {
		zap.L().Debug("No credentials for this managedContainer svc. Nothing to be done",
			zap.String("uid", svc.Metadata.Uid))
		return nil, nil
	}

	creds := cfg.GetUpstream().GetContainer().Credentials
	if creds == nil || creds.GetUsernamePassword() == nil || creds.GetUsernamePassword().GetPassword() == nil ||
		creds.GetUsernamePassword().GetPassword().GetFromSecret() == "" {
		return nil, errors.Errorf("No creds found for managed container: %s", svc.Metadata.Uid)
	}

	zap.L().Debug("Setting password credential Secret for managedContainer svc",
		zap.String("svc", svc.Metadata.Name),
		zap.String("secret", creds.GetUsernamePassword().GetPassword().GetFromSecret()))

	passwordSec, err := c.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
		Name: creds.GetUsernamePassword().GetPassword().GetFromSecret(),
	})
	if err != nil {
		return nil, err
	}

	domain := func() string {
		if creds.GetUsernamePassword().Server != "" {
			return creds.GetUsernamePassword().Server
		}

		parts := strings.Split(cfg.GetUpstream().GetContainer().Image, "/")

		if len(parts) < 1 {
			return "docker.io"
		}

		firstPart := parts[0]
		if strings.Contains(firstPart, ".") || strings.Contains(firstPart, ":") {
			return firstPart
		}

		return "docker.io"
	}()

	dockerConfig := map[string]any{
		"auths": map[string]any{
			domain: map[string]any{
				"auth": base64.StdEncoding.EncodeToString(
					[]byte(fmt.Sprintf("%s:%s",
						creds.GetUsernamePassword().Username, ucorev1.ToSecret(passwordSec).GetValueStr()))),
			},
		},
	}

	dockerJsonBytes, err := json.Marshal(dockerConfig)
	if err != nil {
		return nil, err
	}

	req := &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      fmt.Sprintf("regcred-%s-%s", svc.Metadata.Uid, passwordSec.Metadata.Uid),
			Namespace: ns,
			OwnerReferences: []k8smetav1.OwnerReference{
				*k8smetav1.NewControllerRef(ownerCM, k8scorev1.SchemeGroupVersion.WithKind("ConfigMap")),
			},
		},
		StringData: map[string]string{
			".dockerconfigjson": string(dockerJsonBytes),
		},

		Type: k8scorev1.SecretTypeDockerConfigJson,
	}

	_, err = k8sutils.CreateOrUpdateSecret(ctx, c.k8sC, req)
	if err != nil {
		return nil, err
	}

	return passwordSec, nil
}

func (c *Controller) getK8sUpstreamDeployment(ctx context.Context, svc *corev1.Service,
	cfg *corev1.Service_Spec_Config, passwordSec *corev1.Secret, ownerCM *k8scorev1.ConfigMap) (*appsv1.Deployment, error) {

	spec := cfg.GetUpstream().GetContainer()
	labels := c.getK8sUpstreamLabels(svc, cfg.Name)

	podSpec, err := c.getK8sUpstreamPod(ctx, cfg, svc, passwordSec, ownerCM)
	if err != nil {
		return nil, err
	}

	return &appsv1.Deployment{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      k8sutils.GetSvcK8sUpstreamHostname(svc, cfg.Name),
			Namespace: ns,
			OwnerReferences: []k8smetav1.OwnerReference{
				*k8smetav1.NewControllerRef(ownerCM, k8scorev1.SchemeGroupVersion.WithKind("ConfigMap")),
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: func() *int32 {
				if spec.Replicas < 1 {
					return nil
				}

				return utils_types.Int32ToPtr(int32(spec.Replicas))
			}(),
			Selector: &k8smetav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: k8smetav1.ObjectMeta{
					Labels: labels,

					/*
						Annotations: map[string]string{
							"octelium.com/install-uid": utilrand.GetRandomStringLowercase(8),
						},
					*/
				},
				Spec: *podSpec,
			},
		},
	}, nil
}

func (c *Controller) getK8sUpstreamPod(ctx context.Context,
	cfg *corev1.Service_Spec_Config, svc *corev1.Service, passwordSec *corev1.Secret,
	ownerCM *k8scorev1.ConfigMap) (*k8scorev1.PodSpec, error) {

	spec := cfg.GetUpstream().GetContainer()

	ret := &k8scorev1.PodSpec{
		AutomountServiceAccountToken: utils_types.BoolToPtr(false),
		EnableServiceLinks:           utils_types.BoolToPtr(false),
		DNSPolicy:                    k8scorev1.DNSNone,
		DNSConfig: &k8scorev1.PodDNSConfig{
			Nameservers: []string{"8.8.8.8", "1.1.1.1"},
		},
		Hostname: "octelium",
		SecurityContext: &k8scorev1.PodSecurityContext{
			Sysctls: []k8scorev1.Sysctl{
				{
					Name:  "net.ipv4.ip_unprivileged_port_start",
					Value: "1",
				},
			},
		},

		ImagePullSecrets: func() []k8scorev1.LocalObjectReference {
			if spec.Credentials != nil {
				return []k8scorev1.LocalObjectReference{
					{
						Name: fmt.Sprintf("regcred-%s-%s", svc.Metadata.Uid, passwordSec.Metadata.Uid),
					},
				}
			} else {
				return nil
			}
		}(),
		NodeSelector: func() map[string]string {
			return map[string]string{
				"octelium.com/node-mode-dataplane": "",
			}
		}(),
		Volumes: func() []k8scorev1.Volume {
			if len(spec.Volumes) < 1 {
				return nil
			}

			var ret []k8scorev1.Volume

			for _, vol := range spec.Volumes {
				volume := k8scorev1.Volume{
					Name: vol.Name,
				}

				switch vol.Type.(type) {
				case *corev1.Service_Spec_Config_Upstream_Container_Volume_PersistentVolumeClaim_:
					volume.VolumeSource = k8scorev1.VolumeSource{
						PersistentVolumeClaim: &k8scorev1.PersistentVolumeClaimVolumeSource{
							ClaimName: vol.GetPersistentVolumeClaim().Name,
						},
					}
				default:
					continue
				}

				ret = append(ret, volume)
			}

			return ret
		}(),
	}

	{

		limits := k8scorev1.ResourceList{
			k8scorev1.ResourceMemory: resource.MustParse(
				fmt.Sprintf("%dMi", func() uint32 {
					if spec.ResourceLimit == nil || spec.ResourceLimit.Memory == nil ||
						spec.ResourceLimit.Memory.Megabytes == 0 {
						return 512
					}
					return spec.ResourceLimit.Memory.Megabytes
				}())),
			k8scorev1.ResourceCPU: resource.MustParse(
				fmt.Sprintf("%dm", func() uint32 {
					if spec.ResourceLimit == nil || spec.ResourceLimit.Cpu == nil ||
						spec.ResourceLimit.Cpu.Millicores == 0 {
						return 1000
					}

					return spec.ResourceLimit.Cpu.Millicores
				}())),
			k8scorev1.ResourceEphemeralStorage: resource.MustParse("5000Mi"),
		}

		if spec.ResourceLimit != nil && len(spec.ResourceLimit.Ext) > 0 {
			for key, v := range spec.ResourceLimit.Ext {
				if val, err := resource.ParseQuantity(v); err == nil && key != "" {
					limits[k8scorev1.ResourceName(key)] = val
				}
			}
		}

		container := k8scorev1.Container{
			Name:    "backend",
			Image:   spec.Image,
			Command: spec.Command,
			Args:    spec.Args,
			// ImagePullPolicy: k8sutils.GetImagePullPolicy(),
			Resources: k8scorev1.ResourceRequirements{
				Requests: k8scorev1.ResourceList{
					k8scorev1.ResourceMemory:           resource.MustParse("5Mi"),
					k8scorev1.ResourceCPU:              resource.MustParse("10m"),
					k8scorev1.ResourceEphemeralStorage: resource.MustParse("50Mi"),
				},
				Limits: limits,
			},
			SecurityContext: &k8scorev1.SecurityContext{
				Privileged:               utils_types.BoolToPtr(false),
				AllowPrivilegeEscalation: utils_types.BoolToPtr(false),
				RunAsUser: func() *int64 {
					if spec.SecurityContext == nil ||
						spec.SecurityContext.RunAsUser == 0 ||
						spec.SecurityContext.RunAsUser > 1000000 {
						return nil
					}
					return utils_types.Int64ToPtr(int64(spec.SecurityContext.RunAsUser))
				}(),
				ReadOnlyRootFilesystem: func() *bool {
					if spec.SecurityContext == nil {
						return nil
					}
					return utils_types.BoolToPtr(spec.SecurityContext.ReadOnlyRootFilesystem)
				}(),
			},
			VolumeMounts: func() []k8scorev1.VolumeMount {
				if len(spec.VolumeMounts) < 1 {
					return nil
				}

				var ret []k8scorev1.VolumeMount

				for _, mount := range spec.VolumeMounts {
					ret = append(ret, k8scorev1.VolumeMount{
						Name:      mount.Name,
						MountPath: mount.MountPath,
						SubPath:   mount.SubPath,
						ReadOnly:  mount.ReadOnly,
					})
				}

				return ret
			}(),
		}

		getProbe := func(probe *corev1.Service_Spec_Config_Upstream_Container_Probe) *k8scorev1.Probe {
			ret := &k8scorev1.Probe{
				InitialDelaySeconds: probe.InitialDelaySeconds,
				TimeoutSeconds:      probe.TimeoutSeconds,
				PeriodSeconds:       probe.PeriodSeconds,
				SuccessThreshold:    probe.SuccessThreshold,
				FailureThreshold:    probe.FailureThreshold,
			}
			switch spec.LivenessProbe.Type.(type) {
			case *corev1.Service_Spec_Config_Upstream_Container_Probe_Grpc:
				ret.ProbeHandler = k8scorev1.ProbeHandler{
					GRPC: &k8scorev1.GRPCAction{
						Port: int32(spec.LivenessProbe.GetGrpc().Port),
					},
				}
			case *corev1.Service_Spec_Config_Upstream_Container_Probe_HttpGet:
				ret.ProbeHandler = k8scorev1.ProbeHandler{
					HTTPGet: &k8scorev1.HTTPGetAction{
						Path: spec.LivenessProbe.GetHttpGet().Path,
						Port: intstr.FromInt32(int32(spec.LivenessProbe.GetHttpGet().Port)),
					},
				}
			case *corev1.Service_Spec_Config_Upstream_Container_Probe_TcpSocket:
				ret.ProbeHandler = k8scorev1.ProbeHandler{
					TCPSocket: &k8scorev1.TCPSocketAction{
						Port: intstr.FromInt32(int32(spec.LivenessProbe.GetTcpSocket().Port)),
					},
				}
			default:
				zap.L().Debug("Unsupported probe type. Skipping the probe...")
				ret = nil
			}

			return ret
		}

		if spec.LivenessProbe != nil {
			container.LivenessProbe = getProbe(spec.LivenessProbe)
		}
		if spec.ReadinessProbe != nil {
			container.ReadinessProbe = getProbe(spec.ReadinessProbe)
		}

		for _, e := range spec.Env {
			env := k8scorev1.EnvVar{
				Name: e.Name,
			}
			switch e.Type.(type) {

			case *corev1.Service_Spec_Config_Upstream_Container_Env_Value:
				env.Value = e.GetValue()
				if len(env.Name) == 0 || len(env.Name) > 256 ||
					len(env.Value) == 0 || len(env.Value) > 3000 {
					continue
				}

			case *corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret:

				sec, err := c.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
					Name: e.GetFromSecret(),
				})
				if err == nil {
					k8sSecName := fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, sec.Metadata.Uid)
					req := &k8scorev1.Secret{
						ObjectMeta: k8smetav1.ObjectMeta{
							Name:      k8sSecName,
							Namespace: ns,
							OwnerReferences: []k8smetav1.OwnerReference{
								*k8smetav1.NewControllerRef(ownerCM, k8scorev1.SchemeGroupVersion.WithKind("ConfigMap")),
							},
						},
						StringData: map[string]string{
							"data": ucorev1.ToSecret(sec).GetSpecValueStr(),
						},

						Type: k8scorev1.SecretTypeDockerConfigJson,
					}

					if _, err := k8sutils.CreateOrUpdateSecret(ctx, c.k8sC, req); err == nil {
						env.ValueFrom = &k8scorev1.EnvVarSource{
							SecretKeyRef: &k8scorev1.SecretKeySelector{
								LocalObjectReference: k8scorev1.LocalObjectReference{
									Name: k8sSecName,
								},
								Key: "data",
							},
						}
					}
				}
			case *corev1.Service_Spec_Config_Upstream_Container_Env_KubernetesSecretRef_:
				secretRef := e.GetKubernetesSecretRef()

				env.ValueFrom = &k8scorev1.EnvVarSource{
					SecretKeyRef: &k8scorev1.SecretKeySelector{
						LocalObjectReference: k8scorev1.LocalObjectReference{
							Name: secretRef.Name,
						},
						Key: secretRef.Key,
					},
				}
			}

			if !govalidator.IsASCII(env.Name) {
				continue
			}

			container.Env = append(container.Env, env)
		}
		ret.Containers = append(ret.Containers, container)
	}

	return ret, nil
}

func (c *Controller) getK8sUpstreamService(svc *corev1.Service, cfg *corev1.Service_Spec_Config, ownerCM *k8scorev1.ConfigMap) *k8scorev1.Service {
	labels := c.getK8sUpstreamLabels(svc, cfg.Name)

	spec := cfg.GetUpstream().GetContainer()

	ret := &k8scorev1.Service{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      k8sutils.GetSvcK8sUpstreamHostname(svc, cfg.Name),
			Namespace: ns,
			OwnerReferences: []k8smetav1.OwnerReference{
				*k8smetav1.NewControllerRef(ownerCM, k8scorev1.SchemeGroupVersion.WithKind("ConfigMap")),
			},
		},
		Spec: k8scorev1.ServiceSpec{
			Type:     k8scorev1.ServiceTypeClusterIP,
			Selector: labels,
			Ports: func() []k8scorev1.ServicePort {

				ret := []k8scorev1.ServicePort{
					{
						Protocol: func() k8scorev1.Protocol {
							if ucorev1.ToService(svc).L4Type() == corev1.Service_Spec_UDP {
								return k8scorev1.ProtocolUDP
							} else {
								return k8scorev1.ProtocolTCP
							}
						}(),
						Port: int32(spec.Port),
						TargetPort: intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: int32(spec.Port),
						},
					},
				}

				return ret
			}(),
		},
	}

	return ret
}
