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
	"encoding/json"
	"fmt"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

type Controller struct {
	octeliumC octeliumc.ClientInterface
	k8sC      kubernetes.Interface
}

const ns = vutils.K8sNS

func NewController(octeliumC octeliumc.ClientInterface, k8sC kubernetes.Interface) *Controller {
	return &Controller{
		octeliumC: octeliumC,
		k8sC:      k8sC,
	}
}

func (c *Controller) deployK8sResources(ctx context.Context, svc *corev1.Service) error {

	ownerCM, err := k8sutils.CreateOrUpdateConfigMap(ctx, c.k8sC, c.getOwnerConfigMap(svc))
	if err != nil {
		return err
	}

	if err := c.setK8sUpstream(ctx, svc, ownerCM); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateDeployment(ctx, c.k8sC,
		c.newDeployment(svc, ownerCM)); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateService(ctx, c.k8sC, c.getK8sService(svc, ownerCM)); err != nil {
		return err
	}

	return nil
}

func (c *Controller) OnAdd(ctx context.Context, svc *corev1.Service) error {

	if !ucorev1.ToService(svc).IsInMyRegion() {
		zap.L().Debug("Service is not deployed to this Region. Nothing to be done.",
			zap.String("svc", svc.Metadata.Name))
		return nil
	}

	if err := c.deployK8sResources(ctx, svc); err != nil {
		return err
	}

	if err := c.handleUpdateSessionUpstream(ctx, svc); err != nil {
		return err
	}

	return nil
}

func (c *Controller) OnUpdate(ctx context.Context, newSvc, oldSvc *corev1.Service) error {

	newSvcInMyRegion := ucorev1.ToService(newSvc).IsInMyRegion()
	oldSvcInMyRegion := ucorev1.ToService(oldSvc).IsInMyRegion()
	switch {
	case !newSvcInMyRegion && !oldSvcInMyRegion:
		zap.L().Debug("Service does not belong to this Region. Nothing to update",
			zap.String("svc", newSvc.Metadata.Name))
		return nil
	case !newSvcInMyRegion && oldSvcInMyRegion:
		if err := c.k8sC.CoreV1().ConfigMaps(ns).Delete(ctx,
			k8sutils.GetSvcHostname(oldSvc), k8smetav1.DeleteOptions{}); err != nil {
			if !k8serr.IsNotFound(err) {
				return err
			}
		}
		return nil
	default:
		if err := c.deployK8sResources(ctx, newSvc); err != nil {
			return err
		}
	}

	if err := c.handleUpdateSessionUpstream(ctx, newSvc); err != nil {
		return err
	}

	return nil
}

func (c *Controller) newPodSpec(svc *corev1.Service) k8scorev1.PodSpec {
	return c.newPodSpecVigil(svc)
}

func (c *Controller) newPodSpecVigil(svc *corev1.Service) k8scorev1.PodSpec {
	ret := k8scorev1.PodSpec{
		NodeSelector: func() map[string]string {
			return map[string]string{
				"octelium.com/node-mode-dataplane": "",
			}
		}(),

		SecurityContext: &k8scorev1.PodSecurityContext{
			Sysctls: []k8scorev1.Sysctl{
				{
					Name:  "net.ipv4.ip_unprivileged_port_start",
					Value: "1",
				},
			},
		},

		Containers: []k8scorev1.Container{

			{
				Name:            "vigil",
				Image:           components.GetImage(components.Vigil, ""),
				ImagePullPolicy: k8sutils.GetImagePullPolicy(),
				Resources: k8scorev1.ResourceRequirements{
					Requests: getDefaultRequests(),
					Limits:   getDefaultLimits(),
				},

				LivenessProbe: &k8scorev1.Probe{
					InitialDelaySeconds: 60,
					TimeoutSeconds:      4,
					PeriodSeconds:       30,
					FailureThreshold:    3,
					ProbeHandler: k8scorev1.ProbeHandler{
						GRPC: &k8scorev1.GRPCAction{
							Port: int32(vutils.HealthCheckPortVigil),
						},
					},
				},

				SecurityContext: &k8scorev1.SecurityContext{
					Privileged:               utils_types.BoolToPtr(false),
					AllowPrivilegeEscalation: utils_types.BoolToPtr(false),
					ReadOnlyRootFilesystem:   utils_types.BoolToPtr(true),
					Capabilities: &k8scorev1.Capabilities{
						Drop: []k8scorev1.Capability{
							"all",
						},
						Add: []k8scorev1.Capability{
							"NET_BIND_SERVICE",
						},
					},
				},
				Env: []k8scorev1.EnvVar{
					{
						Name:  "OCTELIUM_SVC_UID",
						Value: svc.Metadata.Uid,
					},
					{
						Name:  "OCTELIUM_SVC_NAME",
						Value: svc.Metadata.Name,
					},
					{
						Name:  "OCTELIUM_REGION_NAME",
						Value: vutils.GetMyRegionName(),
					},
					{
						Name:  "OCTELIUM_REGION_UID",
						Value: vutils.GetMyRegionUID(),
					},
					{
						Name: "OCTELIUM_POD_UID",
						ValueFrom: &k8scorev1.EnvVarSource{
							FieldRef: &k8scorev1.ObjectFieldSelector{
								FieldPath: "metadata.uid",
							},
						},
					},
					{
						Name: "OCTELIUM_POD_NAME",
						ValueFrom: &k8scorev1.EnvVarSource{
							FieldRef: &k8scorev1.ObjectFieldSelector{
								FieldPath: "metadata.name",
							},
						},
					},
				},
			},
		},
	}

	if ucorev1.ToService(svc).IsManagedService() && svc.Status.ManagedService != nil {

		if svc.Status.ManagedService.ImagePullSecret != "" {
			ret.ImagePullSecrets = []k8scorev1.LocalObjectReference{
				{
					Name: svc.Status.ManagedService.ImagePullSecret,
				},
			}
		}

		if svc.Status.ManagedService.Type == "vigil" && svc.Status.ManagedService.Image != "" {
			ret.Containers[0].Image = svc.Status.ManagedService.Image
		} else {
			envVars := []k8scorev1.EnvVar{
				{
					Name:  "OCTELIUM_SVC_UID",
					Value: svc.Metadata.Uid,
				},
				{
					Name:  "OCTELIUM_SVC_NAME",
					Value: svc.Metadata.Name,
				},
				{
					Name:  "OCTELIUM_REGION_NAME",
					Value: vutils.GetMyRegionName(),
				},
				{
					Name:  "OCTELIUM_REGION_UID",
					Value: vutils.GetMyRegionUID(),
				},
			}

			if svc.Status.ManagedService.Image != "" {
				ret.Containers = append(ret.Containers, k8scorev1.Container{
					Name:            "managed",
					Image:           svc.Status.ManagedService.Image,
					Command:         svc.Status.ManagedService.Command,
					Args:            svc.Status.ManagedService.Args,
					ImagePullPolicy: k8sutils.GetImagePullPolicy(),
					Env:             envVars,
					Resources: func() k8scorev1.ResourceRequirements {

						ret := k8scorev1.ResourceRequirements{
							Requests: k8scorev1.ResourceList{
								k8scorev1.ResourceMemory: resource.MustParse("5Mi"),
								k8scorev1.ResourceCPU:    resource.MustParse("10m"),
							},
							Limits: k8sutils.GetDefaultLimits(),
						}
						if svc.Status.ManagedService.ResourceLimit == nil {
							return ret
						}

						ret.Limits = k8scorev1.ResourceList{
							k8scorev1.ResourceMemory: func() resource.Quantity {
								if svc.Status.ManagedService.ResourceLimit.Memory != nil &&
									svc.Status.ManagedService.ResourceLimit.Memory.Megabytes > 0 {
									return resource.MustParse(
										fmt.Sprintf("%dMi", svc.Status.ManagedService.ResourceLimit.Memory.Megabytes))
								}
								return resource.MustParse(
									fmt.Sprintf("%dMi", k8sutils.DefaultLimitMemoryMegabytes))
							}(),
							k8scorev1.ResourceCPU: func() resource.Quantity {
								if svc.Status.ManagedService.ResourceLimit.Cpu != nil &&
									svc.Status.ManagedService.ResourceLimit.Cpu.Millicores > 0 {
									return resource.MustParse(
										fmt.Sprintf("%dm", svc.Status.ManagedService.ResourceLimit.Cpu.Millicores))
								}
								return resource.MustParse(
									fmt.Sprintf("%dm", k8sutils.DefaultLimitCPUMillicores))
							}(),
						}

						return ret
					}(),
					LivenessProbe: func() *k8scorev1.Probe {
						if svc.Status.ManagedService.HealthCheck != nil {
							switch svc.Status.ManagedService.HealthCheck.Type.(type) {
							case *corev1.Service_Status_ManagedService_HealthCheck_Grpc:
								port := svc.Status.ManagedService.HealthCheck.GetGrpc().Port
								if port <= 0 {
									port = int32(vutils.HealthCheckPortManagedService)
								}

								return &k8scorev1.Probe{
									InitialDelaySeconds: 60,
									TimeoutSeconds:      4,
									PeriodSeconds:       30,
									FailureThreshold:    3,
									ProbeHandler: k8scorev1.ProbeHandler{
										GRPC: &k8scorev1.GRPCAction{
											Port: int32(port),
										},
									},
								}
							}
						}

						switch svc.Status.ManagedService.Type {
						case "apiserver", "authserver", "dnsserver":
						default:
							return nil
						}

						return &k8scorev1.Probe{
							InitialDelaySeconds: 60,
							TimeoutSeconds:      4,
							PeriodSeconds:       30,
							FailureThreshold:    3,
							ProbeHandler: k8scorev1.ProbeHandler{
								GRPC: &k8scorev1.GRPCAction{
									Port: int32(vutils.HealthCheckPortManagedService),
								},
							},
						}
					}(),
				})
			}
		}
	}

	return ret
}

func (c *Controller) getPodAnnotations(svc *corev1.Service) map[string]string {
	// Redeploy the Service pod if such fields change

	deployMap := map[string]string{
		"octelium.com/svc-port":  fmt.Sprintf("%d", svc.Status.Port),
		"octelium.com/svc-mode":  svc.Spec.Mode.String(),
		"octelium.com/svc-tls":   fmt.Sprintf("%t", svc.Spec.IsTLS),
		"octelium.com/svc-http2": fmt.Sprintf("%t", ucorev1.ToService(svc).IsListenerHTTP2()),
	}

	deployMapJSON, _ := json.Marshal(deployMap)

	ret := map[string]string{
		"octelium.com/svc-deployment-id": vutils.Sha256SumHex(deployMapJSON),
		"octelium.com/svc-upgrade-uid": func() string {
			if svc.Metadata.SystemLabels == nil {
				return ""
			}

			return svc.Metadata.SystemLabels[vutils.UpgradeIDKey]
		}(),
		"k8s.v1.cni.cncf.io/networks": "octelium/octelium",
	}

	return ret
}

func (c *Controller) newDeployment(svc *corev1.Service, ownerCM *k8scorev1.ConfigMap) *appsv1.Deployment {

	labels := c.getPodLabels(svc)
	podAnnotations := c.getPodAnnotations(svc)

	return &appsv1.Deployment{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      k8sutils.GetSvcHostname(svc),
			Namespace: ns,
			OwnerReferences: []k8smetav1.OwnerReference{
				*k8smetav1.NewControllerRef(ownerCM, k8scorev1.SchemeGroupVersion.WithKind("ConfigMap")),
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: func() *int32 {
				if svc.Spec.Deployment == nil || svc.Spec.Deployment.Replicas < 1 {
					return nil
				}

				return utils_types.Int32ToPtr(int32(svc.Spec.Deployment.Replicas))
			}(),
			Selector: &k8smetav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: k8smetav1.ObjectMeta{
					Labels:      labels,
					Annotations: podAnnotations,
				},
				Spec: c.newPodSpec(svc),
			},
		},
	}
}

func (c *Controller) getPodLabels(svc *corev1.Service) map[string]string {
	labels := map[string]string{
		"app":                         "octelium",
		"octelium.com/component-type": "cluster",
		"octelium.com/component":      "svc",
		"octelium.com/svc":            svc.Metadata.Name,
		"octelium.com/namespace":      svc.Status.NamespaceRef.Name,
		"octelium.com/svc-uid":        svc.Metadata.Uid,
	}

	if ucorev1.ToService(svc).IsManagedService() && svc.Status.ManagedService != nil && len(svc.Status.ManagedService.K8SLabels) > 0 {
		for k, v := range svc.Status.ManagedService.K8SLabels {
			labels[k] = v
		}
	}
	return labels
}

func (c *Controller) OnDelete(ctx context.Context, svc *corev1.Service) error {
	if !ucorev1.ToService(svc).IsInMyRegion() {
		return nil
	}

	if err := c.k8sC.CoreV1().ConfigMaps(ns).Delete(ctx,
		k8sutils.GetSvcHostname(svc), k8smetav1.DeleteOptions{}); err != nil {
		if !k8serr.IsNotFound(err) {
			zap.L().Warn("Could not delete svc configMap",
				zap.String("svc", svc.Metadata.Name), zap.Error(err))
		}
	}

	if err := c.handleDeleteSessionUpstream(ctx, svc); err != nil {
		return err
	}

	return nil
}

func (c *Controller) getK8sService(svc *corev1.Service, ownerCM *k8scorev1.ConfigMap) *k8scorev1.Service {

	svcK8s := &k8scorev1.Service{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      k8sutils.GetSvcHostname(svc),
			Namespace: ns,
			OwnerReferences: []k8smetav1.OwnerReference{
				*k8smetav1.NewControllerRef(ownerCM, k8scorev1.SchemeGroupVersion.WithKind("ConfigMap")),
			},
		},
		Spec: k8scorev1.ServiceSpec{
			Type:     k8scorev1.ServiceTypeClusterIP,
			Selector: c.getPodLabels(svc),
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
						Port: int32(ucorev1.ToService(svc).RealPort()),
						TargetPort: intstr.IntOrString{
							Type:   intstr.Int,
							IntVal: int32(ucorev1.ToService(svc).RealPort()),
						},
					},
				}

				return ret
			}(),
		},
	}

	return svcK8s
}

func (c *Controller) getOwnerConfigMap(svc *corev1.Service) *k8scorev1.ConfigMap {
	return &k8scorev1.ConfigMap{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      k8sutils.GetSvcHostname(svc),
			Namespace: ns,
		},
		Data: map[string]string{
			"uid": svc.Metadata.Uid,
		},
	}
}

func getDefaultRequests() k8scorev1.ResourceList {
	return k8scorev1.ResourceList{
		k8scorev1.ResourceMemory: resource.MustParse("5Mi"),
		k8scorev1.ResourceCPU:    resource.MustParse("10m"),
	}
}

func getDefaultLimits() k8scorev1.ResourceList {
	return k8scorev1.ResourceList{
		k8scorev1.ResourceMemory: resource.MustParse("700Mi"),
		k8scorev1.ResourceCPU:    resource.MustParse("1200m"),
	}
}
