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
	"slices"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
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

func (c *Controller) doOnAdd(ctx context.Context, svc *corev1.Service) error {

	ownerCM, err := c.k8sC.CoreV1().ConfigMaps(ns).Create(ctx, c.getOwnerConfigMap(svc), k8smetav1.CreateOptions{})
	if err != nil {
		return err
	}

	if err := c.setK8sUpstream(ctx, svc, ownerCM); err != nil {
		return err
	}

	hasNodePoolGateway := true

	_, err = c.k8sC.AppsV1().
		Deployments(ns).
		Create(ctx,
			c.newDeployment(svc, hasNodePoolGateway, ownerCM),
			k8smetav1.CreateOptions{})

	if err != nil {
		return err
	}

	if err := c.createK8sService(ctx, svc, ownerCM); err != nil {
		return err
	}

	return nil
}

func (c *Controller) redeploy(ctx context.Context, svc *corev1.Service) error {

	dep, err := c.k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcHostname(svc), k8smetav1.GetOptions{})
	if err != nil {
		return err
	}

	dep.Spec.Template.Annotations["octelium.com/install-uid"] = utilrand.GetRandomStringLowercase(8)

	_, err = c.k8sC.AppsV1().Deployments(ns).Update(ctx, dep, k8smetav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (c *Controller) OnAdd(ctx context.Context, svc *corev1.Service) error {
	zap.S().Debugf("Adding Service %s", svc.Metadata.Name)

	{
		if time.Now().After(svc.Metadata.CreatedAt.AsTime().Add(1 * time.Minute)) {
			zap.S().Debugf("Service %s is probably already created. Re-deploying...", svc.Metadata.Name)
			return c.redeploy(ctx, svc)
		}
	}

	if !ucorev1.ToService(svc).IsInMyRegion() {
		zap.S().Debugf("Service %s is not deployed to this Region. Nothing to be done.", svc.Metadata.Name)
		return nil
	}

	if err := c.doOnAdd(ctx, svc); err != nil {
		return err
	}

	if err := c.handleAdd(ctx, svc); err != nil {
		return err
	}

	return nil
}

func getReplicas(svc *corev1.Service) int32 {
	if svc.Spec.Deployment == nil {
		return 1
	}
	if svc.Spec.Deployment.Replicas < 1 {
		return 1
	}
	return int32(svc.Spec.Deployment.Replicas)
}

func (c *Controller) OnUpdate(ctx context.Context, newSvc, oldSvc *corev1.Service) error {
	if !ucorev1.ToService(newSvc).IsInMyRegion() && !ucorev1.ToService(oldSvc).IsInMyRegion() {
		zap.S().Debugf("Service %s does not belong to this Region. Nothing to update", newSvc.Metadata.Uid)
		return nil
	} else if !ucorev1.ToService(newSvc).IsInMyRegion() && ucorev1.ToService(oldSvc).IsInMyRegion() {

		if err := c.k8sC.CoreV1().ConfigMaps(ns).Delete(ctx, k8sutils.GetSvcHostname(oldSvc), k8smetav1.DeleteOptions{}); err != nil {
			return err
		}
		return nil
	} else if ucorev1.ToService(newSvc).IsInMyRegion() && !ucorev1.ToService(oldSvc).IsInMyRegion() {
		if err := c.doOnAdd(ctx, newSvc); err != nil {
			return err
		}
	} else {

		ownerCM, err := c.k8sC.CoreV1().ConfigMaps(ns).
			Get(ctx, k8sutils.GetSvcHostname(newSvc), k8smetav1.GetOptions{})
		if err != nil {
			return err
		}

		hasNodePoolGateway := true

		if c.shouldRedeploy(newSvc, oldSvc) {
			zap.L().Debug("Redeploying Service k8s resources", zap.Any("svc", newSvc))

			dep, err := c.k8sC.AppsV1().Deployments(ns).Get(ctx, k8sutils.GetSvcHostname(newSvc), k8smetav1.GetOptions{})
			if err != nil {
				return err
			}

			newDep := c.newDeployment(newSvc, hasNodePoolGateway, ownerCM)

			dep.Spec = newDep.Spec
			_, err = c.k8sC.AppsV1().Deployments(ns).Update(ctx, dep, k8smetav1.UpdateOptions{})
			if err != nil {
				return err
			}

		} else {
			zap.L().Debug("No need to redeploy the Service", zap.String("name", newSvc.Metadata.Name))
		}

		if c.shouldRedeployUpstream(newSvc, oldSvc) {
			if err := c.setK8sUpstream(ctx, newSvc, ownerCM); err != nil {
				return err
			}
		} else {
			zap.L().Debug("No need to redeploy the Service upstream", zap.String("name", newSvc.Metadata.Name))
		}

		if err := c.updateK8sService(ctx, newSvc); err != nil {
			return err
		}
	}

	/*
		if !ucorev1.ToService(newSvc).IsManagedContainer() && ucorev1.ToService(oldSvc).IsManagedContainer() {
			if err := c.deleteK8sUpstream(ctx, newSvc); err != nil {
				return err
			}
		}
	*/

	if err := c.handleUpdate(ctx, newSvc, oldSvc); err != nil {
		return err
	}

	return nil
}

func (c *Controller) shouldRedeploy(newSvc, oldSvc *corev1.Service) bool {

	if getReplicas(newSvc) != getReplicas(oldSvc) {
		return true
	}

	if !pbutils.IsEqual(newSvc.Status.ManagedService, oldSvc.Status.ManagedService) {
		return true
	}

	if newSvc.Metadata.SystemLabels != nil &&
		oldSvc.Metadata.SystemLabels != nil &&
		newSvc.Metadata.SystemLabels[vutils.UpgradeIDKey] != oldSvc.Metadata.SystemLabels[vutils.UpgradeIDKey] {
		return true
	}

	return false
}

func (c *Controller) shouldRedeployUpstream(newSvc, oldSvc *corev1.Service) bool {

	needsContainerDeployment := func(new, old *corev1.Service_Spec_Config) bool {
		newHasContainer := new != nil && new.Upstream != nil && new.Upstream.GetContainer() != nil
		oldHasContainer := old != nil && old.Upstream != nil && old.Upstream.GetContainer() != nil

		switch {
		case newHasContainer && !oldHasContainer:
			return true
		case !newHasContainer && oldHasContainer:
			return true
		case newHasContainer && oldHasContainer && !pbutils.IsEqual(newSvc.Spec.Config.Upstream.GetContainer(), oldSvc.Spec.Config.Upstream.GetContainer()):
			return true
		default:
			return false
		}
	}

	if needsContainerDeployment(newSvc.Spec.Config, oldSvc.Spec.Config) {
		return true
	}

	newHasDynamicConfig := newSvc.Spec.DynamicConfig != nil && len(newSvc.Spec.DynamicConfig.Configs) > 0
	oldHasDynamicConfig := oldSvc.Spec.DynamicConfig != nil && len(oldSvc.Spec.DynamicConfig.Configs) > 0
	switch {
	case newHasDynamicConfig && !oldHasDynamicConfig:
		if slices.ContainsFunc(newSvc.Spec.DynamicConfig.Configs, func(c *corev1.Service_Spec_Config) bool {
			return c.Upstream != nil && c.Upstream.GetContainer() != nil
		}) {
			return true
		}
	case !newHasDynamicConfig && oldHasDynamicConfig:
		if slices.ContainsFunc(oldSvc.Spec.DynamicConfig.Configs, func(c *corev1.Service_Spec_Config) bool {
			return c.Upstream != nil && c.Upstream.GetContainer() != nil
		}) {
			return true
		}
	case newHasDynamicConfig && oldHasDynamicConfig:
		if pbutils.IsEqual(newSvc.Spec.DynamicConfig, oldSvc.Spec.DynamicConfig) {
			return false
		}

		if slices.ContainsFunc(newSvc.Spec.DynamicConfig.Configs, func(c *corev1.Service_Spec_Config) bool {
			return c.Upstream != nil && c.Upstream.GetContainer() != nil
		}) {
			return true
		}

		if slices.ContainsFunc(oldSvc.Spec.DynamicConfig.Configs, func(c *corev1.Service_Spec_Config) bool {
			return c.Upstream != nil && c.Upstream.GetContainer() != nil
		}) {
			return true
		}
	}

	return false
}

func (c *Controller) newPodSpec(svc *corev1.Service, hasNodePoolGateway bool) k8scorev1.PodSpec {
	return c.newPodSpecVigil(svc, hasNodePoolGateway)
}

func (c *Controller) newPodSpecVigil(svc *corev1.Service, hasNodePoolGateway bool) k8scorev1.PodSpec {
	ret := k8scorev1.PodSpec{
		NodeSelector: func() map[string]string {
			if !hasNodePoolGateway {
				return nil
			}
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
	ret := map[string]string{
		"octelium.com/install-uid":    utilrand.GetRandomStringLowercase(8),
		"k8s.v1.cni.cncf.io/networks": "octelium/octelium",
	}

	return ret
}

func (c *Controller) newDeployment(svc *corev1.Service, hasNodePoolGateway bool, ownerCM *k8scorev1.ConfigMap) *appsv1.Deployment {

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
				Spec: c.newPodSpec(svc, hasNodePoolGateway),
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

func (c *Controller) newDaemonSet(svc *corev1.Service, hasNodePoolGateway bool, ownerCM *k8scorev1.ConfigMap) *appsv1.DaemonSet {

	labels := c.getPodLabels(svc)
	podAnnotations := c.getPodAnnotations(svc)

	return &appsv1.DaemonSet{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      k8sutils.GetSvcHostname(svc),
			Namespace: ns,
			OwnerReferences: []k8smetav1.OwnerReference{
				*k8smetav1.NewControllerRef(ownerCM, k8scorev1.SchemeGroupVersion.WithKind("ConfigMap")),
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &k8smetav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: k8smetav1.ObjectMeta{
					Labels:      labels,
					Annotations: podAnnotations,
				},
				Spec: c.newPodSpec(svc, hasNodePoolGateway),
			},
		},
	}
}

func (c *Controller) OnDelete(ctx context.Context, svc *corev1.Service) error {
	if !ucorev1.ToService(svc).IsInMyRegion() {
		return nil
	}

	if err := c.k8sC.CoreV1().ConfigMaps(ns).Delete(ctx, k8sutils.GetSvcHostname(svc), k8smetav1.DeleteOptions{}); err != nil {
		return err
	}

	if err := c.handleDelete(ctx, svc); err != nil {
		return err
	}

	return nil
}

func (c *Controller) createK8sService(ctx context.Context, svc *corev1.Service, ownerCM *k8scorev1.ConfigMap) error {

	labels := c.getPodLabels(svc)

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

	if _, err := c.k8sC.CoreV1().Services(ns).Create(ctx, svcK8s, k8smetav1.CreateOptions{}); err != nil {
		return err
	}

	return nil
}

func (c *Controller) updateK8sService(ctx context.Context, svc *corev1.Service) error {

	svcK8s, err := c.k8sC.CoreV1().Services(ns).Get(ctx, k8sutils.GetSvcHostname(svc), k8smetav1.GetOptions{})
	if err != nil {
		return err
	}

	svcK8s.Spec.Ports = func() []k8scorev1.ServicePort {
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
	}()

	if _, err := c.k8sC.CoreV1().Services(ns).Update(ctx, svcK8s, k8smetav1.UpdateOptions{}); err != nil {
		return err
	}

	return nil
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
