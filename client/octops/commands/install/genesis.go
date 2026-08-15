// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package install

import (
	"context"
	"fmt"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const genesisNS = "default"

const genesisJobName = "octelium-genesis"

func getGenesisRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "octelium-genesis",
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

func getGenesisServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "octelium-genesis",
			Namespace: genesisNS,
		},
	}
}

func getGenesisRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "octelium-genesis",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "octelium-genesis",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "octelium-genesis",
				Namespace: genesisNS,
			},
		},
	}
}

func getGenesisJob(o *Opts, spiffe *SPIFFEOpts) *batchv1.Job {
	labels := map[string]string{
		"app":                         "octelium",
		"octelium.com/component":      "genesis",
		"octelium.com/component-type": "cluster",
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "octelium-genesis",
			Namespace: genesisNS,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: GetGenesisPodSpec(&GenesisPodSpecOpts{
					Domain:     o.ClusterDomain,
					Cmd:        "init",
					Version:    o.Version,
					SvcAccount: "octelium-genesis",
					SPIFFE:     spiffe,
				}),
			},
		},
	}
}

type GenesisPodSpecOpts struct {
	Domain     string
	Cmd        string
	Version    string
	SvcAccount string
	Package    string
	Region     string
	SPIFFE     *SPIFFEOpts
}

func GetGenesisPodSpec(o *GenesisPodSpecOpts) corev1.PodSpec {
	pkg := o.Package
	if pkg == "" {
		pkg = "octelium"
	}
	rgn := o.Region
	if rgn == "" {
		rgn = "default"
	}

	return corev1.PodSpec{
		ServiceAccountName: o.SvcAccount,
		RestartPolicy:      corev1.RestartPolicyNever,
		Volumes: func() []corev1.Volume {
			var ret []corev1.Volume
			if o.SPIFFE != nil {
				ret = append(ret, corev1.Volume{
					Name: "spiffe-agent",
					VolumeSource: corev1.VolumeSource{
						CSI: &corev1.CSIVolumeSource{
							Driver:   o.SPIFFE.getCSIDriver(),
							ReadOnly: utils_types.BoolToPtr(true),
						},
					},
				})
			}

			return ret
		}(),

		Containers: []corev1.Container{
			{
				Name: fmt.Sprintf("%s-genesis", pkg),
				Image: func() string {
					if o.Version != "" {
						return cliutils.GetGenesisImageWithPackage(pkg, o.Version)
					}
					if ldflags.IsDev() {
						return cliutils.GetGenesisImageWithPackage(pkg, "")
					} else {
						return cliutils.GetGenesisImageWithPackage(pkg, "latest")
					}
				}(),
				ImagePullPolicy: corev1.PullAlways,
				Args:            []string{o.Cmd},
				VolumeMounts: func() []corev1.VolumeMount {
					var ret []corev1.VolumeMount
					if o.SPIFFE != nil {
						ret = append(ret, corev1.VolumeMount{
							Name:      "spiffe-agent",
							MountPath: "/run/spire/sockets",
							ReadOnly:  true,
						})
					}
					return ret
				}(),
				Env: func() []corev1.EnvVar {
					ret := []corev1.EnvVar{
						{
							Name:  "OCTELIUM_DOMAIN",
							Value: o.Domain,
						},
						{
							Name:  "OCTELIUM_REGION_NAME",
							Value: rgn,
						},
					}

					if o.SPIFFE != nil {
						ret = append(ret, corev1.EnvVar{
							Name:  "OCTELIUM_ENABLE_SPIFFE_CSI",
							Value: "true",
						})

						if val := o.SPIFFE.CSIDriver; val != "" {
							ret = append(ret, corev1.EnvVar{
								Name:  "OCTELIUM_SPIFFE_CSI_DRIVER",
								Value: val,
							})
						}

						if val := o.SPIFFE.TrustDomain; val != "" {
							ret = append(ret, corev1.EnvVar{
								Name:  "OCTELIUM_SPIFFE_TRUST_DOMAIN",
								Value: val,
							})
						}
					}

					return ret
				}(),
			},
		},
	}
}

func createGenesis(ctx context.Context, o *Opts) error {

	c := o.K8sC
	if err := cleanupResources(ctx, o.K8sC); err != nil {
		return errors.Errorf("Could not clean up components: %+v", err)
	}

	_, err := c.CoreV1().ServiceAccounts(genesisNS).Create(ctx, getGenesisServiceAccount(), metav1.CreateOptions{})
	if err != nil {
		return err
	}

	_, err = c.RbacV1().ClusterRoles().Create(ctx, getGenesisRole(), metav1.CreateOptions{})
	if err != nil {
		return err
	}

	_, err = c.RbacV1().ClusterRoleBindings().Create(ctx, getGenesisRoleBinding(), metav1.CreateOptions{})
	if err != nil {
		return err
	}

	_, err = c.BatchV1().Jobs(genesisNS).Create(ctx,
		getGenesisJob(o, spiffeFromBootstrap(o.Bootstrap)), metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func cleanupResources(ctx context.Context, c kubernetes.Interface) error {
	zap.S().Debugf("Cleaning up resources if existent")
	if _, err := c.BatchV1().Jobs(genesisNS).Get(ctx, genesisJobName, metav1.GetOptions{}); err == nil {
		zap.S().Debugf("Deleting already existing job")
		if err := c.BatchV1().Jobs(genesisNS).Delete(ctx, genesisJobName, metav1.DeleteOptions{}); err != nil {
			return err
		}
	} else if !k8serr.IsNotFound(err) {
		return err
	}

	if _, err := c.RbacV1().ClusterRoleBindings().Get(ctx, getGenesisRoleBinding().Name, metav1.GetOptions{}); err == nil {
		if err := c.RbacV1().ClusterRoleBindings().Delete(ctx, getGenesisRoleBinding().Name, metav1.DeleteOptions{}); err != nil {
			return err
		}
	} else if !k8serr.IsNotFound(err) {
		return err
	}

	if _, err := c.RbacV1().ClusterRoles().Get(ctx, getGenesisRole().Name, metav1.GetOptions{}); err == nil {
		if err := c.RbacV1().ClusterRoles().Delete(ctx, getGenesisRole().Name, metav1.DeleteOptions{}); err != nil {
			return err
		}

	} else if !k8serr.IsNotFound(err) {
		return err
	}

	if _, err := c.CoreV1().ServiceAccounts(genesisNS).Get(ctx, getGenesisServiceAccount().Name, metav1.GetOptions{}); err == nil {
		if err := c.CoreV1().ServiceAccounts(genesisNS).Delete(ctx, getGenesisServiceAccount().Name, metav1.DeleteOptions{}); err != nil {
			return err
		}

	} else if !k8serr.IsNotFound(err) {
		return err
	}

	return nil
}
