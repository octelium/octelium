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

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
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

func getGenesisJob(domain, regionName string, version string) *batchv1.Job {
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
				Spec: corev1.PodSpec{
					ServiceAccountName: "octelium-genesis",
					RestartPolicy:      corev1.RestartPolicyNever,
					ImagePullSecrets: func() []corev1.LocalObjectReference {

						return nil
						/*
							if ldflags.IsPrivateRegistry() {
								return []corev1.LocalObjectReference{
									{
										Name: "octelium-regcred",
									},
								}
							} else {
								return nil
							}
						*/
					}(),

					Containers: []corev1.Container{
						{
							Name: "octelium-genesis",
							Image: func() string {
								if version != "" {
									return cliutils.GetGenesisImage(version)
								}
								if ldflags.IsDev() {
									return cliutils.GetGenesisImage("")
								} else {
									return cliutils.GetGenesisImage("latest")
								}
							}(),
							ImagePullPolicy: corev1.PullAlways,
							Args:            []string{"init"},
							/*
								Env: func() []corev1.EnvVar {
									ret := []corev1.EnvVar{
										{
											Name:  "OCTELIUM_DOMAIN",
											Value: domain,
										},
										{
											Name:  "OCTELIUM_REGION_NAME",
											Value: regionName,
										},
									}

									return ret
								}(),
							*/
						},
					},
				},
			},
		},
	}
}

func createGenesis(ctx context.Context, o *Opts) error {

	c := o.K8sC
	if err := cleanupResources(ctx, o.K8sC, o.ClusterDomain, o.Region.Metadata.Name, o.Version); err != nil {
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
		getGenesisJob(o.ClusterDomain, o.Region.Metadata.Name, o.Version), metav1.CreateOptions{})
	if err != nil {
		return err
	}

	return nil
}

func cleanupResources(ctx context.Context, c kubernetes.Interface, domain, regionName string, version string) error {
	zap.S().Debugf("Cleaning up resources if existent")
	if _, err := c.BatchV1().Jobs(genesisNS).Get(ctx, getGenesisJob(domain, regionName, version).Name, metav1.GetOptions{}); err == nil {
		zap.S().Debugf("Deleting already existing job")
		if err := c.BatchV1().Jobs(genesisNS).Delete(ctx, getGenesisJob(domain, regionName, version).Name, metav1.DeleteOptions{}); err != nil {
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
