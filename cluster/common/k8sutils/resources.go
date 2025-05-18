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

package k8sutils

import (
	"context"

	"github.com/octelium/octelium/cluster/common/vutils"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func CreateOrUpdateDeployment(ctx context.Context, c kubernetes.Interface, itm *appsv1.Deployment) (*appsv1.Deployment, error) {
	ret, err := c.AppsV1().Deployments(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.AppsV1().Deployments(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	oldItem.Annotations["octelium.com/last-upgrade"] = vutils.NowRFC3339Nano()
	oldItem.ObjectMeta.OwnerReferences = itm.OwnerReferences
	oldItem.Spec = itm.Spec

	return c.AppsV1().Deployments(itm.Namespace).Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}

func CreateOrUpdateService(ctx context.Context, c kubernetes.Interface, itm *corev1.Service) (*corev1.Service, error) {
	ret, err := c.CoreV1().Services(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.CoreV1().Services(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	oldItem.Spec.Ports = itm.Spec.Ports
	oldItem.Spec.Selector = itm.Spec.Selector
	oldItem.ObjectMeta.OwnerReferences = itm.OwnerReferences

	return c.CoreV1().Services(itm.Namespace).Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}

func CreateOrUpdateSecret(ctx context.Context, c kubernetes.Interface, itm *corev1.Secret) (*corev1.Secret, error) {
	ret, err := c.CoreV1().Secrets(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.CoreV1().Secrets(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	oldItem.Data = itm.Data
	oldItem.StringData = itm.StringData
	oldItem.ObjectMeta.OwnerReferences = itm.OwnerReferences
	oldItem.Type = itm.Type

	return c.CoreV1().Secrets(itm.Namespace).Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}

func CreateOrUpdateNetworkPolicy(ctx context.Context, c kubernetes.Interface, itm *networkingv1.NetworkPolicy) (*networkingv1.NetworkPolicy, error) {
	ret, err := c.NetworkingV1().NetworkPolicies(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.NetworkingV1().NetworkPolicies(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	oldItem.Spec = itm.Spec

	return c.NetworkingV1().NetworkPolicies(itm.Namespace).Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}

func CreateOrUpdateDaemonset(ctx context.Context, c kubernetes.Interface, itm *appsv1.DaemonSet) (*appsv1.DaemonSet, error) {
	ret, err := c.AppsV1().DaemonSets(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.AppsV1().DaemonSets(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	oldItem.Spec = itm.Spec

	return c.AppsV1().DaemonSets(itm.Namespace).Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}

func CreateOrUpdateClusterRole(ctx context.Context, c kubernetes.Interface, itm *rbacv1.ClusterRole) (*rbacv1.ClusterRole, error) {
	ret, err := c.RbacV1().ClusterRoles().Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.RbacV1().ClusterRoles().Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err == nil {
		return ret, nil
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	oldItem.Rules = itm.Rules

	return c.RbacV1().ClusterRoles().Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}

func CreateOrUpdateClusterRoleBinding(ctx context.Context, c kubernetes.Interface, itm *rbacv1.ClusterRoleBinding) (*rbacv1.ClusterRoleBinding, error) {
	ret, err := c.RbacV1().ClusterRoleBindings().Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.RbacV1().ClusterRoleBindings().Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err == nil {
		return ret, nil
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	oldItem.RoleRef = itm.RoleRef
	oldItem.Subjects = itm.Subjects

	return c.RbacV1().ClusterRoleBindings().Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}

func CreateOrUpdateConfigMap(ctx context.Context, c kubernetes.Interface, itm *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	ret, err := c.CoreV1().ConfigMaps(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.CoreV1().ConfigMaps(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	oldItem.Data = itm.Data

	return c.CoreV1().ConfigMaps(itm.Namespace).Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}

func CreateOrUpdateServiceAccount(ctx context.Context, c kubernetes.Interface, itm *corev1.ServiceAccount) (*corev1.ServiceAccount, error) {
	ret, err := c.CoreV1().ServiceAccounts(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.CoreV1().ServiceAccounts(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	return c.CoreV1().ServiceAccounts(itm.Namespace).Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}

func CreateOrUpdateIngress(ctx context.Context, c kubernetes.Interface, itm *networkingv1.Ingress) (*networkingv1.Ingress, error) {
	ret, err := c.NetworkingV1().Ingresses(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
	if err == nil {
		return ret, nil
	}

	if !k8serr.IsAlreadyExists(err) {
		return nil, err
	}

	oldItem, err := c.NetworkingV1().Ingresses(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for k, v := range itm.Labels {
		oldItem.Labels[k] = v
	}
	if oldItem.Annotations == nil {
		oldItem.Annotations = make(map[string]string)
	}
	for k, v := range itm.Annotations {
		oldItem.Annotations[k] = v
	}

	oldItem.Spec = itm.Spec

	return c.NetworkingV1().Ingresses(itm.Namespace).Update(ctx, oldItem, k8smetav1.UpdateOptions{})
}
