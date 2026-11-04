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
	"errors"
	"time"

	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/octelium/octelium/cluster/common/vutils"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

var defaultRetryBackoff = wait.Backoff{
	Steps:    15,
	Duration: 400 * time.Millisecond,
	Factor:   1.4,
	Jitter:   0.2,
}

func isTransientError(err error) bool {
	return k8sretry.IsTransient(err)
}

func mergeMetadata(dst, src k8smetav1.Object) {
	labels := dst.GetLabels()
	if labels == nil && len(src.GetLabels()) > 0 {
		labels = make(map[string]string)
	}
	for k, v := range src.GetLabels() {
		labels[k] = v
	}
	dst.SetLabels(labels)

	annotations := dst.GetAnnotations()
	if annotations == nil && len(src.GetAnnotations()) > 0 {
		annotations = make(map[string]string)
	}
	for k, v := range src.GetAnnotations() {
		annotations[k] = v
	}
	dst.SetAnnotations(annotations)
}

func retryableCreateOrUpdate[T any](
	ctx context.Context,
	name string,
	createFunc func(ctx context.Context) (T, error),
	getFunc func(ctx context.Context) (T, error),
	updateFunc func(ctx context.Context, obj T) (T, error),
	modifyFunc func(obj T),
) (T, error) {
	var result T
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if name == "" {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return createFunc(ctx)
	}
	var lastErr error
	var createErr error
	exists := false
	verify := false
	err := k8sretry.Retry(ctx, defaultRetryBackoff, func(ctx context.Context) error {
		if !exists {
			var err error
			result, err = createFunc(ctx)
			createErr = err
			verify = isTransientError(err)
			if err == nil {
				return nil
			}
			lastErr = err
			if !k8serr.IsAlreadyExists(err) && !isTransientError(err) {
				return err
			}
			exists = true
		}
		oldItem, err := getFunc(ctx)
		if err != nil {
			lastErr = err
			if k8serr.IsNotFound(err) {
				exists = false
				if isTransientError(createErr) {
					lastErr = createErr
					return createErr
				}
				return k8serr.NewConflict(schema.GroupResource{}, "", err)
			}
			return err
		}
		var before runtime.Object
		if obj, ok := any(oldItem).(runtime.Object); ok {
			before = obj.DeepCopyObject()
			oldItem = any(obj.DeepCopyObject()).(T)
		}
		modifyFunc(oldItem)
		if verify && before != nil && apiequality.Semantic.DeepEqual(before, oldItem) {
			result = oldItem
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err = updateFunc(ctx, oldItem)
		verify = isTransientError(err)
		lastErr = err
		if k8serr.IsNotFound(err) || k8serr.IsAlreadyExists(err) {
			exists = false
			return k8serr.NewConflict(schema.GroupResource{}, "", err)
		}
		return err
	})
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err != nil && lastErr != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		return result, lastErr
	}
	return result, err
}

func CreateOrUpdateDeployment(ctx context.Context, c kubernetes.Interface, itm *appsv1.Deployment) (*appsv1.Deployment, error) {
	upgradeAt := vutils.NowRFC3339Nano()
	return retryableCreateOrUpdate(
		ctx, itm.Name,
		func(ctx context.Context) (*appsv1.Deployment, error) {
			return c.AppsV1().Deployments(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*appsv1.Deployment, error) {
			return c.AppsV1().Deployments(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, old *appsv1.Deployment) (*appsv1.Deployment, error) {
			return c.AppsV1().Deployments(itm.Namespace).Update(ctx, old, k8smetav1.UpdateOptions{})
		},
		func(old *appsv1.Deployment) {
			mergeMetadata(old, itm)
			ann := old.GetAnnotations()
			if ann == nil {
				ann = make(map[string]string)
			}
			ann["octelium.com/last-upgrade"] = upgradeAt
			old.SetAnnotations(ann)
			old.OwnerReferences = itm.OwnerReferences
			old.Spec = itm.Spec
		},
	)
}

func CreateOrUpdateDaemonset(ctx context.Context, c kubernetes.Interface, itm *appsv1.DaemonSet) (*appsv1.DaemonSet, error) {
	return retryableCreateOrUpdate(
		ctx, itm.Name,
		func(ctx context.Context) (*appsv1.DaemonSet, error) {
			return c.AppsV1().DaemonSets(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*appsv1.DaemonSet, error) {
			return c.AppsV1().DaemonSets(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, old *appsv1.DaemonSet) (*appsv1.DaemonSet, error) {
			return c.AppsV1().DaemonSets(itm.Namespace).Update(ctx, old, k8smetav1.UpdateOptions{})
		},
		func(old *appsv1.DaemonSet) {
			mergeMetadata(old, itm)
			old.OwnerReferences = itm.OwnerReferences
			old.Spec = itm.Spec
		},
	)
}

func CreateOrUpdateService(ctx context.Context, c kubernetes.Interface, itm *corev1.Service) (*corev1.Service, error) {
	return retryableCreateOrUpdate(
		ctx, itm.Name,
		func(ctx context.Context) (*corev1.Service, error) {
			return c.CoreV1().Services(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*corev1.Service, error) {
			return c.CoreV1().Services(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, old *corev1.Service) (*corev1.Service, error) {
			return c.CoreV1().Services(itm.Namespace).Update(ctx, old, k8smetav1.UpdateOptions{})
		},
		func(old *corev1.Service) {
			mergeMetadata(old, itm)
			old.OwnerReferences = itm.OwnerReferences
			old.Spec.Ports = itm.Spec.Ports
			old.Spec.Selector = itm.Spec.Selector
			old.Spec.Type = itm.Spec.Type
		},
	)
}

func CreateOrUpdateSecret(ctx context.Context, c kubernetes.Interface, itm *corev1.Secret) (*corev1.Secret, error) {
	return retryableCreateOrUpdate(
		ctx, itm.Name,
		func(ctx context.Context) (*corev1.Secret, error) {
			return c.CoreV1().Secrets(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*corev1.Secret, error) {
			return c.CoreV1().Secrets(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, old *corev1.Secret) (*corev1.Secret, error) {
			return c.CoreV1().Secrets(itm.Namespace).Update(ctx, old, k8smetav1.UpdateOptions{})
		},
		func(old *corev1.Secret) {
			mergeMetadata(old, itm)
			old.OwnerReferences = itm.OwnerReferences
			old.Type = itm.Type
			old.Data = itm.Data
			old.StringData = itm.StringData
		},
	)
}

func CreateOrUpdateConfigMap(ctx context.Context, c kubernetes.Interface, itm *corev1.ConfigMap) (*corev1.ConfigMap, error) {
	return retryableCreateOrUpdate(
		ctx, itm.Name,
		func(ctx context.Context) (*corev1.ConfigMap, error) {
			return c.CoreV1().ConfigMaps(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*corev1.ConfigMap, error) {
			return c.CoreV1().ConfigMaps(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, old *corev1.ConfigMap) (*corev1.ConfigMap, error) {
			return c.CoreV1().ConfigMaps(itm.Namespace).Update(ctx, old, k8smetav1.UpdateOptions{})
		},
		func(old *corev1.ConfigMap) {
			mergeMetadata(old, itm)
			old.OwnerReferences = itm.OwnerReferences
			old.Data = itm.Data
			old.BinaryData = itm.BinaryData
		},
	)
}

func CreateOrUpdateServiceAccount(ctx context.Context, c kubernetes.Interface, itm *corev1.ServiceAccount) (*corev1.ServiceAccount, error) {
	return retryableCreateOrUpdate(
		ctx, itm.Name,
		func(ctx context.Context) (*corev1.ServiceAccount, error) {
			return c.CoreV1().ServiceAccounts(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*corev1.ServiceAccount, error) {
			return c.CoreV1().ServiceAccounts(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, old *corev1.ServiceAccount) (*corev1.ServiceAccount, error) {
			return c.CoreV1().ServiceAccounts(itm.Namespace).Update(ctx, old, k8smetav1.UpdateOptions{})
		},
		func(old *corev1.ServiceAccount) {
			mergeMetadata(old, itm)
			old.OwnerReferences = itm.OwnerReferences
		},
	)
}

func CreateOrUpdateNetworkPolicy(ctx context.Context, c kubernetes.Interface, itm *networkingv1.NetworkPolicy) (*networkingv1.NetworkPolicy, error) {
	return retryableCreateOrUpdate(
		ctx, itm.Name,
		func(ctx context.Context) (*networkingv1.NetworkPolicy, error) {
			return c.NetworkingV1().NetworkPolicies(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*networkingv1.NetworkPolicy, error) {
			return c.NetworkingV1().NetworkPolicies(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, old *networkingv1.NetworkPolicy) (*networkingv1.NetworkPolicy, error) {
			return c.NetworkingV1().NetworkPolicies(itm.Namespace).Update(ctx, old, k8smetav1.UpdateOptions{})
		},
		func(old *networkingv1.NetworkPolicy) {
			mergeMetadata(old, itm)
			old.OwnerReferences = itm.OwnerReferences
			old.Spec = itm.Spec
		},
	)
}

func CreateOrUpdateIngress(ctx context.Context, c kubernetes.Interface, itm *networkingv1.Ingress) (*networkingv1.Ingress, error) {
	return retryableCreateOrUpdate(
		ctx, itm.Name,
		func(ctx context.Context) (*networkingv1.Ingress, error) {
			return c.NetworkingV1().Ingresses(itm.Namespace).Create(ctx, itm, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*networkingv1.Ingress, error) {
			return c.NetworkingV1().Ingresses(itm.Namespace).Get(ctx, itm.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, old *networkingv1.Ingress) (*networkingv1.Ingress, error) {
			return c.NetworkingV1().Ingresses(itm.Namespace).Update(ctx, old, k8smetav1.UpdateOptions{})
		},
		func(old *networkingv1.Ingress) {
			mergeMetadata(old, itm)
			old.OwnerReferences = itm.OwnerReferences
			old.Spec = itm.Spec
		},
	)
}

func CreateOrUpdateClusterRole(ctx context.Context, c kubernetes.Interface, itm *rbacv1.ClusterRole) (*rbacv1.ClusterRole, error) {
	return retryableCreateOrUpdate(
		ctx, itm.Name,
		func(ctx context.Context) (*rbacv1.ClusterRole, error) {
			return c.RbacV1().ClusterRoles().Create(ctx, itm, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*rbacv1.ClusterRole, error) {
			return c.RbacV1().ClusterRoles().Get(ctx, itm.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, old *rbacv1.ClusterRole) (*rbacv1.ClusterRole, error) {
			return c.RbacV1().ClusterRoles().Update(ctx, old, k8smetav1.UpdateOptions{})
		},
		func(old *rbacv1.ClusterRole) {
			mergeMetadata(old, itm)
			old.OwnerReferences = itm.OwnerReferences
			old.Rules = itm.Rules
			old.AggregationRule = itm.AggregationRule
		},
	)
}

func CreateOrUpdateClusterRoleBinding(ctx context.Context, c kubernetes.Interface, itm *rbacv1.ClusterRoleBinding) (*rbacv1.ClusterRoleBinding, error) {
	replace := false
	return retryableCreateOrUpdate(
		ctx, itm.Name,
		func(ctx context.Context) (*rbacv1.ClusterRoleBinding, error) {
			return c.RbacV1().ClusterRoleBindings().Create(ctx, itm, k8smetav1.CreateOptions{})
		},
		func(ctx context.Context) (*rbacv1.ClusterRoleBinding, error) {
			return c.RbacV1().ClusterRoleBindings().Get(ctx, itm.Name, k8smetav1.GetOptions{})
		},
		func(ctx context.Context, old *rbacv1.ClusterRoleBinding) (*rbacv1.ClusterRoleBinding, error) {
			if replace {
				deleteErr := c.RbacV1().ClusterRoleBindings().Delete(
					ctx, old.Name, k8smetav1.DeleteOptions{Preconditions: &k8smetav1.Preconditions{UID: &old.UID, ResourceVersion: &old.ResourceVersion}},
				)
				if deleteErr != nil && !k8serr.IsNotFound(deleteErr) {
					return nil, deleteErr
				}
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return c.RbacV1().ClusterRoleBindings().Create(ctx, itm, k8smetav1.CreateOptions{})
			}
			return c.RbacV1().ClusterRoleBindings().Update(ctx, old, k8smetav1.UpdateOptions{})
		},
		func(old *rbacv1.ClusterRoleBinding) {
			mergeMetadata(old, itm)
			old.OwnerReferences = itm.OwnerReferences
			old.Subjects = itm.Subjects
			replace = old.RoleRef != itm.RoleRef
			old.RoleRef = itm.RoleRef
		},
	)
}
