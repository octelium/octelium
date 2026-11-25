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

	"github.com/octelium/octelium/cluster/common/k8sretry"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	k8scorev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const componentGenesis = "genesis"

const initGenesisNS = "default"

func getGenesisServiceAccount() *k8scorev1.ServiceAccount {
	return &k8scorev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      getComponentName(componentGenesis),
			Namespace: ns,
		},
	}
}

func getGenesisRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: getComponentName(componentGenesis),
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

func getGenesisRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: getComponentName(componentGenesis),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     getComponentName(componentGenesis),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      getComponentName(componentGenesis),
				Namespace: ns,
			},
		},
	}
}

func getInitGenesisSubject() rbacv1.Subject {
	return rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      getComponentName(componentGenesis),
		Namespace: initGenesisNS,
	}
}

func CreateGenesisIdentity(ctx context.Context, o *CommonOpts, isInit bool) error {

	if _, err := k8sutils.CreateOrUpdateServiceAccount(ctx, o.K8sC, getGenesisServiceAccount()); err != nil {
		return err
	}

	if _, err := k8sutils.CreateOrUpdateClusterRole(ctx, o.K8sC, getGenesisRole()); err != nil {
		return err
	}

	if isInit {
		if _, err := k8sutils.CreateOrUpdateClusterRoleBindingSubjects(ctx, o.K8sC, getGenesisRoleBinding(), nil); err != nil {
			return err
		}

		return nil
	}

	if _, err := k8sutils.CreateOrUpdateClusterRoleBindingSubjects(ctx, o.K8sC,
		getGenesisRoleBinding(), []rbacv1.Subject{getInitGenesisSubject()}); err != nil {
		return err
	}

	return deleteInitGenesisServiceAccount(ctx, o)
}

func deleteInitGenesisServiceAccount(ctx context.Context, o *CommonOpts) error {
	serviceAccounts := o.K8sC.CoreV1().ServiceAccounts(initGenesisNS)
	name := getComponentName(componentGenesis)

	sa, err := k8sretry.Read(ctx, func(ctx context.Context) (*k8scorev1.ServiceAccount, error) {
		return serviceAccounts.Get(ctx, name, metav1.GetOptions{})
	})
	if k8serr.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}

	return k8sretry.Delete(ctx, sa,
		func(ctx context.Context) (*k8scorev1.ServiceAccount, error) {
			return serviceAccounts.Get(ctx, name, metav1.GetOptions{})
		},
		func(ctx context.Context, options metav1.DeleteOptions) error {
			return serviceAccounts.Delete(ctx, name, options)
		})
}
