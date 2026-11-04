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

package genesis

import (
	"context"

	"github.com/octelium/octelium/cluster/common/k8sretry"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (g *Genesis) getK8sSecret(ctx context.Context, namespace, name string) (*corev1.Secret, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*corev1.Secret, error) {
		return g.k8sC.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}

func (g *Genesis) getK8sConfigMap(ctx context.Context, namespace, name string) (*corev1.ConfigMap, error) {
	return k8sretry.Read(ctx, func(ctx context.Context) (*corev1.ConfigMap, error) {
		return g.k8sC.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	})
}
