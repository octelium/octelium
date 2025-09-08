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

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type K8sClientOpts struct {
}

func NewClient(ctx context.Context, o *K8sClientOpts) (*kubernetes.Clientset, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	cfg.QPS = 100
	cfg.Burst = 200

	k8sC, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	return k8sC, nil
}
