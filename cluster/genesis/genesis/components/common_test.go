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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
)

func TestComponents(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg := &corev1.ClusterConfig{
		Metadata: &metav1.Metadata{},
		Spec:     &corev1.ClusterConfig_Spec{},
		Status: &corev1.ClusterConfig_Status{
			Domain: "example.com",
		},
	}

	region := &corev1.Region{
		Metadata: &metav1.Metadata{
			Name: "default",
		},
		Spec:   &corev1.Region_Spec{},
		Status: &corev1.Region_Status{},
	}

	doInstall := func() {
		{
			err := CreateGatewayAgent(ctx, fakeC.K8sC, clusterCfg, region)
			assert.Nil(t, err)
		}

		{
			err := CreateNocturne(ctx, fakeC.K8sC, clusterCfg, region)
			assert.Nil(t, err)
		}

		{
			err := CreateIngress(ctx, fakeC.K8sC, clusterCfg, region)
			assert.Nil(t, err)
		}
	}

	doInstall()
	// for upgrades
	doInstall()
}
