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

package admin

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
)

func TestCreateNamespace(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	validNets := []*corev1.Namespace{
		{
			Metadata: &metav1.Metadata{Name: "net-1"},
			Spec:     &corev1.Namespace_Spec{},
		},
	}

	for _, net := range validNets {

		_, err = srv.CreateNamespace(ctx, net)
		assert.Nil(t, err)

	}
}

func TestNamespace(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	validNets := []*corev1.Namespace{
		{
			Metadata: &metav1.Metadata{Name: "net-1"},
			Spec:     &corev1.Namespace_Spec{},
		},
	}

	for _, net := range validNets {

		_, err = srv.CreateNamespace(ctx, net)
		assert.Nil(t, err)
	}

}
