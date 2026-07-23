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
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestGateway(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	{
		_, err = srv.ListGateway(ctx, &corev1.ListGatewayOptions{})
		assert.Nil(t, err, "%+v", err)
	}

	{
		_, err = srv.ListGateway(ctx, nil)
		assert.NotNil(t, err)
	}

	{
		_, err = srv.GetGateway(ctx, &metav1.GetOptions{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err = srv.GetGateway(ctx, &metav1.GetOptions{Name: utilrand.GetRandomStringCanonical(8)})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		regionList, err := srv.ListRegion(ctx, &corev1.ListRegionOptions{})
		assert.Nil(t, err, "%+v", err)

		if len(regionList.Items) > 0 {
			_, err = srv.ListGateway(ctx, &corev1.ListGatewayOptions{
				RegionRef: umetav1.GetObjectReference(regionList.Items[0]),
			})
			assert.Nil(t, err, "%+v", err)
		}
	}

	{
		_, err = srv.ListGateway(ctx, &corev1.ListGatewayOptions{
			RegionRef: &metav1.ObjectReference{},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err = srv.ListGateway(ctx, &corev1.ListGatewayOptions{
			RegionRef: &metav1.ObjectReference{
				Uid: utilrand.GetRandomStringCanonical(8),
			},
		})
		assert.NotNil(t, err)
	}
}
