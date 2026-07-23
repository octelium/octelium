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
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestRegion(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	itemList, err := srv.ListRegion(ctx, &corev1.ListRegionOptions{})
	assert.Nil(t, err, "%+v", err)

	if len(itemList.Items) > 0 {
		region := itemList.Items[0]

		ret, err := srv.GetRegion(ctx, &metav1.GetOptions{Uid: region.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, region.Metadata.Uid, ret.Metadata.Uid)

		ret, err = srv.GetRegion(ctx, &metav1.GetOptions{Name: region.Metadata.Name})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, region.Metadata.Uid, ret.Metadata.Uid)
	}

	{
		_, err = srv.GetRegion(ctx, &metav1.GetOptions{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err = srv.GetRegion(ctx, &metav1.GetOptions{Name: utilrand.GetRandomStringCanonical(8)})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		_, err = srv.ListRegion(ctx, nil)
		assert.NotNil(t, err)
	}
}
