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

package rscserver

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {

	srvCache := &srvCache{
		redisC: redisutils.NewClient(),
	}

	ctx := context.Background()
	{
		_, err := srvCache.GetCache(ctx, &rcachev1.GetCacheRequest{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}
	{
		_, err := srvCache.GetCache(ctx, &rcachev1.GetCacheRequest{
			Key: []byte(utilrand.GetRandomString(8)),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}
	{

		key := utilrand.GetRandomString(8)
		val := utilrand.GetRandomBytesMust(32)
		_, err := srvCache.SetCache(ctx, &rcachev1.SetCacheRequest{
			Key:  []byte(key),
			Data: val,
		})
		assert.Nil(t, err)

		res, err := srvCache.GetCache(ctx, &rcachev1.GetCacheRequest{
			Key: []byte(key),
		})
		assert.Nil(t, err)
		assert.Equal(t, val, res.Data)

		res, err = srvCache.GetCache(ctx, &rcachev1.GetCacheRequest{
			Key:    []byte(key),
			Delete: true,
		})
		assert.Nil(t, err)
		assert.Equal(t, val, res.Data)

		_, err = srvCache.GetCache(ctx, &rcachev1.GetCacheRequest{
			Key: []byte(key),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{

		key := utilrand.GetRandomString(8)
		val := utilrand.GetRandomBytesMust(32)
		_, err := srvCache.SetCache(ctx, &rcachev1.SetCacheRequest{
			Key:  []byte(key),
			Data: val,
			Duration: &metav1.Duration{
				Type: &metav1.Duration_Seconds{
					Seconds: 1,
				},
			},
		})
		assert.Nil(t, err)

		res, err := srvCache.GetCache(ctx, &rcachev1.GetCacheRequest{
			Key: []byte(key),
		})
		assert.Nil(t, err)
		assert.Equal(t, val, res.Data)

		time.Sleep(2 * time.Second)

		_, err = srvCache.GetCache(ctx, &rcachev1.GetCacheRequest{
			Key: []byte(key),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{

		key := utilrand.GetRandomString(8)

		_, err := srvCache.DeleteCache(ctx, &rcachev1.DeleteCacheRequest{
			Key: []byte(key),
		})
		assert.Nil(t, err)

		val := utilrand.GetRandomBytesMust(32)
		_, err = srvCache.SetCache(ctx, &rcachev1.SetCacheRequest{
			Key:  []byte(key),
			Data: val,
			Duration: &metav1.Duration{
				Type: &metav1.Duration_Seconds{
					Seconds: 1,
				},
			},
		})
		assert.Nil(t, err)

		res, err := srvCache.GetCache(ctx, &rcachev1.GetCacheRequest{
			Key: []byte(key),
		})
		assert.Nil(t, err)
		assert.Equal(t, val, res.Data)

		_, err = srvCache.DeleteCache(ctx, &rcachev1.DeleteCacheRequest{
			Key: []byte(key),
		})
		assert.Nil(t, err)

		_, err = srvCache.GetCache(ctx, &rcachev1.GetCacheRequest{
			Key: []byte(key),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))

		_, err = srvCache.DeleteCache(ctx, &rcachev1.DeleteCacheRequest{
			Key: []byte(key),
		})
		assert.Nil(t, err)
	}

}
