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
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func TestCacheBinaryAndOverwrite(t *testing.T) {
	ctx := t.Context()
	srv := &srvCache{redisC: redisutils.NewClient()}
	t.Cleanup(func() { srv.redisC.Close() })

	key := append(utilrand.GetRandomBytesMust(32), 0, 255, ':', '*')
	t.Cleanup(func() { srv.redisC.Del(context.Background(), srv.getRedisCacheKey(key)) })
	data := []byte{0, 255, 128, 1}
	_, err := srv.SetCache(ctx, &rcachev1.SetCacheRequest{Key: key, Data: data, Duration: durSeconds(30)})
	require.Nil(t, err)

	got, err := srv.GetCache(ctx, &rcachev1.GetCacheRequest{Key: key})
	require.Nil(t, err)
	assert.Equal(t, data, got.Data)

	_, err = srv.SetCache(ctx, &rcachev1.SetCacheRequest{Key: key})
	require.Nil(t, err)
	got, err = srv.GetCache(ctx, &rcachev1.GetCacheRequest{Key: key})
	require.Nil(t, err)
	assert.Empty(t, got.Data)
	ttl, err := srv.redisC.PTTL(ctx, srv.getRedisCacheKey(key)).Result()
	require.Nil(t, err)
	assert.Equal(t, -time.Nanosecond, ttl)

	other := append(bytes.Clone(key), 0)
	_, err = srv.GetCache(ctx, &rcachev1.GetCacheRequest{Key: other})
	assert.True(t, grpcerr.IsNotFound(err))
}

func TestCacheGetDeleteConcurrent(t *testing.T) {
	ctx := t.Context()
	srv := &srvCache{redisC: redisutils.NewClient()}
	t.Cleanup(func() { srv.redisC.Close() })
	key := utilrand.GetRandomBytesMust(32)
	data := utilrand.GetRandomBytesMust(128)
	_, err := srv.SetCache(ctx, &rcachev1.SetCacheRequest{Key: key, Data: data})
	require.Nil(t, err)
	t.Cleanup(func() { srv.redisC.Del(context.Background(), srv.getRedisCacheKey(key)) })

	var wg sync.WaitGroup
	results := make(chan *rcachev1.GetCacheResponse, 64)
	start := make(chan struct{})
	for range 64 {
		wg.Go(func() {
			<-start
			res, err := srv.GetCache(ctx, &rcachev1.GetCacheRequest{Key: key, Delete: true})
			if err != nil {
				assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
				return
			}
			results <- res
		})
	}
	close(start)
	wg.Wait()
	close(results)
	require.Len(t, results, 1)
	assert.Equal(t, data, (<-results).Data)
	_, err = srv.GetCache(ctx, &rcachev1.GetCacheRequest{Key: key})
	assert.True(t, grpcerr.IsNotFound(err))
}

func TestCacheErrors(t *testing.T) {
	srv := &srvCache{redisC: redisutils.NewClient()}
	require.Nil(t, srv.redisC.Close())
	ctx := t.Context()

	res, err := srv.SetCache(ctx, &rcachev1.SetCacheRequest{})
	assert.Nil(t, res)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	deleted, err := srv.DeleteCache(ctx, &rcachev1.DeleteCacheRequest{})
	assert.Nil(t, err)
	assert.NotNil(t, deleted)
	for _, del := range []bool{false, true} {
		got, err := srv.GetCache(ctx, &rcachev1.GetCacheRequest{Key: []byte("key"), Delete: del})
		assert.Nil(t, got)
		assert.Equal(t, codes.Internal, status.Code(err))
	}
	deleted, err = srv.DeleteCache(ctx, &rcachev1.DeleteCacheRequest{Key: []byte("key")})
	assert.Nil(t, deleted)
	assert.Equal(t, codes.Internal, status.Code(err))
	res, err = srv.SetCache(ctx, &rcachev1.SetCacheRequest{Key: []byte("key")})
	assert.Nil(t, res)
	assert.NotNil(t, err)
}
