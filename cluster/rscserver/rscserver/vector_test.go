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
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rvectorv1"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func hasRedisSearch(t *testing.T) bool {
	redisC := redisutils.NewClient()
	defer redisC.Close()

	err := redisC.FT_List(context.Background()).Err()
	if err == nil {
		return true
	}

	assert.True(t, isRedisUnknownCommandErr(err), "%+v", err)
	return false
}

func newTestSrvVectorFallback() *srvVector {
	redisC := redisutils.NewClient()
	return &srvVector{
		redisC: redisC,
		backend: &vectorBackendFallback{
			redisC: redisC,
		},
	}
}

func newTestSrvVectorSearch() *srvVector {
	redisC := redisutils.NewClient()
	return &srvVector{
		redisC:  redisC,
		backend: newVectorBackendSearch(redisC),
	}
}

func runTestVectorBackends(t *testing.T, fn func(t *testing.T, srv *srvVector)) {
	t.Run("fallback", func(t *testing.T) {
		fn(t, newTestSrvVectorFallback())
	})

	if !hasRedisSearch(t) {
		return
	}

	t.Run("search", func(t *testing.T) {
		fn(t, newTestSrvVectorSearch())
	})
}

func TestVector(t *testing.T) {
	runTestVectorBackends(t, doTestVector)
}

func doTestVector(t *testing.T, srv *srvVector) {

	ctx := context.Background()

	collection := []byte(utilrand.GetRandomString(8))
	partition := []byte(utilrand.GetRandomString(8))

	t.Cleanup(func() {
		srv.DeleteCollection(context.Background(), &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
	})

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: []float32{1, 0},
				},
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Entries: []*rvectorv1.Entry{
				{
					Vector: []float32{1, 0},
				},
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Entries: []*rvectorv1.Entry{
				{
					Id: []byte("id-1"),
				},
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: []float32{1, float32(math.NaN())},
				},
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: []float32{0, 0},
				},
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: []float32{1, 0},
				},
				{
					Id:     []byte("id-2"),
					Vector: []float32{1, 0, 0},
				},
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, resp.Results)
	}

	{
		resp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1")},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, resp.Results)
	}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: []float32{1, 0},
					Data:   []byte("data-1"),
				},
				{
					Id:     []byte("id-2"),
					Vector: []float32{0.9, 0.1},
					Data:   []byte("data-2"),
				},
				{
					Id:     []byte("id-3"),
					Vector: []float32{0, 1},
					Data:   []byte("data-3"),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
	}

	{
		resp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-2"), []byte("id-9")},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(resp.Results))
		assert.Equal(t, []byte("id-2"), resp.Results[0].Id)
		assert.Equal(t, []byte("data-2"), resp.Results[0].Data)
		assert.Zero(t, resp.Results[0].Similarity)
	}

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{2, 0},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 3, len(resp.Results))

		assert.Equal(t, []byte("id-1"), resp.Results[0].Id)
		assert.Equal(t, []byte("data-1"), resp.Results[0].Data)
		assert.InDelta(t, 1, resp.Results[0].Similarity, 0.0001)

		assert.Equal(t, []byte("id-2"), resp.Results[1].Id)
		assert.Equal(t, []byte("id-3"), resp.Results[2].Id)
		assert.Zero(t, resp.Results[2].Similarity)
	}

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection:    collection,
			Partition:     partition,
			Vector:        []float32{1, 0},
			MinSimilarity: 0.9,
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(resp.Results))
		assert.Equal(t, []byte("id-1"), resp.Results[0].Id)
		assert.Equal(t, []byte("id-2"), resp.Results[1].Id)
	}

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0},
			Limit:      1,
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(resp.Results))
		assert.Equal(t, []byte("id-1"), resp.Results[0].Id)
	}

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0, 0},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, resp.Results)
	}

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  []byte(utilrand.GetRandomString(8)),
			Vector:     []float32{1, 0},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, resp.Results)
	}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: []float32{0, 1},
					Data:   []byte("data-1-updated"),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection:    collection,
			Partition:     partition,
			Vector:        []float32{0, 1},
			MinSimilarity: 0.99,
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(resp.Results))

		getResp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1")},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(getResp.Results))
		assert.Equal(t, []byte("data-1-updated"), getResp.Results[0].Data)
	}

	{
		_, err := srv.DeleteVectors(ctx, &rvectorv1.DeleteVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1"), []byte("id-9")},
		})
		assert.Nil(t, err, "%+v", err)

		resp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1")},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, resp.Results)

		searchResp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(searchResp.Results))
	}

	{
		_, err := srv.DeleteCollection(ctx, &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
		assert.Nil(t, err, "%+v", err)

		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, resp.Results)

		getResp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-2")},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, getResp.Results)
	}
}

func TestVectorTTL(t *testing.T) {
	runTestVectorBackends(t, doTestVectorTTL)
}

func doTestVectorTTL(t *testing.T, srv *srvVector) {

	ctx := context.Background()

	collection := []byte(utilrand.GetRandomString(8))
	partition := []byte(utilrand.GetRandomString(8))

	t.Cleanup(func() {
		srv.DeleteCollection(context.Background(), &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
	})

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: []float32{1, 0},
					Data:   []byte("data-1"),
				},
			},
			Duration: &metav1.Duration{
				Type: &metav1.Duration_Seconds{
					Seconds: 2,
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
	}

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(resp.Results))
	}

	time.Sleep(3 * time.Second)

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, resp.Results)

		getResp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1")},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, getResp.Results)
	}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-2"),
					Vector: []float32{1, 0},
					Data:   []byte("data-2"),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
	}

	time.Sleep(3 * time.Second)

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(resp.Results))
		assert.Equal(t, []byte("id-2"), resp.Results[0].Id)
	}
}

func TestVectorMaxPartitionEntries(t *testing.T) {
	runTestVectorBackends(t, doTestVectorMaxPartitionEntries)
}

func doTestVectorMaxPartitionEntries(t *testing.T, srv *srvVector) {

	ctx := context.Background()

	collection := []byte(utilrand.GetRandomString(8))
	partition := []byte(utilrand.GetRandomString(8))

	t.Cleanup(func() {
		srv.DeleteCollection(context.Background(), &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
	})

	total := maxVectorPartitionEntries + maxVectorEntries

	for i := 0; i < total; i += maxVectorEntries {
		req := &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
		}
		for j := range maxVectorEntries {
			req.Entries = append(req.Entries, &rvectorv1.Entry{
				Id:     []byte(fmt.Sprintf("id-%06d", i+j)),
				Vector: []float32{float32(i + j + 1), 1},
				Data:   []byte(fmt.Sprintf("data-%06d", i+j)),
			})
		}

		_, err := srv.UpsertVectors(ctx, req)
		assert.Nil(t, err, "%+v", err)
	}

	{
		resp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids: [][]byte{
				[]byte(fmt.Sprintf("id-%06d", 0)),
				[]byte(fmt.Sprintf("id-%06d", total-1)),
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(resp.Results))
		assert.Equal(t, []byte(fmt.Sprintf("id-%06d", total-1)), resp.Results[0].Id)
	}

	{
		_, err := srv.DeleteCollection(ctx, &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
		assert.Nil(t, err, "%+v", err)

		resp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte(fmt.Sprintf("id-%06d", total-1))},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, resp.Results)
	}
}

func TestVectorSearchInvalidMinSimilarity(t *testing.T) {
	runTestVectorBackends(t, doTestVectorSearchInvalidMinSimilarity)
}

func doTestVectorSearchInvalidMinSimilarity(t *testing.T, srv *srvVector) {

	ctx := context.Background()
	collection := []byte(utilrand.GetRandomString(8))

	for _, minSimilarity := range []float32{
		float32(math.NaN()),
		float32(math.Inf(1)),
		-0.5,
		1.5,
	} {
		_, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection:    collection,
			Vector:        []float32{1, 0},
			MinSimilarity: minSimilarity,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection:    collection,
			Vector:        []float32{1, 0},
			MinSimilarity: 1,
		})
		assert.Nil(t, err, "%+v", err)
	}
}

func TestVectorFallbackKeys(t *testing.T) {

	srv := newTestSrvVectorFallback()

	ctx := context.Background()

	collection := []byte(utilrand.GetRandomString(8))
	partition := []byte(utilrand.GetRandomString(8))
	keys := getVectorKeys(collection, partition)

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: []float32{1, 0},
					Data:   []byte("data-1"),
				},
			},
			Duration: &metav1.Duration{
				Type: &metav1.Duration_Minutes{
					Minutes: 10,
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		for _, key := range keys {
			ttl, err := srv.redisC.TTL(ctx, key).Result()
			assert.Nil(t, err, "%+v", err)
			assert.True(t, ttl > 0, "%s: %s", key, ttl)
		}
	}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-2"),
					Vector: []float32{0, 1},
					Data:   []byte("data-2"),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		for _, key := range keys {
			ttl, err := srv.redisC.TTL(ctx, key).Result()
			assert.Nil(t, err, "%+v", err)
			assert.True(t, ttl < 0, "%s: %s", key, ttl)
		}
	}

	{
		_, err := srv.DeleteVectors(ctx, &rvectorv1.DeleteVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-2")},
		})
		assert.Nil(t, err, "%+v", err)

		for _, key := range keys {
			ttl, err := srv.redisC.TTL(ctx, key).Result()
			assert.Nil(t, err, "%+v", err)
			assert.True(t, ttl > 0, "%s: %s", key, ttl)
		}
	}

	{
		_, err := srv.DeleteVectors(ctx, &rvectorv1.DeleteVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1")},
		})
		assert.Nil(t, err, "%+v", err)

		for _, key := range keys {
			exists, err := srv.redisC.Exists(ctx, key).Result()
			assert.Nil(t, err, "%+v", err)
			assert.Zero(t, exists, "%s", key)
		}
	}
}

func TestVectorFallbackMaxPartitionEntries(t *testing.T) {

	srv := newTestSrvVectorFallback()

	ctx := context.Background()

	collection := []byte(utilrand.GetRandomString(8))
	partition := []byte(utilrand.GetRandomString(8))
	keys := getVectorKeys(collection, partition)

	t.Cleanup(func() {
		srv.DeleteCollection(context.Background(), &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
	})

	total := maxVectorPartitionEntries + maxVectorEntries

	for i := 0; i < total; i += maxVectorEntries {
		req := &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
		}
		for j := range maxVectorEntries {
			req.Entries = append(req.Entries, &rvectorv1.Entry{
				Id:     []byte(fmt.Sprintf("id-%06d", i+j)),
				Vector: []float32{float32(i + j + 1), 1},
				Data:   []byte(fmt.Sprintf("data-%06d", i+j)),
			})
		}

		_, err := srv.UpsertVectors(ctx, req)
		assert.Nil(t, err, "%+v", err)
	}

	{
		card, err := srv.redisC.ZCard(ctx, keys[0]).Result()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, int64(maxVectorPartitionEntries), card)

		vecLen, err := srv.redisC.HLen(ctx, keys[1]).Result()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, int64(maxVectorPartitionEntries), vecLen)

		dataLen, err := srv.redisC.HLen(ctx, keys[2]).Result()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, int64(maxVectorPartitionEntries), dataLen)
	}
}

func TestVectorSearchPartitionEntries(t *testing.T) {

	if !hasRedisSearch(t) {
		t.Skip("Redis Search is unavailable")
	}

	srv := newTestSrvVectorSearch()

	ctx := context.Background()

	collection := []byte(utilrand.GetRandomString(8))
	partition := []byte(utilrand.GetRandomString(8))

	t.Cleanup(func() {
		srv.DeleteCollection(context.Background(), &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
	})

	total := maxVectorPartitionEntries + maxVectorEntries

	for i := 0; i < total; i += maxVectorEntries {
		req := &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
		}
		for j := range maxVectorEntries {
			req.Entries = append(req.Entries, &rvectorv1.Entry{
				Id:     []byte(fmt.Sprintf("id-%06d", i+j)),
				Vector: []float32{float32(i + j + 1), 1},
				Data:   []byte(fmt.Sprintf("data-%06d", i+j)),
			})
		}

		_, err := srv.UpsertVectors(ctx, req)
		assert.Nil(t, err, "%+v", err)
	}

	{
		res, err := srv.redisC.FTSearchWithArgs(ctx, getVectorSearchIndex(2),
			getVectorSearchPartitionFilter(collection, partition),
			&redis.FTSearchOptions{
				CountOnly:      true,
				DialectVersion: vectorSearchDialect,
			}).Result()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, maxVectorPartitionEntries, res.Total)
	}

	{
		_, err := srv.DeleteCollection(ctx, &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
		assert.Nil(t, err, "%+v", err)

		res, err := srv.redisC.FTSearchWithArgs(ctx, getVectorSearchIndex(2),
			getVectorSearchCollectionFilter(collection),
			&redis.FTSearchOptions{
				CountOnly:      true,
				DialectVersion: vectorSearchDialect,
			}).Result()
		assert.Nil(t, err, "%+v", err)
		assert.Zero(t, res.Total)

		keys, err := srv.redisC.Keys(ctx,
			fmt.Sprintf("%s:%s:*", vectorSearchDataPrefix,
				vutils.Sha256SumHex(collection))).Result()
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, keys)
	}
}

func TestVectorSearchIsolatedFromFallback(t *testing.T) {

	if !hasRedisSearch(t) {
		t.Skip("Redis Search is unavailable")
	}

	ctx := context.Background()

	collection := []byte(utilrand.GetRandomString(8))
	partition := []byte(utilrand.GetRandomString(8))

	fallbackSrv := newTestSrvVectorFallback()
	searchSrv := newTestSrvVectorSearch()

	t.Cleanup(func() {
		fallbackSrv.DeleteCollection(context.Background(), &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
		searchSrv.DeleteCollection(context.Background(), &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
	})

	{
		_, err := fallbackSrv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: []float32{1, 0},
					Data:   []byte("fallback"),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
	}

	{
		resp, err := searchSrv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, resp.Results)
	}
}

func TestVectorUtils(t *testing.T) {
	{
		vec := []float32{3, 4}
		normalized := normalizeVector(vec)
		assert.InDelta(t, 0.6, normalized[0], 0.0001)
		assert.InDelta(t, 0.8, normalized[1], 0.0001)
	}

	{
		vec := []float32{0, 0}
		assert.Equal(t, vec, normalizeVector(vec))
	}

	{
		vec := []float32{1, -2.5, 3.75}
		assert.Equal(t, vec, decodeVector(string(encodeVector(vec))))
	}

	{
		assert.Nil(t, decodeVector(""))
		assert.Nil(t, decodeVector("abc"))
	}

	{
		assert.InDelta(t, 1, getVectorSimilarity(
			normalizeVector([]float32{1, 1}), normalizeVector([]float32{2, 2})), 0.0001)
		assert.Zero(t, getVectorSimilarity(
			normalizeVector([]float32{1, 0}), normalizeVector([]float32{-1, 0})))
		assert.InDelta(t, 0, getVectorSimilarity(
			normalizeVector([]float32{1, 0}), normalizeVector([]float32{0, 1})), 0.0001)
	}

	{
		assert.Zero(t, clampVectorSimilarity(math.NaN()))
		assert.Zero(t, clampVectorSimilarity(-1))
		assert.EqualValues(t, 1, clampVectorSimilarity(2))
		assert.EqualValues(t, 0.5, clampVectorSimilarity(0.5))
	}

	{
		assert.NotEqual(t, getVectorKeys([]byte("a"), []byte("b")),
			getVectorKeys([]byte("b"), []byte("a")))
	}

	{
		key := getVectorSearchEntryKey(384, []byte("a"), []byte("b"), []byte("c"))
		assert.True(t, strings.HasPrefix(key, getVectorSearchEntryPrefix(384)))

		dataKey, ok := getVectorSearchEntryDataKey(key)
		assert.True(t, ok)
		assert.Equal(t, getVectorSearchDataKey([]byte("a"), []byte("b"), []byte("c")), dataKey)

		_, ok = getVectorSearchEntryDataKey("octelium:vec:e:384")
		assert.False(t, ok)
	}

	{
		assert.NotEqual(t, getVectorSearchEntryKey(384, []byte("a"), []byte("b"), []byte("c")),
			getVectorSearchEntryKey(768, []byte("a"), []byte("b"), []byte("c")))
	}
}
