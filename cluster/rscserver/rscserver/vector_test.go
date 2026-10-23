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
	"sync"
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
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	t.Run("search", func(t *testing.T) {
		if !hasRedisSearch(t) {
			t.Skip("Redis Search is unavailable")
		}
		fn(t, newTestSrvVectorSearch())
	})
}

type fakeVectorSearchIndexHook struct {
	process redis.ProcessHook
}

func (h *fakeVectorSearchIndexHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h *fakeVectorSearchIndexHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return h.process
}

func (h *fakeVectorSearchIndexHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestVectorSearchIndexReady(t *testing.T) {
	redisC := redisutils.NewClient()
	t.Cleanup(func() {
		redisC.Close()
	})

	var gets int
	redisC.AddHook(&fakeVectorSearchIndexHook{
		process: func(ctx context.Context, cmd redis.Cmder) error {
			switch cmd := cmd.(type) {
			case *redis.StatusCmd:
				assert.Equal(t, "ft.create", cmd.Name())
				cmd.SetVal("OK")
			case *redis.FTInfoCmd:
				gets = gets + 1
				var indexing int
				if gets < 3 {
					indexing = 1
				}
				cmd.SetVal(redis.FTInfoResult{Indexing: indexing})
			}
			return nil
		},
	})

	b := newVectorBackendSearch(redisC)
	assert.Nil(t, b.setIndex(context.Background(), 2))
	assert.Equal(t, 3, gets)
	assert.Contains(t, b.indexes, 2)

	assert.Nil(t, b.setIndex(context.Background(), 2))
	assert.Equal(t, 3, gets)
}

func TestVectorSearchIndexCanceled(t *testing.T) {
	redisC := redisutils.NewClient()
	t.Cleanup(func() {
		redisC.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	indexing := 1
	redisC.AddHook(&fakeVectorSearchIndexHook{
		process: func(ctx context.Context, cmd redis.Cmder) error {
			switch cmd := cmd.(type) {
			case *redis.StatusCmd:
				assert.Equal(t, "ft.create", cmd.Name())
				cmd.SetVal("OK")
			case *redis.FTInfoCmd:
				cmd.SetVal(redis.FTInfoResult{Indexing: indexing})
				if indexing != 0 {
					cancel()
				}
			}
			return nil
		},
	})

	b := newVectorBackendSearch(redisC)
	assert.ErrorIs(t, b.setIndex(ctx, 2), context.Canceled)
	assert.NotContains(t, b.indexes, 2)

	indexing = 0
	assert.Nil(t, b.setIndex(context.Background(), 2))
	assert.Contains(t, b.indexes, 2)
}

func TestVectorSearchIndexFailure(t *testing.T) {
	redisC := redisutils.NewClient()
	t.Cleanup(func() {
		redisC.Close()
	})

	errInfo := fmt.Errorf("Could not get index info")
	redisC.AddHook(&fakeVectorSearchIndexHook{
		process: func(ctx context.Context, cmd redis.Cmder) error {
			switch cmd := cmd.(type) {
			case *redis.StatusCmd:
				assert.Equal(t, "ft.create", cmd.Name())
				cmd.SetVal("OK")
			case *redis.FTInfoCmd:
				return errInfo
			}
			return nil
		},
	})

	b := newVectorBackendSearch(redisC)
	assert.ErrorIs(t, b.setIndex(context.Background(), 2), errInfo)
	assert.NotContains(t, b.indexes, 2)
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
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		assert.Empty(t, resp.Results)
	}

	{
		resp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1")},
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
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
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
	}

	{
		resp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-2"), []byte("id-9")},
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		if !assert.Equal(t, 1, len(resp.Results)) {
			return
		}
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
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		if !assert.Equal(t, 3, len(resp.Results)) {
			return
		}

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
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		if !assert.Equal(t, 2, len(resp.Results)) {
			return
		}
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
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		if !assert.Equal(t, 1, len(resp.Results)) {
			return
		}
		assert.Equal(t, []byte("id-1"), resp.Results[0].Id)
	}

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0, 0},
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		assert.Empty(t, resp.Results)
	}

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  []byte(utilrand.GetRandomString(8)),
			Vector:     []float32{1, 0},
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
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
		if !assert.Nil(t, err, "%+v", err) {
			return
		}

		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection:    collection,
			Partition:     partition,
			Vector:        []float32{0, 1},
			MinSimilarity: 0.99,
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		if !assert.Equal(t, 2, len(resp.Results)) {
			return
		}

		getResp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1")},
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		if !assert.Equal(t, 1, len(getResp.Results)) {
			return
		}
		assert.Equal(t, []byte("data-1-updated"), getResp.Results[0].Data)
	}

	{
		_, err := srv.DeleteVectors(ctx, &rvectorv1.DeleteVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1"), []byte("id-9")},
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}

		resp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1")},
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		assert.Empty(t, resp.Results)

		searchResp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0},
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		assert.Equal(t, 2, len(searchResp.Results))
	}

	{
		_, err := srv.DeleteCollection(ctx, &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}

		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{1, 0},
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
		assert.Empty(t, resp.Results)

		getResp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-2")},
		})
		if !assert.Nil(t, err, "%+v", err) {
			return
		}
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

func TestVectorReplaceAcrossDimensions(t *testing.T) {
	runTestVectorBackends(t, doTestVectorReplaceAcrossDimensions)
}

func doTestVectorReplaceAcrossDimensions(t *testing.T, srv *srvVector) {

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
					Data:   []byte("data-old"),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
	}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: []float32{0, 0, 1},
					Data:   []byte("data-new"),
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
		assert.Empty(t, resp.Results)
	}

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     []float32{0, 0, 1},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(resp.Results))
		assert.Equal(t, []byte("data-new"), resp.Results[0].Data)
	}

	for i := 0; i < maxVectorPartitionEntries+maxVectorEntries; i += maxVectorEntries {
		req := &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Duration: &metav1.Duration{
				Type: &metav1.Duration_Minutes{
					Minutes: 10,
				},
			},
		}
		for j := range maxVectorEntries {
			req.Entries = append(req.Entries, &rvectorv1.Entry{
				Id:     []byte(fmt.Sprintf("flood-%06d", i+j)),
				Vector: []float32{float32(i + j + 2), 1},
				Data:   []byte("flood"),
			})
		}

		_, err := srv.UpsertVectors(ctx, req)
		assert.Nil(t, err, "%+v", err)
	}

	{
		resp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Ids:        [][]byte{[]byte("id-1")},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(resp.Results))
		assert.Equal(t, []byte("data-new"), resp.Results[0].Data)
	}
}

func TestVectorMaxPartitionEntriesAcrossDimensions(t *testing.T) {
	runTestVectorBackends(t, doTestVectorMaxPartitionEntriesAcrossDimensions)
}

func doTestVectorMaxPartitionEntriesAcrossDimensions(t *testing.T, srv *srvVector) {

	ctx := context.Background()

	collection := []byte(utilrand.GetRandomString(8))
	partition := []byte(utilrand.GetRandomString(8))

	t.Cleanup(func() {
		srv.DeleteCollection(context.Background(), &rvectorv1.DeleteCollectionRequest{
			Collection: collection,
		})
	})

	total := maxVectorPartitionEntries

	for _, dimension := range []int{2, 3} {
		for i := 0; i < total; i += maxVectorEntries {
			req := &rvectorv1.UpsertVectorsRequest{
				Collection: collection,
				Partition:  partition,
			}
			for j := range maxVectorEntries {
				vector := make([]float32, dimension)
				vector[0] = float32(i + j + 1)
				vector[dimension-1] = 1

				req.Entries = append(req.Entries, &rvectorv1.Entry{
					Id:     []byte(fmt.Sprintf("d%d-id-%06d", dimension, i+j)),
					Vector: vector,
					Data:   []byte("data"),
				})
			}

			_, err := srv.UpsertVectors(ctx, req)
			assert.Nil(t, err, "%+v", err)
		}
	}

	var found int
	for _, dimension := range []int{2, 3} {
		var ids [][]byte
		for i := range total {
			ids = append(ids, []byte(fmt.Sprintf("d%d-id-%06d", dimension, i)))
			if len(ids) < maxVectorIDs {
				continue
			}

			resp, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{
				Collection: collection,
				Partition:  partition,
				Ids:        ids,
			})
			assert.Nil(t, err, "%+v", err)
			found += len(resp.Results)
			ids = nil
		}
	}

	assert.Equal(t, maxVectorPartitionEntries, found)
}

func TestVectorSearchIndexLoss(t *testing.T) {

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

	vector := []float32{1, 0, 0, 0, 1, 0, 1}

	{
		_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Entries: []*rvectorv1.Entry{
				{
					Id:     []byte("id-1"),
					Vector: vector,
					Data:   []byte("data-1"),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
	}

	assert.Nil(t, srv.redisC.FTDropIndex(ctx, getVectorSearchIndex(len(vector))).Err())

	{
		resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
			Collection: collection,
			Partition:  partition,
			Vector:     vector,
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
					Id:     []byte("id-2"),
					Vector: vector,
					Data:   []byte("data-2"),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
	}

	resp, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
		Collection: collection,
		Partition:  partition,
		Vector:     vector,
	})
	if !assert.Nil(t, err, "%+v", err) {
		return
	}

	var ids [][]byte
	for _, itm := range resp.Results {
		ids = append(ids, itm.Id)
	}
	assert.ElementsMatch(t, [][]byte{[]byte("id-1"), []byte("id-2")}, ids)
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

func TestVectorRequestBoundaries(t *testing.T) {
	srv := &srvVector{}
	ctx := t.Context()
	collection := []byte("collection")
	for _, req := range []*rvectorv1.UpsertVectorsRequest{
		{Collection: collection, Entries: make([]*rvectorv1.Entry, maxVectorEntries+1)},
		{
			Collection: collection,
			Entries:    []*rvectorv1.Entry{{Id: []byte("id"), Vector: make([]float32, maxVectorDimension+1)}},
		},
		{
			Collection: collection,
			Entries:    []*rvectorv1.Entry{{Id: make([]byte, maxVectorIDBytes+1), Vector: []float32{1}}},
		},
		{
			Collection: collection,
			Entries:    []*rvectorv1.Entry{{Id: []byte("id"), Vector: []float32{1}, Data: make([]byte, maxVectorDataBytes+1)}},
		},
		{
			Collection: collection,
			Entries:    []*rvectorv1.Entry{{Id: []byte("id"), Vector: []float32{float32(math.Inf(1))}}},
		},
	} {
		res, err := srv.UpsertVectors(ctx, req)
		assert.Nil(t, res)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	for _, ids := range [][][]byte{{nil}, {make([]byte, maxVectorIDBytes+1)}, make([][]byte, maxVectorIDs+1)} {
		_, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{Collection: collection, Ids: ids})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		_, err = srv.DeleteVectors(ctx, &rvectorv1.DeleteVectorsRequest{Collection: collection, Ids: ids})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	_, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = srv.DeleteVectors(ctx, &rvectorv1.DeleteVectorsRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = srv.DeleteCollection(ctx, &rvectorv1.DeleteCollectionRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	upsert, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{Collection: collection})
	assert.Nil(t, err)
	assert.NotNil(t, upsert)
	get, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{Collection: collection})
	require.Nil(t, err)
	assert.Empty(t, get.Results)
	deleted, err := srv.DeleteVectors(ctx, &rvectorv1.DeleteVectorsRequest{Collection: collection})
	assert.Nil(t, err)
	assert.NotNil(t, deleted)
}

func TestVectorBackendErrors(t *testing.T) {
	for _, search := range []bool{false, true} {
		t.Run(fmt.Sprintf("search-%t", search), func(t *testing.T) {
			redisC := redisutils.NewClient()
			require.Nil(t, redisC.Close())
			srv := &srvVector{redisC: redisC, backend: &vectorBackendFallback{redisC: redisC}}
			if search {
				srv.backend = newVectorBackendSearch(redisC)
			}
			ctx := t.Context()
			_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
				Collection: []byte("collection"),
				Entries:    []*rvectorv1.Entry{{Id: []byte("id"), Vector: []float32{1}}},
			})
			assert.Equal(t, codes.Internal, status.Code(err))
			_, err = srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{Collection: []byte("collection"), Ids: [][]byte{[]byte("id")}})
			assert.Equal(t, codes.Internal, status.Code(err))
			_, err = srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{Collection: []byte("collection"), Vector: []float32{1}})
			assert.Equal(t, codes.Internal, status.Code(err))
			_, err = srv.DeleteVectors(ctx, &rvectorv1.DeleteVectorsRequest{Collection: []byte("collection"), Ids: [][]byte{[]byte("id")}})
			assert.Equal(t, codes.Internal, status.Code(err))
			_, err = srv.DeleteCollection(ctx, &rvectorv1.DeleteCollectionRequest{Collection: []byte("collection")})
			assert.Equal(t, codes.Internal, status.Code(err))
		})
	}
}

func TestVectorBackendSelection(t *testing.T) {
	ctx := t.Context()
	redisC := redisutils.NewClient()
	t.Cleanup(func() { redisC.Close() })
	srv := newSrvVector(ctx, redisC)
	require.NotNil(t, srv.backend)
	supported, err := checkVectorSearch(ctx, redisC)
	require.Nil(t, err)
	if supported {
		assert.IsType(t, &vectorBackendSearch{}, srv.backend)
	} else {
		assert.IsType(t, &vectorBackendFallback{}, srv.backend)
	}

	opts := redisutils.NewOptions()
	opts.DB = 1
	other := redis.NewClient(opts)
	t.Cleanup(func() { other.Close() })
	supported, err = checkVectorSearch(ctx, other)
	assert.Nil(t, err)
	assert.False(t, supported)
	assert.IsType(t, &vectorBackendFallback{}, newVectorBackend(ctx, other))
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	assert.IsType(t, &vectorBackendFallback{}, newVectorBackend(canceled, other))
	assert.IsType(t, &vectorBackendFallback{}, newVectorBackend(canceled, redisC))
}

func TestVectorConcurrentPartitions(t *testing.T) {
	runTestVectorBackends(t, func(t *testing.T, srv *srvVector) {
		ctx := t.Context()
		collection := utilrand.GetRandomBytesMust(32)
		t.Cleanup(func() { srv.redisC.Close() })
		t.Cleanup(func() {
			_, err := srv.DeleteCollection(context.Background(), &rvectorv1.DeleteCollectionRequest{Collection: collection})
			assert.Nil(t, err)
		})
		var wg sync.WaitGroup
		for worker := range 16 {
			wg.Go(func() {
				partition := []byte(fmt.Sprintf("partition-%d", worker))
				for i := range 8 {
					id := []byte(fmt.Sprintf("id-%d", i))
					data := []byte(fmt.Sprintf("data-%d-%d", worker, i))
					_, err := srv.UpsertVectors(ctx, &rvectorv1.UpsertVectorsRequest{
						Collection: collection,
						Partition:  partition,
						Entries:    []*rvectorv1.Entry{{Id: id, Data: data, Vector: []float32{1, 0}}},
					})
					if !assert.Nil(t, err) {
						return
					}
					got, err := srv.GetVectors(ctx, &rvectorv1.GetVectorsRequest{Collection: collection, Partition: partition, Ids: [][]byte{id}})
					if !assert.Nil(t, err) || !assert.Len(t, got.Results, 1) {
						return
					}
					assert.Equal(t, data, got.Results[0].Data)
				}
				got, err := srv.SearchVectors(ctx, &rvectorv1.SearchVectorsRequest{
					Collection: collection,
					Partition:  partition,
					Vector:     []float32{1, 0},
					Limit:      maxVectorSearchLimit + 1,
				})
				if !assert.Nil(t, err) {
					return
				}
				assert.Len(t, got.Results, 8)
				for _, result := range got.Results {
					assert.InDelta(t, 1, result.Similarity, 0.0001)
					assert.True(t, strings.HasPrefix(string(result.Data), fmt.Sprintf("data-%d-", worker)))
				}
			})
		}
		wg.Wait()
	})
}

type testVectorSearchHook struct {
	fakeVectorSearchIndexHook
	search  func(*redis.FTSearchCmd) error
	indexes []string
}

func (h *testVectorSearchHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		switch cmd.Name() {
		case "ft.search":
			return h.search(cmd.(*redis.FTSearchCmd))
		case "ft._list":
			cmd.(*redis.StringSliceCmd).SetVal(h.indexes)
			return nil
		default:
			return next(ctx, cmd)
		}
	}
}

func TestVectorSearchResponses(t *testing.T) {
	ctx := t.Context()
	redisC := redisutils.NewClient()
	t.Cleanup(func() { redisC.Close() })
	collection := utilrand.GetRandomBytesMust(32)
	partition := []byte("partition")
	backend := newVectorBackendSearch(redisC)
	var docs []redis.Document
	for i, score := range []string{"0.25", "-0.01", "1", "NaN", "invalid", "0.1"} {
		id := []byte(fmt.Sprintf("id-%d", i))
		entryKey := getVectorSearchEntryKey(2, collection, partition, id)
		dataKey := getVectorSearchDataKey(collection, partition, id)
		if i != 5 {
			require.Nil(t, redisC.Set(ctx, dataKey, id, 0).Err())
			t.Cleanup(func() { redisC.Del(context.Background(), dataKey) })
		}
		docs = append(docs, redis.Document{
			ID:     entryKey,
			Fields: map[string]string{vectorSearchFieldID: string(id), vectorSearchFieldScore: score},
		})
	}
	docs = append(docs, redis.Document{ID: "malformed-key", Fields: map[string]string{vectorSearchFieldScore: "0"}})
	hook := &testVectorSearchHook{search: func(cmd *redis.FTSearchCmd) error {
		cmd.SetVal(redis.FTSearchResult{Docs: docs, Total: len(docs)})
		return nil
	}}
	redisC.AddHook(hook)
	got, err := backend.search(ctx, &vectorSearchOpts{
		collection:    collection,
		partition:     partition,
		vector:        []float32{1, 0},
		minSimilarity: 0.1,
		limit:         8,
	})
	require.Nil(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, []byte("id-0"), got[0].Id)
	assert.Equal(t, []byte("id-0"), got[0].Data)
	assert.InDelta(t, 0.75, got[0].Similarity, 0.0001)
	assert.InDelta(t, 1, got[1].Similarity, 0.0001)

	backend.indexes[2] = struct{}{}
	hook.search = func(*redis.FTSearchCmd) error { return fmt.Errorf("Unknown Index name") }
	got, err = backend.search(ctx, &vectorSearchOpts{collection: collection, vector: []float32{1, 0}, limit: 8})
	assert.Nil(t, err)
	assert.Empty(t, got)
	assert.Empty(t, backend.indexes)
	assert.True(t, isRedisIndexNotFoundErr(fmt.Errorf("No such index")))
	assert.True(t, isRedisIndexNotFoundErr(fmt.Errorf("Index not found")))
	assert.False(t, isRedisIndexNotFoundErr(nil))
	assert.False(t, isRedisIndexExistsErr(nil))
	assert.True(t, isRedisIndexExistsErr(fmt.Errorf("Index already exists")))
}

func TestVectorSearchStorage(t *testing.T) {
	ctx := t.Context()
	redisC := redisutils.NewClient()
	t.Cleanup(func() { redisC.Close() })
	collection := utilrand.GetRandomBytesMust(32)
	partition := []byte{0, 255}
	id := []byte{255, 0, 1}
	hook := &testVectorSearchHook{
		indexes: []string{getVectorSearchIndex(2), getVectorSearchIndex(3), "other:2", vectorSearchProbeIndex},
		search:  func(cmd *redis.FTSearchCmd) error { cmd.SetVal(redis.FTSearchResult{Total: 1}); return nil },
	}
	redisC.AddHook(hook)
	backend := newVectorBackendSearch(redisC)
	backend.indexes[2] = struct{}{}
	staleKey := getVectorSearchEntryKey(3, collection, partition, id)
	require.Nil(t, redisC.HSet(ctx, staleKey, vectorSearchFieldID, id).Err())
	t.Cleanup(func() { backend.deleteCollection(context.Background(), collection) })
	now := time.Now()
	entry := &rvectorv1.Entry{Id: id, Vector: []float32{3, 4}, Data: []byte{0, 255, 128}}
	require.Nil(t, backend.upsert(ctx, &vectorUpsertOpts{
		collection: collection,
		partition:  partition,
		entries:    []*rvectorv1.Entry{entry},
		dimension:  2,
		now:        now,
		score:      now.Add(time.Minute).UnixMilli(),
	}))
	exists, err := redisC.Exists(ctx, staleKey).Result()
	require.Nil(t, err)
	assert.Zero(t, exists)
	entryKey := getVectorSearchEntryKey(2, collection, partition, id)
	stored, err := redisC.HGetAll(ctx, entryKey).Result()
	require.Nil(t, err)
	assert.Equal(t, string(id), stored[vectorSearchFieldID])
	assert.Equal(t, encodeVector(normalizeVector(entry.Vector)), []byte(stored[vectorSearchFieldVector]))
	for _, key := range []string{entryKey, getVectorSearchDataKey(collection, partition, id)} {
		ttl, err := redisC.PTTL(ctx, key).Result()
		require.Nil(t, err)
		assert.Greater(t, ttl, 50*time.Second)
		assert.LessOrEqual(t, ttl, time.Minute)
	}
	got, err := backend.get(ctx, &vectorGetOpts{collection: collection, partition: partition, ids: [][]byte{id, []byte("missing")}})
	require.Nil(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, entry.Data, got[0].Data)
	require.Nil(t, backend.delete(ctx, &vectorDeleteOpts{collection: collection, partition: partition, ids: [][]byte{id}}))
	got, err = backend.get(ctx, &vectorGetOpts{collection: collection, partition: partition, ids: [][]byte{id}})
	assert.Nil(t, err)
	assert.Empty(t, got)
}

func TestVectorSearchEvictionAcrossDimensions(t *testing.T) {
	ctx := t.Context()
	redisC := redisutils.NewClient()
	t.Cleanup(func() { redisC.Close() })
	collection := utilrand.GetRandomBytesMust(32)
	partition := []byte("partition")
	backend := newVectorBackendSearch(redisC)
	t.Cleanup(func() { backend.deleteCollection(context.Background(), collection) })
	docs := map[string][]redis.Document{}
	var keys []string
	for i, dimension := range []int{2, 3, 2, 3} {
		id := []byte(fmt.Sprintf("id-%d", i))
		key := getVectorSearchEntryKey(dimension, collection, partition, id)
		dataKey := getVectorSearchDataKey(collection, partition, id)
		require.Nil(t, redisC.HSet(ctx, key, vectorSearchFieldID, id).Err())
		require.Nil(t, redisC.Set(ctx, dataKey, "data", 0).Err())
		keys = append(keys, key, dataKey)
		index := getVectorSearchIndex(dimension)
		docs[index] = append(docs[index], redis.Document{ID: key, Fields: map[string]string{vectorSearchFieldExpiresAt: fmt.Sprintf("%d", i+1)}})
	}
	redisC.AddHook(&testVectorSearchHook{search: func(cmd *redis.FTSearchCmd) error {
		cmd.SetVal(redis.FTSearchResult{Total: maxVectorPartitionEntries/2 + 1, Docs: docs[cmd.Args()[1].(string)]})
		return nil
	}})
	require.Nil(t, backend.evict(ctx, &vectorUpsertOpts{collection: collection, partition: partition}, []int{2, 3}))
	for i, key := range keys {
		exists, err := redisC.Exists(ctx, key).Result()
		require.Nil(t, err)
		if i < 4 {
			assert.Zero(t, exists)
		} else {
			assert.Equal(t, int64(1), exists)
		}
	}
}
