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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/rsc/rvectorv1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/redis/go-redis/v9"
)

const (
	vectorSearchIndexPrefix = "octelium:vec:idx"
	vectorSearchEntryPrefix = "octelium:vec:e"
	vectorSearchDataPrefix  = "octelium:vec:d"

	vectorSearchFieldCollection = "c"
	vectorSearchFieldPartition  = "p"
	vectorSearchFieldExpiresAt  = "t"
	vectorSearchFieldVector     = "v"
	vectorSearchFieldID         = "i"
	vectorSearchFieldScore      = "__score"

	vectorSearchParamVector = "q"

	vectorSearchDialect       = 2
	vectorSearchPageSize      = 256
	vectorSearchEntryKeyParts = 7
)

type vectorBackendSearch struct {
	redisC *redis.Client

	mu      sync.Mutex
	indexes map[int]struct{}
}

func newVectorBackendSearch(redisC *redis.Client) *vectorBackendSearch {
	return &vectorBackendSearch{
		redisC:  redisC,
		indexes: make(map[int]struct{}),
	}
}

func getVectorSearchIndex(dimension int) string {
	return fmt.Sprintf("%s:%d", vectorSearchIndexPrefix, dimension)
}

func getVectorSearchEntryPrefix(dimension int) string {
	return fmt.Sprintf("%s:%d:", vectorSearchEntryPrefix, dimension)
}

func getVectorSearchEntryKey(dimension int, collection, partition, id []byte) string {
	return fmt.Sprintf("%s%s:%s:%s", getVectorSearchEntryPrefix(dimension),
		vutils.Sha256SumHex(collection), vutils.Sha256SumHex(partition), vutils.Sha256SumHex(id))
}

func getVectorSearchDataKey(collection, partition, id []byte) string {
	return fmt.Sprintf("%s:%s:%s:%s", vectorSearchDataPrefix,
		vutils.Sha256SumHex(collection), vutils.Sha256SumHex(partition), vutils.Sha256SumHex(id))
}

func getVectorSearchEntryDataKey(entryKey string) (string, bool) {
	args := strings.Split(entryKey, ":")
	if len(args) != vectorSearchEntryKeyParts {
		return "", false
	}
	return fmt.Sprintf("%s:%s:%s:%s", vectorSearchDataPrefix, args[4], args[5], args[6]), true
}

func getVectorSearchCollectionFilter(collection []byte) string {
	return fmt.Sprintf("@%s:{%s}", vectorSearchFieldCollection, vutils.Sha256SumHex(collection))
}

func getVectorSearchPartitionFilter(collection, partition []byte) string {
	return fmt.Sprintf("%s @%s:{%s}", getVectorSearchCollectionFilter(collection),
		vectorSearchFieldPartition, vutils.Sha256SumHex(partition))
}

func isRedisIndexNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	arg := strings.ToLower(err.Error())
	return strings.Contains(arg, "index not found") ||
		strings.Contains(arg, "no such index") ||
		strings.Contains(arg, "unknown index")
}

func isRedisIndexExistsErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "already exists")
}

func (b *vectorBackendSearch) setIndex(ctx context.Context, dimension int) error {
	b.mu.Lock()
	_, ok := b.indexes[dimension]
	b.mu.Unlock()

	if ok {
		return nil
	}

	err := b.redisC.FTCreate(ctx, getVectorSearchIndex(dimension),
		&redis.FTCreateOptions{
			OnHash: true,
			Prefix: []any{getVectorSearchEntryPrefix(dimension)},
		},
		&redis.FieldSchema{
			FieldName: vectorSearchFieldCollection,
			FieldType: redis.SearchFieldTypeTag,
		},
		&redis.FieldSchema{
			FieldName: vectorSearchFieldPartition,
			FieldType: redis.SearchFieldTypeTag,
		},
		&redis.FieldSchema{
			FieldName: vectorSearchFieldExpiresAt,
			FieldType: redis.SearchFieldTypeNumeric,
			Sortable:  true,
		},
		&redis.FieldSchema{
			FieldName: vectorSearchFieldVector,
			FieldType: redis.SearchFieldTypeVector,
			VectorArgs: &redis.FTVectorArgs{
				FlatOptions: &redis.FTFlatOptions{
					Type:           "FLOAT32",
					Dim:            dimension,
					DistanceMetric: "COSINE",
				},
			},
		}).Err()
	if err != nil && !isRedisIndexExistsErr(err) {
		return err
	}

	b.mu.Lock()
	b.indexes[dimension] = struct{}{}
	b.mu.Unlock()

	return nil
}

func (b *vectorBackendSearch) getIndexDimensions(ctx context.Context) ([]int, error) {
	names, err := b.redisC.FT_List(ctx).Result()
	if err != nil {
		return nil, err
	}

	var ret []int
	for _, name := range names {
		arg, ok := strings.CutPrefix(name, fmt.Sprintf("%s:", vectorSearchIndexPrefix))
		if !ok {
			continue
		}

		dimension, err := strconv.Atoi(arg)
		if err != nil {
			continue
		}

		ret = append(ret, dimension)
	}

	return ret, nil
}

func (b *vectorBackendSearch) upsert(ctx context.Context, opts *vectorUpsertOpts) error {

	if err := b.setIndex(ctx, opts.dimension); err != nil {
		return err
	}

	var ttl time.Duration
	if opts.score != vectorNoExpiryScore {
		ttl = time.UnixMilli(opts.score).Sub(opts.now)
		if ttl <= 0 {
			return nil
		}
	}

	pipe := b.redisC.Pipeline()

	for _, entry := range opts.entries {
		entryKey := getVectorSearchEntryKey(opts.dimension,
			opts.collection, opts.partition, entry.Id)

		pipe.HSet(ctx, entryKey, map[string]any{
			vectorSearchFieldCollection: vutils.Sha256SumHex(opts.collection),
			vectorSearchFieldPartition:  vutils.Sha256SumHex(opts.partition),
			vectorSearchFieldExpiresAt:  opts.score,
			vectorSearchFieldVector:     encodeVector(normalizeVector(entry.Vector)),
			vectorSearchFieldID:         entry.Id,
		})

		pipe.Set(ctx, getVectorSearchDataKey(opts.collection, opts.partition, entry.Id),
			entry.Data, ttl)

		if ttl > 0 {
			pipe.PExpire(ctx, entryKey, ttl)
		} else {
			pipe.Persist(ctx, entryKey)
		}
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}

	return b.evict(ctx, opts)
}

func (b *vectorBackendSearch) evict(ctx context.Context, opts *vectorUpsertOpts) error {

	index := getVectorSearchIndex(opts.dimension)
	filter := getVectorSearchPartitionFilter(opts.collection, opts.partition)

	total, err := b.redisC.FTSearchWithArgs(ctx, index, filter, &redis.FTSearchOptions{
		CountOnly:      true,
		DialectVersion: vectorSearchDialect,
	}).Result()
	if err != nil {
		return err
	}

	excess := total.Total - maxVectorPartitionEntries
	if excess <= 0 {
		return nil
	}

	res, err := b.redisC.FTSearchWithArgs(ctx, index, filter, &redis.FTSearchOptions{
		NoContent: true,
		SortBy: []redis.FTSearchSortBy{
			{
				FieldName: vectorSearchFieldExpiresAt,
				Asc:       true,
			},
		},
		Limit:          excess,
		DialectVersion: vectorSearchDialect,
	}).Result()
	if err != nil {
		return err
	}

	return b.deleteDocs(ctx, res.Docs)
}

func (b *vectorBackendSearch) deleteDocs(ctx context.Context, docs []redis.Document) error {
	if len(docs) == 0 {
		return nil
	}

	keys := make([]string, 0, len(docs)*2)
	for _, doc := range docs {
		keys = append(keys, doc.ID)
		if dataKey, ok := getVectorSearchEntryDataKey(doc.ID); ok {
			keys = append(keys, dataKey)
		}
	}

	return b.redisC.Del(ctx, keys...).Err()
}

func (b *vectorBackendSearch) get(ctx context.Context,
	opts *vectorGetOpts) ([]*rvectorv1.Result, error) {

	keys := make([]string, 0, len(opts.ids))
	for _, id := range opts.ids {
		keys = append(keys, getVectorSearchDataKey(opts.collection, opts.partition, id))
	}

	vals, err := b.redisC.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	var ret []*rvectorv1.Result
	for i, val := range vals {
		if i >= len(opts.ids) {
			break
		}

		data, ok := val.(string)
		if !ok {
			continue
		}

		ret = append(ret, &rvectorv1.Result{
			Id:   opts.ids[i],
			Data: []byte(data),
		})
	}

	return ret, nil
}

func (b *vectorBackendSearch) search(ctx context.Context,
	opts *vectorSearchOpts) ([]*rvectorv1.Result, error) {

	query := fmt.Sprintf("(%s)=>[KNN %d @%s $%s AS %s]",
		getVectorSearchPartitionFilter(opts.collection, opts.partition),
		opts.limit, vectorSearchFieldVector, vectorSearchParamVector, vectorSearchFieldScore)

	res, err := b.redisC.FTSearchWithArgs(ctx, getVectorSearchIndex(len(opts.vector)), query,
		&redis.FTSearchOptions{
			Return: []redis.FTSearchReturn{
				{
					FieldName: vectorSearchFieldScore,
				},
				{
					FieldName: vectorSearchFieldID,
				},
			},
			SortBy: []redis.FTSearchSortBy{
				{
					FieldName: vectorSearchFieldScore,
					Asc:       true,
				},
			},
			Limit:          opts.limit,
			DialectVersion: vectorSearchDialect,
			Params: map[string]any{
				vectorSearchParamVector: encodeVector(normalizeVector(opts.vector)),
			},
		}).Result()
	if err != nil {
		if isRedisIndexNotFoundErr(err) {
			return nil, nil
		}
		return nil, err
	}

	var matches []*rvectorv1.Result
	var keys []string

	for _, doc := range res.Docs {
		distance, err := strconv.ParseFloat(doc.Fields[vectorSearchFieldScore], 64)
		if err != nil {
			continue
		}

		similarity := clampVectorSimilarity(1 - distance)
		if similarity < opts.minSimilarity {
			continue
		}

		dataKey, ok := getVectorSearchEntryDataKey(doc.ID)
		if !ok {
			continue
		}

		matches = append(matches, &rvectorv1.Result{
			Id:         []byte(doc.Fields[vectorSearchFieldID]),
			Similarity: similarity,
		})
		keys = append(keys, dataKey)
	}

	if len(matches) == 0 {
		return nil, nil
	}

	vals, err := b.redisC.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	var ret []*rvectorv1.Result
	for i, match := range matches {
		if i >= len(vals) {
			break
		}

		data, ok := vals[i].(string)
		if !ok {
			continue
		}

		match.Data = []byte(data)
		ret = append(ret, match)
	}

	return ret, nil
}

func (b *vectorBackendSearch) delete(ctx context.Context, opts *vectorDeleteOpts) error {

	dimensions, err := b.getIndexDimensions(ctx)
	if err != nil {
		return err
	}

	keys := make([]string, 0, len(opts.ids)*(len(dimensions)+1))
	for _, id := range opts.ids {
		keys = append(keys, getVectorSearchDataKey(opts.collection, opts.partition, id))
		for _, dimension := range dimensions {
			keys = append(keys,
				getVectorSearchEntryKey(dimension, opts.collection, opts.partition, id))
		}
	}

	return b.redisC.Del(ctx, keys...).Err()
}

func (b *vectorBackendSearch) deleteCollection(ctx context.Context, collection []byte) error {

	dimensions, err := b.getIndexDimensions(ctx)
	if err != nil {
		return err
	}

	filter := getVectorSearchCollectionFilter(collection)

	for _, dimension := range dimensions {
		for {
			res, err := b.redisC.FTSearchWithArgs(ctx, getVectorSearchIndex(dimension), filter,
				&redis.FTSearchOptions{
					NoContent:      true,
					Limit:          vectorSearchPageSize,
					DialectVersion: vectorSearchDialect,
				}).Result()
			if err != nil {
				if isRedisIndexNotFoundErr(err) {
					break
				}
				return err
			}

			if len(res.Docs) == 0 {
				break
			}

			if err := b.deleteDocs(ctx, res.Docs); err != nil {
				return err
			}
		}
	}

	return nil
}
