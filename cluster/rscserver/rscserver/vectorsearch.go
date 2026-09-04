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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/rsc/rvectorv1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	vectorSearchIndexPrefix = "octelium:vec:idx"
	vectorSearchEntryPrefix = "octelium:vec:e"
	vectorSearchDataPrefix  = "octelium:vec:d"

	vectorSearchProbeIndex     = "octelium:vec:idx:probe"
	vectorSearchProbeDimension = 2

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

func getVectorSearchCollectionMatches(collection []byte) []string {
	collectionHex := vutils.Sha256SumHex(collection)
	return []string{
		fmt.Sprintf("%s:*:%s:*", vectorSearchEntryPrefix, collectionHex),
		fmt.Sprintf("%s:%s:*", vectorSearchDataPrefix, collectionHex),
	}
}

func getVectorSearchCollectionFilter(collection []byte) string {
	return fmt.Sprintf("@%s:{%s}", vectorSearchFieldCollection, vutils.Sha256SumHex(collection))
}

func getVectorSearchPartitionFilter(collection, partition []byte) string {
	return fmt.Sprintf("%s @%s:{%s}", getVectorSearchCollectionFilter(collection),
		vectorSearchFieldPartition, vutils.Sha256SumHex(partition))
}

func getVectorSearchExpiresAt(doc redis.Document) int64 {
	ret, err := strconv.ParseInt(doc.Fields[vectorSearchFieldExpiresAt], 10, 64)
	if err != nil {
		return 0
	}
	return ret
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

func createVectorSearchIndex(ctx context.Context, redisC *redis.Client,
	index, prefix string, dimension int) error {

	err := redisC.FTCreate(ctx, index,
		&redis.FTCreateOptions{
			OnHash: true,
			Prefix: []any{prefix},
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

	return nil
}

func checkVectorSearch(ctx context.Context, redisC *redis.Client) (bool, error) {

	if db := redisC.Options().DB; db != 0 {
		zap.L().Warn("Redis Search indexes can only be created on the Redis database 0",
			zap.Int("db", db))
		return false, nil
	}

	if err := redisC.FT_List(ctx).Err(); err != nil {
		if isRedisUnknownCommandErr(err) {
			return false, nil
		}
		return false, err
	}

	if err := createVectorSearchIndex(ctx, redisC, vectorSearchProbeIndex,
		fmt.Sprintf("%s:", vectorSearchProbeIndex), vectorSearchProbeDimension); err != nil {
		return false, err
	}

	if err := redisC.FTDropIndex(ctx, vectorSearchProbeIndex).Err(); err != nil {
		zap.L().Debug("Could not drop the Redis Search probe index", zap.Error(err))
	}

	return true, nil
}

func (b *vectorBackendSearch) setIndex(ctx context.Context, dimension int) error {
	b.mu.Lock()
	_, ok := b.indexes[dimension]
	b.mu.Unlock()

	if ok {
		return nil
	}

	if err := createVectorSearchIndex(ctx, b.redisC, getVectorSearchIndex(dimension),
		getVectorSearchEntryPrefix(dimension), dimension); err != nil {
		return err
	}

	b.mu.Lock()
	b.indexes[dimension] = struct{}{}
	b.mu.Unlock()

	return nil
}

func (b *vectorBackendSearch) forgetIndex(dimension int) {
	b.mu.Lock()
	delete(b.indexes, dimension)
	b.mu.Unlock()
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

	dimensions, err := b.getIndexDimensions(ctx)
	if err != nil {
		return err
	}

	if !slices.Contains(dimensions, opts.dimension) {
		b.forgetIndex(opts.dimension)
		dimensions = append(dimensions, opts.dimension)
	}

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

	pipe := b.redisC.TxPipeline()

	var stale []string

	for _, entry := range opts.entries {
		entryKey := getVectorSearchEntryKey(opts.dimension,
			opts.collection, opts.partition, entry.Id)

		for _, dimension := range dimensions {
			if dimension == opts.dimension {
				continue
			}
			stale = append(stale,
				getVectorSearchEntryKey(dimension, opts.collection, opts.partition, entry.Id))
		}

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

	if len(stale) > 0 {
		pipe.Del(ctx, stale...)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}

	return b.evict(ctx, opts, dimensions)
}

func (b *vectorBackendSearch) evict(ctx context.Context,
	opts *vectorUpsertOpts, dimensions []int) error {

	filter := getVectorSearchPartitionFilter(opts.collection, opts.partition)

	var total int

	for _, dimension := range dimensions {
		res, err := b.redisC.FTSearchWithArgs(ctx, getVectorSearchIndex(dimension), filter,
			&redis.FTSearchOptions{
				CountOnly:      true,
				DialectVersion: vectorSearchDialect,
			}).Result()
		if err != nil {
			if isRedisIndexNotFoundErr(err) {
				b.forgetIndex(dimension)
				continue
			}
			return err
		}

		total += res.Total
	}

	excess := total - maxVectorPartitionEntries
	if excess <= 0 {
		return nil
	}

	var docs []redis.Document

	for _, dimension := range dimensions {
		res, err := b.redisC.FTSearchWithArgs(ctx, getVectorSearchIndex(dimension), filter,
			&redis.FTSearchOptions{
				Return: []redis.FTSearchReturn{
					{
						FieldName: vectorSearchFieldExpiresAt,
					},
				},
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
			if isRedisIndexNotFoundErr(err) {
				b.forgetIndex(dimension)
				continue
			}
			return err
		}

		docs = append(docs, res.Docs...)
	}

	if len(docs) > excess {
		sort.SliceStable(docs, func(i, j int) bool {
			return getVectorSearchExpiresAt(docs[i]) < getVectorSearchExpiresAt(docs[j])
		})
		docs = docs[:excess]
	}

	return b.deleteDocs(ctx, docs)
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

	dimension := len(opts.vector)

	query := fmt.Sprintf("(%s)=>[KNN %d @%s $%s AS %s]",
		getVectorSearchPartitionFilter(opts.collection, opts.partition),
		opts.limit, vectorSearchFieldVector, vectorSearchParamVector, vectorSearchFieldScore)

	res, err := b.redisC.FTSearchWithArgs(ctx, getVectorSearchIndex(dimension), query,
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
		if !isRedisIndexNotFoundErr(err) {
			return nil, err
		}

		b.mu.Lock()
		_, hadIndex := b.indexes[dimension]
		delete(b.indexes, dimension)
		b.mu.Unlock()

		if hadIndex {
			zap.L().Warn("The Redis Search vector index no longer exists. It is re-created on the next upsert",
				zap.Int("dimension", dimension))
		}

		return nil, nil
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

	for _, match := range getVectorSearchCollectionMatches(collection) {
		var cursor uint64

		for {
			keys, next, err := b.redisC.Scan(ctx, cursor, match, vectorSearchPageSize).Result()
			if err != nil {
				return err
			}

			if len(keys) > 0 {
				if err := b.redisC.Del(ctx, keys...).Err(); err != nil {
					return err
				}
			}

			cursor = next
			if cursor == 0 {
				break
			}
		}
	}

	return nil
}
