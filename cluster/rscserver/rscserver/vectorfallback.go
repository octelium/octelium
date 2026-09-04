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
	"sort"

	"github.com/octelium/octelium/apis/rsc/rvectorv1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/redis/go-redis/v9"
)

type vectorBackendFallback struct {
	redisC *redis.Client
}

const vectorPruneLua = `
local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1])
for i = 1, #expired do
	redis.call('ZREM', KEYS[1], expired[i])
	redis.call('HDEL', KEYS[2], expired[i])
	redis.call('HDEL', KEYS[3], expired[i])
end
`

const vectorExpiryLua = `
local top = redis.call('ZREVRANGE', KEYS[1], 0, 0, 'WITHSCORES')
if #top == 0 then
	redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
else
	local ttl = 0
	if tonumber(top[2]) < noExpiry then
		ttl = math.ceil(tonumber(top[2]) - now) + grace
	end
	for j = 1, 3 do
		if ttl > 0 then
			redis.call('PEXPIRE', KEYS[j], ttl)
		else
			redis.call('PERSIST', KEYS[j])
		end
	end
end
`

var vectorUpsertScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local grace = tonumber(ARGV[3])
local noExpiry = tonumber(ARGV[5])
` + vectorPruneLua + `
local i = 6
while i + 2 <= #ARGV do
	redis.call('ZADD', KEYS[1], ARGV[2], ARGV[i])
	redis.call('HSET', KEYS[2], ARGV[i], ARGV[i + 1])
	redis.call('HSET', KEYS[3], ARGV[i], ARGV[i + 2])
	i = i + 3
end
local excess = redis.call('ZCARD', KEYS[1]) - tonumber(ARGV[4])
if excess > 0 then
	local evicted = redis.call('ZRANGE', KEYS[1], 0, excess - 1)
	for j = 1, #evicted do
		redis.call('ZREM', KEYS[1], evicted[j])
		redis.call('HDEL', KEYS[2], evicted[j])
		redis.call('HDEL', KEYS[3], evicted[j])
	end
end
` + vectorExpiryLua + `
return 1
`)

var vectorGetScript = redis.NewScript(vectorPruneLua + `
local ret = {}
for i = 2, #ARGV do
	local data = redis.call('HGET', KEYS[3], ARGV[i])
	if data then
		ret[#ret + 1] = ARGV[i]
		ret[#ret + 1] = data
	end
end
return ret
`)

var vectorSearchScript = redis.NewScript(vectorPruneLua + `
return redis.call('HGETALL', KEYS[2])
`)

var vectorDeleteScript = redis.NewScript(`
local now = tonumber(ARGV[1])
local grace = tonumber(ARGV[2])
local noExpiry = tonumber(ARGV[3])
` + vectorPruneLua + `
for i = 4, #ARGV do
	redis.call('ZREM', KEYS[1], ARGV[i])
	redis.call('HDEL', KEYS[2], ARGV[i])
	redis.call('HDEL', KEYS[3], ARGV[i])
end
` + vectorExpiryLua + `
return 1
`)

func getVectorKeys(collection, partition []byte) []string {
	prefix := fmt.Sprintf("octelium:vec:%s:%s",
		vutils.Sha256SumHex(collection), vutils.Sha256SumHex(partition))
	return []string{prefix, fmt.Sprintf("%s:v", prefix), fmt.Sprintf("%s:d", prefix)}
}

func getVectorCollectionMatch(collection []byte) string {
	return fmt.Sprintf("octelium:vec:%s:*", vutils.Sha256SumHex(collection))
}

func (b *vectorBackendFallback) upsert(ctx context.Context, opts *vectorUpsertOpts) error {

	args := []any{opts.now.UnixMilli(), opts.score, vectorKeyGrace.Milliseconds(),
		maxVectorPartitionEntries, int64(vectorNoExpiryScore)}

	for _, entry := range opts.entries {
		args = append(args, entry.Id, encodeVector(normalizeVector(entry.Vector)), entry.Data)
	}

	return vectorUpsertScript.Run(ctx, b.redisC,
		getVectorKeys(opts.collection, opts.partition), args...).Err()
}

func (b *vectorBackendFallback) get(ctx context.Context,
	opts *vectorGetOpts) ([]*rvectorv1.Result, error) {

	args := []any{opts.now.UnixMilli()}
	for _, id := range opts.ids {
		args = append(args, id)
	}

	res, err := vectorGetScript.Run(ctx, b.redisC,
		getVectorKeys(opts.collection, opts.partition), args...).StringSlice()
	if err != nil {
		return nil, err
	}

	var ret []*rvectorv1.Result
	for i := 0; i+1 < len(res); i += 2 {
		ret = append(ret, &rvectorv1.Result{
			Id:   []byte(res[i]),
			Data: []byte(res[i+1]),
		})
	}

	return ret, nil
}

func (b *vectorBackendFallback) search(ctx context.Context,
	opts *vectorSearchOpts) ([]*rvectorv1.Result, error) {

	keys := getVectorKeys(opts.collection, opts.partition)

	res, err := vectorSearchScript.Run(ctx, b.redisC, keys, opts.now.UnixMilli()).StringSlice()
	if err != nil {
		return nil, err
	}

	query := normalizeVector(opts.vector)

	var matches []*rvectorv1.Result
	for i := 0; i+1 < len(res); i += 2 {
		vec := decodeVector(res[i+1])
		if len(vec) != len(query) {
			continue
		}

		similarity := getVectorSimilarity(query, vec)
		if similarity < opts.minSimilarity {
			continue
		}

		matches = append(matches, &rvectorv1.Result{
			Id:         []byte(res[i]),
			Similarity: similarity,
		})
	}

	if len(matches) == 0 {
		return nil, nil
	}

	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].Similarity > matches[j].Similarity
	})

	if len(matches) > opts.limit {
		matches = matches[:opts.limit]
	}

	fields := make([]string, 0, len(matches))
	for _, match := range matches {
		fields = append(fields, string(match.Id))
	}

	vals, err := b.redisC.HMGet(ctx, keys[2], fields...).Result()
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

func (b *vectorBackendFallback) delete(ctx context.Context, opts *vectorDeleteOpts) error {

	args := []any{opts.now.UnixMilli(), vectorKeyGrace.Milliseconds(), int64(vectorNoExpiryScore)}
	for _, id := range opts.ids {
		args = append(args, id)
	}

	return vectorDeleteScript.Run(ctx, b.redisC,
		getVectorKeys(opts.collection, opts.partition), args...).Err()
}

func (b *vectorBackendFallback) deleteCollection(ctx context.Context, collection []byte) error {

	match := getVectorCollectionMatch(collection)
	var cursor uint64

	for {
		keys, next, err := b.redisC.Scan(ctx, cursor, match, 256).Result()
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
			return nil
		}
	}
}
