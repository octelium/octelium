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
	"sort"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/apis/rsc/rvectorv1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver/rerr"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
)

type srvVector struct {
	redisC *redis.Client
	rvectorv1.UnimplementedMainServiceServer
}

const (
	maxVectorDimension        = 4096
	maxVectorEntries          = 256
	maxVectorIDs              = 256
	maxVectorIDBytes          = 256
	maxVectorDataBytes        = 2 << 20
	maxVectorPartitionEntries = 1024
	maxVectorSearchLimit      = 128
	defaultVectorSearchLimit  = 8
	vectorNoExpiryScore       = 9007199254740991
	vectorKeyGrace            = 10 * time.Second
)

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

func encodeVector(vec []float32) []byte {
	ret := make([]byte, len(vec)*4)
	for i, val := range vec {
		bits := math.Float32bits(val)
		ret[i*4] = byte(bits)
		ret[i*4+1] = byte(bits >> 8)
		ret[i*4+2] = byte(bits >> 16)
		ret[i*4+3] = byte(bits >> 24)
	}
	return ret
}

func decodeVector(arg string) []float32 {
	if len(arg) == 0 || len(arg)%4 != 0 {
		return nil
	}
	ret := make([]float32, len(arg)/4)
	for i := range ret {
		ret[i] = math.Float32frombits(uint32(arg[i*4]) |
			uint32(arg[i*4+1])<<8 | uint32(arg[i*4+2])<<16 | uint32(arg[i*4+3])<<24)
	}
	return ret
}

func normalizeVector(vec []float32) []float32 {
	var sum float64
	for _, val := range vec {
		sum += float64(val) * float64(val)
	}
	if sum <= 0 {
		return vec
	}

	norm := math.Sqrt(sum)
	ret := make([]float32, len(vec))
	for i, val := range vec {
		ret[i] = float32(float64(val) / norm)
	}
	return ret
}

func getVectorSimilarity(a, b []float32) float32 {
	var sum float32
	for i := range a {
		sum += a[i] * b[i]
	}
	switch {
	case sum <= 0:
		return 0
	case sum > 1:
		return 1
	default:
		return sum
	}
}

func checkVectorCollection(collection []byte) error {
	if len(collection) == 0 {
		return grpcutils.InvalidArg("Empty collection is not allowed")
	}
	return nil
}

func checkVectorID(id []byte) error {
	if len(id) == 0 {
		return grpcutils.InvalidArg("Empty id is not allowed")
	}
	if len(id) > maxVectorIDBytes {
		return grpcutils.InvalidArg("ID is too large: %d", len(id))
	}
	return nil
}

func checkVectorSimilarity(arg float32) error {
	if math.IsNaN(float64(arg)) || math.IsInf(float64(arg), 0) {
		return grpcutils.InvalidArg("The minimum similarity must be finite")
	}
	if arg < 0 || arg > 1 {
		return grpcutils.InvalidArg("The minimum similarity must be between 0 and 1: %v", arg)
	}
	return nil
}

func checkVector(vec []float32) error {
	if len(vec) == 0 {
		return grpcutils.InvalidArg("Empty vector is not allowed")
	}
	if len(vec) > maxVectorDimension {
		return grpcutils.InvalidArg("Vector dimension is too large: %d", len(vec))
	}
	for _, val := range vec {
		if math.IsNaN(float64(val)) || math.IsInf(float64(val), 0) {
			return grpcutils.InvalidArg("Vector values must be finite")
		}
	}
	return nil
}

func (s *srvVector) UpsertVectors(ctx context.Context,
	req *rvectorv1.UpsertVectorsRequest) (*rvectorv1.UpsertVectorsResponse, error) {

	if err := checkVectorCollection(req.Collection); err != nil {
		return nil, err
	}

	if len(req.Entries) == 0 {
		return &rvectorv1.UpsertVectorsResponse{}, nil
	}

	if len(req.Entries) > maxVectorEntries {
		return nil, grpcutils.InvalidArg("Too many entries: %d", len(req.Entries))
	}

	duration := umetav1.ToDuration(req.Duration).ToGo()
	if duration < 0 {
		return nil, grpcutils.InvalidArg("Duration cannot be negative")
	}

	now := time.Now()
	score := int64(vectorNoExpiryScore)
	if duration > 0 {
		score = now.Add(duration).UnixMilli()
	}

	args := []any{now.UnixMilli(), score, vectorKeyGrace.Milliseconds(),
		maxVectorPartitionEntries, int64(vectorNoExpiryScore)}

	for _, entry := range req.Entries {
		if err := checkVectorID(entry.Id); err != nil {
			return nil, err
		}
		if err := checkVector(entry.Vector); err != nil {
			return nil, err
		}
		if len(entry.Data) > maxVectorDataBytes {
			return nil, grpcutils.InvalidArg("Entry data is too large: %d", len(entry.Data))
		}

		args = append(args, entry.Id, encodeVector(normalizeVector(entry.Vector)), entry.Data)
	}

	if err := vectorUpsertScript.Run(ctx, s.redisC,
		getVectorKeys(req.Collection, req.Partition), args...).Err(); err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	return &rvectorv1.UpsertVectorsResponse{}, nil
}

func (s *srvVector) GetVectors(ctx context.Context,
	req *rvectorv1.GetVectorsRequest) (*rvectorv1.GetVectorsResponse, error) {

	if err := checkVectorCollection(req.Collection); err != nil {
		return nil, err
	}

	if len(req.Ids) == 0 {
		return &rvectorv1.GetVectorsResponse{}, nil
	}

	if len(req.Ids) > maxVectorIDs {
		return nil, grpcutils.InvalidArg("Too many ids: %d", len(req.Ids))
	}

	args := []any{time.Now().UnixMilli()}
	for _, id := range req.Ids {
		if err := checkVectorID(id); err != nil {
			return nil, err
		}
		args = append(args, id)
	}

	res, err := vectorGetScript.Run(ctx, s.redisC,
		getVectorKeys(req.Collection, req.Partition), args...).StringSlice()
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	ret := &rvectorv1.GetVectorsResponse{}
	for i := 0; i+1 < len(res); i += 2 {
		ret.Results = append(ret.Results, &rvectorv1.Result{
			Id:   []byte(res[i]),
			Data: []byte(res[i+1]),
		})
	}

	return ret, nil
}

func (s *srvVector) SearchVectors(ctx context.Context,
	req *rvectorv1.SearchVectorsRequest) (*rvectorv1.SearchVectorsResponse, error) {

	if err := checkVectorCollection(req.Collection); err != nil {
		return nil, err
	}

	if err := checkVector(req.Vector); err != nil {
		return nil, err
	}

	if err := checkVectorSimilarity(req.MinSimilarity); err != nil {
		return nil, err
	}

	limit := int(req.Limit)
	switch {
	case limit <= 0:
		limit = defaultVectorSearchLimit
	case limit > maxVectorSearchLimit:
		limit = maxVectorSearchLimit
	}

	keys := getVectorKeys(req.Collection, req.Partition)

	res, err := vectorSearchScript.Run(ctx, s.redisC, keys, time.Now().UnixMilli()).StringSlice()
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	query := normalizeVector(req.Vector)

	var matches []*rvectorv1.Result
	for i := 0; i+1 < len(res); i += 2 {
		vec := decodeVector(res[i+1])
		if len(vec) != len(query) {
			continue
		}

		similarity := getVectorSimilarity(query, vec)
		if similarity < req.MinSimilarity {
			continue
		}

		matches = append(matches, &rvectorv1.Result{
			Id:         []byte(res[i]),
			Similarity: similarity,
		})
	}

	if len(matches) == 0 {
		return &rvectorv1.SearchVectorsResponse{}, nil
	}

	sort.SliceStable(matches, func(i, j int) bool {
		return matches[i].Similarity > matches[j].Similarity
	})

	if len(matches) > limit {
		matches = matches[:limit]
	}

	fields := make([]string, 0, len(matches))
	for _, match := range matches {
		fields = append(fields, string(match.Id))
	}

	vals, err := s.redisC.HMGet(ctx, keys[2], fields...).Result()
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	ret := &rvectorv1.SearchVectorsResponse{}
	for i, match := range matches {
		if i >= len(vals) {
			break
		}
		data, ok := vals[i].(string)
		if !ok {
			continue
		}

		match.Data = []byte(data)
		ret.Results = append(ret.Results, match)
	}

	return ret, nil
}

func (s *srvVector) DeleteVectors(ctx context.Context,
	req *rvectorv1.DeleteVectorsRequest) (*rvectorv1.DeleteVectorsResponse, error) {

	if err := checkVectorCollection(req.Collection); err != nil {
		return nil, err
	}

	if len(req.Ids) == 0 {
		return &rvectorv1.DeleteVectorsResponse{}, nil
	}

	if len(req.Ids) > maxVectorIDs {
		return nil, grpcutils.InvalidArg("Too many ids: %d", len(req.Ids))
	}

	args := []any{time.Now().UnixMilli(), vectorKeyGrace.Milliseconds(),
		int64(vectorNoExpiryScore)}
	for _, id := range req.Ids {
		if err := checkVectorID(id); err != nil {
			return nil, err
		}
		args = append(args, id)
	}

	if err := vectorDeleteScript.Run(ctx, s.redisC,
		getVectorKeys(req.Collection, req.Partition), args...).Err(); err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	return &rvectorv1.DeleteVectorsResponse{}, nil
}

func (s *srvVector) DeleteCollection(ctx context.Context,
	req *rvectorv1.DeleteCollectionRequest) (*rvectorv1.DeleteCollectionResponse, error) {

	if err := checkVectorCollection(req.Collection); err != nil {
		return nil, err
	}

	match := getVectorCollectionMatch(req.Collection)
	var cursor uint64

	for {
		keys, next, err := s.redisC.Scan(ctx, cursor, match, 256).Result()
		if err != nil {
			return nil, rerr.InternalWithErr(err)
		}

		if len(keys) > 0 {
			if err := s.redisC.Del(ctx, keys...).Err(); err != nil {
				return nil, rerr.InternalWithErr(err)
			}
		}

		cursor = next
		if cursor == 0 {
			return &rvectorv1.DeleteCollectionResponse{}, nil
		}
	}
}
