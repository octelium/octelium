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
	"math"
	"strings"
	"time"

	"github.com/octelium/octelium/apis/rsc/rvectorv1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver/rerr"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type srvVector struct {
	redisC  *redis.Client
	backend vectorBackend
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

type vectorBackend interface {
	upsert(ctx context.Context, opts *vectorUpsertOpts) error
	get(ctx context.Context, opts *vectorGetOpts) ([]*rvectorv1.Result, error)
	search(ctx context.Context, opts *vectorSearchOpts) ([]*rvectorv1.Result, error)
	delete(ctx context.Context, opts *vectorDeleteOpts) error
	deleteCollection(ctx context.Context, collection []byte) error
}

type vectorUpsertOpts struct {
	collection []byte
	partition  []byte
	entries    []*rvectorv1.Entry
	dimension  int
	now        time.Time
	score      int64
}

type vectorGetOpts struct {
	collection []byte
	partition  []byte
	ids        [][]byte
	now        time.Time
}

type vectorSearchOpts struct {
	collection    []byte
	partition     []byte
	vector        []float32
	minSimilarity float32
	limit         int
	now           time.Time
}

type vectorDeleteOpts struct {
	collection []byte
	partition  []byte
	ids        [][]byte
	now        time.Time
}

func newSrvVector(ctx context.Context, redisC *redis.Client) *srvVector {
	return &srvVector{
		redisC:  redisC,
		backend: newVectorBackend(ctx, redisC),
	}
}

func newVectorBackend(ctx context.Context, redisC *redis.Client) vectorBackend {
	err := redisC.FT_List(ctx).Err()
	switch {
	case err == nil:
		zap.L().Debug("Redis Search is available. Using it for the vector store")
		return newVectorBackendSearch(redisC)
	case isRedisUnknownCommandErr(err):
		zap.L().Debug("Redis Search is unavailable. Using the fallback vector store")
	default:
		zap.L().Warn("Could not check whether Redis Search is available. Using the fallback vector store",
			zap.Error(err))
	}

	return &vectorBackendFallback{
		redisC: redisC,
	}
}

func isRedisUnknownCommandErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unknown command")
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

func clampVectorSimilarity(arg float64) float32 {
	switch {
	case arg <= 0 || math.IsNaN(arg):
		return 0
	case arg > 1:
		return 1
	default:
		return float32(arg)
	}
}

func getVectorSimilarity(a, b []float32) float32 {
	var sum float32
	for i := range a {
		sum += a[i] * b[i]
	}
	return clampVectorSimilarity(float64(sum))
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

	var sum float64
	for _, val := range vec {
		if math.IsNaN(float64(val)) || math.IsInf(float64(val), 0) {
			return grpcutils.InvalidArg("Vector values must be finite")
		}
		sum += float64(val) * float64(val)
	}

	if sum <= 0 {
		return grpcutils.InvalidArg("Zero vectors are not allowed")
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

	dimension := len(req.Entries[0].Vector)

	for _, entry := range req.Entries {
		if err := checkVectorID(entry.Id); err != nil {
			return nil, err
		}
		if err := checkVector(entry.Vector); err != nil {
			return nil, err
		}
		if len(entry.Vector) != dimension {
			return nil, grpcutils.InvalidArg("All the entries must have the same dimension: %d and %d",
				dimension, len(entry.Vector))
		}
		if len(entry.Data) > maxVectorDataBytes {
			return nil, grpcutils.InvalidArg("Entry data is too large: %d", len(entry.Data))
		}
	}

	if err := s.backend.upsert(ctx, &vectorUpsertOpts{
		collection: req.Collection,
		partition:  req.Partition,
		entries:    req.Entries,
		dimension:  dimension,
		now:        now,
		score:      score,
	}); err != nil {
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

	for _, id := range req.Ids {
		if err := checkVectorID(id); err != nil {
			return nil, err
		}
	}

	results, err := s.backend.get(ctx, &vectorGetOpts{
		collection: req.Collection,
		partition:  req.Partition,
		ids:        req.Ids,
		now:        time.Now(),
	})
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	return &rvectorv1.GetVectorsResponse{
		Results: results,
	}, nil
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

	results, err := s.backend.search(ctx, &vectorSearchOpts{
		collection:    req.Collection,
		partition:     req.Partition,
		vector:        req.Vector,
		minSimilarity: req.MinSimilarity,
		limit:         limit,
		now:           time.Now(),
	})
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	return &rvectorv1.SearchVectorsResponse{
		Results: results,
	}, nil
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

	for _, id := range req.Ids {
		if err := checkVectorID(id); err != nil {
			return nil, err
		}
	}

	if err := s.backend.delete(ctx, &vectorDeleteOpts{
		collection: req.Collection,
		partition:  req.Partition,
		ids:        req.Ids,
		now:        time.Now(),
	}); err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	return &rvectorv1.DeleteVectorsResponse{}, nil
}

func (s *srvVector) DeleteCollection(ctx context.Context,
	req *rvectorv1.DeleteCollectionRequest) (*rvectorv1.DeleteCollectionResponse, error) {

	if err := checkVectorCollection(req.Collection); err != nil {
		return nil, err
	}

	if err := s.backend.deleteCollection(ctx, req.Collection); err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	return &rvectorv1.DeleteCollectionResponse{}, nil
}
