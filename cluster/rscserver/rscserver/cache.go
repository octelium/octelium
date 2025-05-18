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

	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"go.uber.org/zap"
)

type srvCache struct {
	redisC *redis.Client
	rcachev1.UnimplementedMainServiceServer
}

func (s *srvCache) getRedisCacheKey(key []byte) string {
	return fmt.Sprintf("octelium:cache:%s", string(key))
}

func (s *srvCache) SetCache(ctx context.Context, req *rcachev1.SetCacheRequest) (*rcachev1.SetCacheResponse, error) {
	if len(req.Key) == 0 {
		return nil, grpcutils.InvalidArg("Empty key is not allowed")
	}

	if err := s.redisC.Set(ctx, s.getRedisCacheKey(req.Key), req.Data, umetav1.ToDuration(req.Duration).ToGo()).Err(); err != nil {
		zap.L().Warn("setCache err", zap.Error(err))
		return nil, grpcutils.InvalidArgWithErr(err)
	}
	return &rcachev1.SetCacheResponse{}, nil
}

func (s *srvCache) GetCache(ctx context.Context, req *rcachev1.GetCacheRequest) (*rcachev1.GetCacheResponse, error) {
	if len(req.Key) == 0 {
		return nil, grpcutils.NotFound("This key does not exist")
	}

	var cmd *redis.StringCmd
	if req.Delete {
		cmd = s.redisC.GetDel(ctx, s.getRedisCacheKey(req.Key))
	} else {
		cmd = s.redisC.Get(ctx, s.getRedisCacheKey(req.Key))
	}

	res, err := cmd.Result()
	if err != nil {
		if err == redis.Nil {
			return nil, grpcutils.NotFound("This key does not exist")
		}
		return nil, grpcutils.InternalWithErr(err)
	}
	return &rcachev1.GetCacheResponse{
		Data: []byte(res),
	}, nil
}

func (s *srvCache) DeleteCache(ctx context.Context, req *rcachev1.DeleteCacheRequest) (*rcachev1.DeleteCacheResponse, error) {

	if len(req.Key) == 0 {
		return &rcachev1.DeleteCacheResponse{}, nil
	}

	err := s.redisC.Del(ctx, s.getRedisCacheKey(req.Key)).Err()
	if err != nil {
		if err == redis.Nil {
			return nil, grpcutils.NotFound("This key does not exist")
		}
		return nil, grpcutils.InternalWithErr(err)
	}
	return &rcachev1.DeleteCacheResponse{}, nil
}
