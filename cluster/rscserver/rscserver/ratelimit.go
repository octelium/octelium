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
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/apis/rsc/rratelimitv1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver/rerr"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
)

type srvRateLimit struct {
	redisC *redis.Client
	rratelimitv1.UnimplementedMainServiceServer
}

func (s *srvRateLimit) CheckSlidingWindow(ctx context.Context,
	req *rratelimitv1.CheckSlidingWindowRequest) (*rratelimitv1.CheckSlidingWindowResponse, error) {

	if len(req.Key) == 0 {
		return nil, grpcutils.InvalidArg("Empty key is not allowed")
	}

	key := fmt.Sprintf("octelium:rlsw:%s", vutils.Sha256SumHex(req.Key))
	now := time.Now().UnixMicro()
	window := umetav1.ToDuration(req.Window).ToGo()
	windowStart := now - window.Microseconds()
	pipe := s.redisC.TxPipeline()

	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprint(windowStart))

	pipe.ZAdd(ctx, key, &redis.Z{Score: float64(now), Member: now})

	countCmd := pipe.ZCard(ctx, key)

	pipe.Expire(ctx, key, window+1*time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	count := countCmd.Val()
	ret := &rratelimitv1.CheckSlidingWindowResponse{
		IsAllowed: req.Limit >= int64(count),
	}

	return ret, nil
}
