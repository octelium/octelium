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
	"github.com/octelium/octelium/apis/main/metav1"
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

const maxSlidingWindowAmount = 1 << 48

var rateLimitReserveScript = redis.NewScript(`
local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
for i = 1, #expired do
	local weight = redis.call('HGET', KEYS[2], expired[i])
	if weight then
		redis.call('HINCRBY', KEYS[2], '_total', string.format('%d', -tonumber(weight)))
		redis.call('HDEL', KEYS[2], expired[i])
	end
end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
if redis.call('ZCARD', KEYS[1]) == 0 then
	redis.call('HSET', KEYS[2], '_total', '0')
end
local score = redis.call('ZSCORE', KEYS[1], ARGV[4])
local weight = redis.call('HGET', KEYS[2], ARGV[4])
local previous = 0
if weight then
	previous = tonumber(weight)
end
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
redis.call('HSET', KEYS[2], ARGV[4], ARGV[5])
local total = redis.call('HINCRBY', KEYS[2], '_total',
	string.format('%d', tonumber(ARGV[5]) - previous))
redis.call('PEXPIRE', KEYS[1], ARGV[6])
redis.call('PEXPIRE', KEYS[2], ARGV[6])
if total > tonumber(ARGV[3]) then
	total = redis.call('HINCRBY', KEYS[2], '_total',
		string.format('%d', previous - tonumber(ARGV[5])))
	if score then
		redis.call('ZADD', KEYS[1], score, ARGV[4])
		redis.call('HSET', KEYS[2], ARGV[4], weight)
	else
		redis.call('ZREM', KEYS[1], ARGV[4])
		redis.call('HDEL', KEYS[2], ARGV[4])
	end
	return {0, total}
end
return {1, total}
`)

var rateLimitReconcileScript = redis.NewScript(`
local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
for i = 1, #expired do
	local weight = redis.call('HGET', KEYS[2], expired[i])
	if weight then
		redis.call('HINCRBY', KEYS[2], '_total', string.format('%d', -tonumber(weight)))
		redis.call('HDEL', KEYS[2], expired[i])
	end
end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
if redis.call('ZCARD', KEYS[1]) == 0 then
	redis.call('HSET', KEYS[2], '_total', '0')
end
local weight = redis.call('HGET', KEYS[2], ARGV[3])
local previous = 0
if weight then
	previous = tonumber(weight)
end
if tonumber(ARGV[4]) > 0 then
	redis.call('ZADD', KEYS[1], ARGV[1], ARGV[3])
	redis.call('HSET', KEYS[2], ARGV[3], ARGV[4])
else
	redis.call('ZREM', KEYS[1], ARGV[3])
	redis.call('HDEL', KEYS[2], ARGV[3])
end
local total = redis.call('HINCRBY', KEYS[2], '_total',
	string.format('%d', tonumber(ARGV[4]) - previous))
redis.call('PEXPIRE', KEYS[1], ARGV[5])
redis.call('PEXPIRE', KEYS[2], ARGV[5])
return total
`)

func getReservationKeys(key []byte) []string {
	hash := vutils.Sha256SumHex(key)
	return []string{
		fmt.Sprintf("octelium:rlswr:%s", hash),
		fmt.Sprintf("octelium:rlswr:%s:w", hash),
	}
}

func checkReservationArgs(key, id []byte, window *metav1.Duration, amount int64) error {
	if len(key) == 0 {
		return grpcutils.InvalidArg("Empty key is not allowed")
	}

	if len(id) == 0 {
		return grpcutils.InvalidArg("Empty id is not allowed")
	}

	if window == nil {
		return grpcutils.InvalidArg("Window duration must be set")
	}

	if umetav1.ToDuration(window).ToGo() <= 0 {
		return grpcutils.InvalidArg("Window duration must be positive")
	}

	if amount < 0 {
		return grpcutils.InvalidArg("Amount cannot be negative: %d", amount)
	}

	if amount > maxSlidingWindowAmount {
		return grpcutils.InvalidArg("Amount is too large: %d", amount)
	}

	return nil
}

func (s *srvRateLimit) ReserveSlidingWindow(ctx context.Context,
	req *rratelimitv1.ReserveSlidingWindowRequest) (*rratelimitv1.ReserveSlidingWindowResponse, error) {

	if err := checkReservationArgs(req.Key, req.Id, req.Window, req.Amount); err != nil {
		return nil, err
	}

	if req.Limit <= 0 {
		return nil, grpcutils.InvalidArg("Limit must be positive: %d", req.Limit)
	}

	now := time.Now().UnixMicro()
	window := umetav1.ToDuration(req.Window).ToGo()

	res, err := rateLimitReserveScript.Run(ctx, s.redisC, getReservationKeys(req.Key),
		now, now-window.Microseconds(), req.Limit,
		vutils.Sha256SumHex(req.Id), req.Amount,
		(window + 1*time.Second).Milliseconds()).Int64Slice()
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	if len(res) != 2 {
		return nil, rerr.Internal("Invalid reservation result")
	}

	return &rratelimitv1.ReserveSlidingWindowResponse{
		IsAllowed: res[0] == 1,
		Total:     res[1],
	}, nil
}

func (s *srvRateLimit) ReconcileSlidingWindow(ctx context.Context,
	req *rratelimitv1.ReconcileSlidingWindowRequest) (*rratelimitv1.ReconcileSlidingWindowResponse, error) {

	if err := checkReservationArgs(req.Key, req.Id, req.Window, req.Amount); err != nil {
		return nil, err
	}

	now := time.Now().UnixMicro()
	window := umetav1.ToDuration(req.Window).ToGo()

	total, err := rateLimitReconcileScript.Run(ctx, s.redisC, getReservationKeys(req.Key),
		now, now-window.Microseconds(),
		vutils.Sha256SumHex(req.Id), req.Amount,
		(window + 1*time.Second).Milliseconds()).Int64()
	if err != nil {
		return nil, rerr.InternalWithErr(err)
	}

	return &rratelimitv1.ReconcileSlidingWindowResponse{
		Total: total,
	}, nil
}
