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
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/apis/rsc/rlockv1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
	"google.golang.org/grpc/status"
)

const (
	lockLeaseIDLen = 32
	lockMaxKeyLen  = 256

	lockMinTTL = 1 * time.Second
	lockMaxTTL = 5 * time.Minute

	lockMaxWait    = 60 * time.Second
	lockPollPeriod = 100 * time.Millisecond
)

var scriptUnlock = redis.NewScript(`
if redis.call("get", KEYS[1]) == ARGV[1] then
	return redis.call("del", KEYS[1])
else
	return 0
end
`)

var scriptRefresh = redis.NewScript(`
if redis.call("get", KEYS[1]) == ARGV[1] then
	return redis.call("pexpire", KEYS[1], ARGV[2])
else
	return 0
end
`)

type srvLock struct {
	redisC *redis.Client
	rlockv1.UnimplementedMainServiceServer
}

func (s *srvLock) getRedisLockKey(key []byte) string {
	return fmt.Sprintf("octelium:lock:%s", string(key))
}

func (s *srvLock) validateKey(key []byte) error {
	if len(key) == 0 {
		return grpcutils.InvalidArg("Empty key is not allowed")
	}
	if len(key) > lockMaxKeyLen {
		return grpcutils.InvalidArg("The key is too long")
	}
	return nil
}

func (s *srvLock) validateLeaseID(leaseID []byte) error {
	if len(leaseID) != lockLeaseIDLen {
		return grpcutils.InvalidArg("Invalid leaseID")
	}
	return nil
}

func (s *srvLock) getTTL(arg *umetav1.Duration) (time.Duration, error) {
	ttl := arg.ToGo()

	if ttl < lockMinTTL {
		return 0, grpcutils.InvalidArg("The ttl cannot be less than %s", lockMinTTL)
	}
	if ttl > lockMaxTTL {
		return 0, grpcutils.InvalidArg("The ttl cannot exceed %s", lockMaxTTL)
	}

	return ttl, nil
}

func (s *srvLock) toGRPCErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return status.FromContextError(ctxErr).Err()
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}

	zap.L().Warn("lock redis err", zap.Error(err))

	return grpcutils.InternalWithErr(err)
}

func (s *srvLock) Lock(ctx context.Context, req *rlockv1.LockRequest) (*rlockv1.LockResponse, error) {
	if err := s.validateKey(req.Key); err != nil {
		return nil, err
	}

	ttl, err := s.getTTL(umetav1.ToDuration(req.Ttl))
	if err != nil {
		return nil, err
	}

	wait := umetav1.ToDuration(req.Wait).ToGo()
	if wait < 0 {
		return nil, grpcutils.InvalidArg("The wait cannot be negative")
	}
	if wait > lockMaxWait {
		return nil, grpcutils.InvalidArg("The wait cannot exceed %s", lockMaxWait)
	}

	leaseID := utilrand.GetRandomBytesMust(lockLeaseIDLen)

	redisKey := s.getRedisLockKey(req.Key)

	acquired, err := s.doTryLock(ctx, redisKey, leaseID, ttl)
	if err != nil {
		return nil, err
	}
	if acquired {
		return &rlockv1.LockResponse{
			Acquired: true,
			LeaseID:  leaseID,
		}, nil
	}

	if wait == 0 {
		return &rlockv1.LockResponse{}, nil
	}

	deadline := time.Now().Add(wait)

	ticker := time.NewTicker(lockPollPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-ticker.C:
			acquired, err := s.doTryLock(ctx, redisKey, leaseID, ttl)
			if err != nil {
				return nil, err
			}
			if acquired {
				return &rlockv1.LockResponse{
					Acquired: true,
					LeaseID:  leaseID,
				}, nil
			}
			if !time.Now().Before(deadline) {
				return &rlockv1.LockResponse{}, nil
			}
		}
	}
}

func (s *srvLock) doTryLock(ctx context.Context,
	redisKey string, leaseID []byte, ttl time.Duration) (bool, error) {
	res, err := s.redisC.SetNX(ctx, redisKey, leaseID, ttl).Result()
	if err != nil {
		return false, s.toGRPCErr(ctx, err)
	}
	return res, nil
}

func (s *srvLock) Unlock(ctx context.Context, req *rlockv1.UnlockRequest) (*rlockv1.UnlockResponse, error) {
	if err := s.validateKey(req.Key); err != nil {
		return nil, err
	}

	if err := s.validateLeaseID(req.LeaseID); err != nil {
		return nil, err
	}

	res, err := scriptUnlock.Run(ctx, s.redisC,
		[]string{s.getRedisLockKey(req.Key)}, req.LeaseID).Int64()
	if err != nil {
		return nil, s.toGRPCErr(ctx, err)
	}

	return &rlockv1.UnlockResponse{Released: res == 1}, nil
}

func (s *srvLock) Refresh(ctx context.Context, req *rlockv1.RefreshRequest) (*rlockv1.RefreshResponse, error) {
	if err := s.validateKey(req.Key); err != nil {
		return nil, err
	}

	if err := s.validateLeaseID(req.LeaseID); err != nil {
		return nil, err
	}

	ttl, err := s.getTTL(umetav1.ToDuration(req.Ttl))
	if err != nil {
		return nil, err
	}

	res, err := scriptRefresh.Run(ctx, s.redisC,
		[]string{s.getRedisLockKey(req.Key)}, req.LeaseID, ttl.Milliseconds()).Int64()
	if err != nil {
		return nil, s.toGRPCErr(ctx, err)
	}

	return &rlockv1.RefreshResponse{Refreshed: res == 1}, nil
}
