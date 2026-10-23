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
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rlockv1"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func durSeconds(n uint32) *metav1.Duration {
	return &metav1.Duration{
		Type: &metav1.Duration_Seconds{
			Seconds: n,
		},
	}
}

func durMinutes(n uint32) *metav1.Duration {
	return &metav1.Duration{
		Type: &metav1.Duration_Minutes{
			Minutes: n,
		},
	}
}

func durMilliseconds(n uint32) *metav1.Duration {
	return &metav1.Duration{
		Type: &metav1.Duration_Milliseconds{
			Milliseconds: n,
		},
	}
}

func TestLock(t *testing.T) {

	srvLock := &srvLock{
		redisC: redisutils.NewClient(),
	}

	ctx := context.Background()

	{
		_, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Ttl: durSeconds(10),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: []byte(utilrand.GetRandomString(8)),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: []byte(utilrand.GetRandomString(8)),
			Ttl: durMilliseconds(10),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: []byte(utilrand.GetRandomString(8)),
			Ttl: durMinutes(30),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key:  []byte(utilrand.GetRandomString(8)),
			Ttl:  durSeconds(10),
			Wait: durMinutes(5),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     []byte(utilrand.GetRandomString(8)),
			LeaseID: utilrand.GetRandomBytesMust(16),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key: []byte(utilrand.GetRandomString(8)),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srvLock.Refresh(ctx, &rlockv1.RefreshRequest{
			Key:     []byte(utilrand.GetRandomString(8)),
			LeaseID: utilrand.GetRandomBytesMust(64),
			Ttl:     durSeconds(10),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		key := []byte(utilrand.GetRandomString(8))

		res, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(10),
		})
		assert.Nil(t, err)
		assert.True(t, res.Acquired)
		assert.Equal(t, lockLeaseIDLen, len(res.LeaseID))

		res2, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(10),
		})
		assert.Nil(t, err)
		assert.False(t, res2.Acquired)
		assert.Equal(t, 0, len(res2.LeaseID))

		unlockRes, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     key,
			LeaseID: res.LeaseID,
		})
		assert.Nil(t, err)
		assert.True(t, unlockRes.Released)

		res3, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(10),
		})
		assert.Nil(t, err)
		assert.True(t, res3.Acquired)
		assert.NotEqual(t, res.LeaseID, res3.LeaseID)
	}

	{
		key := []byte(utilrand.GetRandomString(8))

		res, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(10),
		})
		assert.Nil(t, err)
		assert.True(t, res.Acquired)

		unlockRes, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     key,
			LeaseID: utilrand.GetRandomBytesMust(lockLeaseIDLen),
		})
		assert.Nil(t, err)
		assert.False(t, unlockRes.Released)

		res2, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(10),
		})
		assert.Nil(t, err)
		assert.False(t, res2.Acquired)

		unlockRes2, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     key,
			LeaseID: res.LeaseID,
		})
		assert.Nil(t, err)
		assert.True(t, unlockRes2.Released)
	}

	{
		key := []byte(utilrand.GetRandomString(8))

		res, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(1),
		})
		assert.Nil(t, err)
		assert.True(t, res.Acquired)

		time.Sleep(2 * time.Second)

		res2, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(10),
		})
		assert.Nil(t, err)
		assert.True(t, res2.Acquired)

		unlockRes, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     key,
			LeaseID: res.LeaseID,
		})
		assert.Nil(t, err)
		assert.False(t, unlockRes.Released)
	}

	{
		key := []byte(utilrand.GetRandomString(8))

		res, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(1),
		})
		assert.Nil(t, err)
		assert.True(t, res.Acquired)

		refreshRes, err := srvLock.Refresh(ctx, &rlockv1.RefreshRequest{
			Key:     key,
			LeaseID: res.LeaseID,
			Ttl:     durSeconds(30),
		})
		assert.Nil(t, err)
		assert.True(t, refreshRes.Refreshed)

		time.Sleep(2 * time.Second)

		res2, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(10),
		})
		assert.Nil(t, err)
		assert.False(t, res2.Acquired)

		unlockRes, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     key,
			LeaseID: res.LeaseID,
		})
		assert.Nil(t, err)
		assert.True(t, unlockRes.Released)
	}

	{
		key := []byte(utilrand.GetRandomString(8))

		res, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(10),
		})
		assert.Nil(t, err)
		assert.True(t, res.Acquired)

		refreshRes, err := srvLock.Refresh(ctx, &rlockv1.RefreshRequest{
			Key:     key,
			LeaseID: utilrand.GetRandomBytesMust(lockLeaseIDLen),
			Ttl:     durSeconds(30),
		})
		assert.Nil(t, err)
		assert.False(t, refreshRes.Refreshed)

		unlockRes, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     key,
			LeaseID: res.LeaseID,
		})
		assert.Nil(t, err)
		assert.True(t, unlockRes.Released)
	}

	{
		key := []byte(utilrand.GetRandomString(8))

		refreshRes, err := srvLock.Refresh(ctx, &rlockv1.RefreshRequest{
			Key:     key,
			LeaseID: utilrand.GetRandomBytesMust(lockLeaseIDLen),
			Ttl:     durSeconds(10),
		})
		assert.Nil(t, err)
		assert.False(t, refreshRes.Refreshed)

		unlockRes, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     key,
			LeaseID: utilrand.GetRandomBytesMust(lockLeaseIDLen),
		})
		assert.Nil(t, err)
		assert.False(t, unlockRes.Released)
	}

	{
		key := []byte(utilrand.GetRandomString(8))

		res, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(2),
		})
		assert.Nil(t, err)
		assert.True(t, res.Acquired)

		start := time.Now()
		res2, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key:  key,
			Ttl:  durSeconds(10),
			Wait: durSeconds(8),
		})
		assert.Nil(t, err)
		assert.True(t, res2.Acquired)
		assert.True(t, time.Since(start) >= 1*time.Second)
		assert.NotEqual(t, res.LeaseID, res2.LeaseID)

		unlockRes, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     key,
			LeaseID: res2.LeaseID,
		})
		assert.Nil(t, err)
		assert.True(t, unlockRes.Released)
	}

	{
		key := []byte(utilrand.GetRandomString(8))

		res, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(30),
		})
		assert.Nil(t, err)
		assert.True(t, res.Acquired)

		start := time.Now()
		res2, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key:  key,
			Ttl:  durSeconds(10),
			Wait: durSeconds(1),
		})
		assert.Nil(t, err)
		assert.False(t, res2.Acquired)
		assert.Equal(t, 0, len(res2.LeaseID))
		assert.True(t, time.Since(start) >= 1*time.Second)

		unlockRes, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     key,
			LeaseID: res.LeaseID,
		})
		assert.Nil(t, err)
		assert.True(t, unlockRes.Released)
	}

	{
		ctxCancel, cancel := context.WithCancel(ctx)

		key := []byte(utilrand.GetRandomString(8))

		res, err := srvLock.Lock(ctx, &rlockv1.LockRequest{
			Key: key,
			Ttl: durSeconds(30),
		})
		assert.Nil(t, err)
		assert.True(t, res.Acquired)

		go func() {
			time.Sleep(500 * time.Millisecond)
			cancel()
		}()

		_, err = srvLock.Lock(ctxCancel, &rlockv1.LockRequest{
			Key:  key,
			Ttl:  durSeconds(10),
			Wait: durSeconds(8),
		})
		assert.NotNil(t, err)
		assert.Equal(t, codes.Canceled, status.Code(err))

		unlockRes, err := srvLock.Unlock(ctx, &rlockv1.UnlockRequest{
			Key:     key,
			LeaseID: res.LeaseID,
		})
		assert.Nil(t, err)
		assert.True(t, unlockRes.Released)
	}
}

func TestLockConcurrent(t *testing.T) {
	ctx := t.Context()
	srv := &srvLock{redisC: redisutils.NewClient()}
	t.Cleanup(func() { srv.redisC.Close() })
	key := utilrand.GetRandomBytesMust(lockMaxKeyLen)
	t.Cleanup(func() { srv.redisC.Del(context.Background(), srv.getRedisLockKey(key)) })

	var wg sync.WaitGroup
	start := make(chan struct{})
	leases := make(chan []byte, 64)
	for range 64 {
		wg.Go(func() {
			<-start
			res, err := srv.Lock(ctx, &rlockv1.LockRequest{Key: key, Ttl: durMinutes(5)})
			if !assert.Nil(t, err) {
				return
			}
			if res.Acquired {
				leases <- res.LeaseID
			} else {
				assert.Empty(t, res.LeaseID)
			}
		})
	}
	close(start)
	wg.Wait()
	close(leases)
	require.Len(t, leases, 1)
	lease := <-leases
	require.Len(t, lease, lockLeaseIDLen)
	res, err := srv.Unlock(ctx, &rlockv1.UnlockRequest{Key: key, LeaseID: lease})
	require.Nil(t, err)
	require.True(t, res.Released)

	next, err := srv.Lock(ctx, &rlockv1.LockRequest{Key: key, Ttl: durSeconds(1)})
	require.Nil(t, err)
	require.True(t, next.Acquired)
	assert.NotEqual(t, lease, next.LeaseID)
	refreshed, err := srv.Refresh(ctx, &rlockv1.RefreshRequest{Key: key, LeaseID: lease, Ttl: durMinutes(5)})
	require.Nil(t, err)
	assert.False(t, refreshed.Refreshed)
	res, err = srv.Unlock(ctx, &rlockv1.UnlockRequest{Key: key, LeaseID: lease})
	require.Nil(t, err)
	assert.False(t, res.Released)
	stored, err := srv.redisC.Get(ctx, srv.getRedisLockKey(key)).Bytes()
	require.Nil(t, err)
	assert.Equal(t, next.LeaseID, stored)
}

func TestLockValidationAndBackendErrors(t *testing.T) {
	srv := &srvLock{redisC: redisutils.NewClient()}
	require.Nil(t, srv.redisC.Close())
	ctx := t.Context()
	for _, key := range [][]byte{nil, {}, bytes.Repeat([]byte("x"), lockMaxKeyLen+1)} {
		_, err := srv.Lock(ctx, &rlockv1.LockRequest{Key: key, Ttl: durSeconds(1)})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		_, err = srv.Unlock(ctx, &rlockv1.UnlockRequest{Key: key, LeaseID: make([]byte, lockLeaseIDLen)})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		_, err = srv.Refresh(ctx, &rlockv1.RefreshRequest{Key: key, LeaseID: make([]byte, lockLeaseIDLen), Ttl: durSeconds(1)})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	for _, ttl := range []*metav1.Duration{nil, {}, durMilliseconds(999), durMilliseconds(300001)} {
		_, err := srv.Lock(ctx, &rlockv1.LockRequest{Key: []byte("key"), Ttl: ttl})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		_, err = srv.Refresh(ctx, &rlockv1.RefreshRequest{Key: []byte("key"), LeaseID: make([]byte, lockLeaseIDLen), Ttl: ttl})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}

	_, err := srv.Lock(ctx, &rlockv1.LockRequest{Key: []byte("key"), Ttl: durSeconds(1)})
	assert.Equal(t, codes.Internal, status.Code(err))
	_, err = srv.Unlock(ctx, &rlockv1.UnlockRequest{Key: []byte("key"), LeaseID: make([]byte, lockLeaseIDLen)})
	assert.Equal(t, codes.Internal, status.Code(err))
	_, err = srv.Refresh(ctx, &rlockv1.RefreshRequest{Key: []byte("key"), LeaseID: make([]byte, lockLeaseIDLen), Ttl: durSeconds(1)})
	assert.Equal(t, codes.Internal, status.Code(err))

	for _, entry := range []struct {
		err  error
		code codes.Code
	}{
		{context.Canceled, codes.Canceled},
		{context.DeadlineExceeded, codes.DeadlineExceeded},
	} {
		assert.Equal(t, entry.code, status.Code(srv.toGRPCErr(ctx, entry.err)))
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = srv.Lock(canceled, &rlockv1.LockRequest{Key: []byte("key"), Ttl: durSeconds(1)})
	assert.Equal(t, codes.Canceled, status.Code(err))
}
