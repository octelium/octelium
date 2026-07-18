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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rlockv1"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
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
