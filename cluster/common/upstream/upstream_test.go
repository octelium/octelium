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

package upstream

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rlockv1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

type fakeLockC struct {
	rlockv1.MainServiceClient

	mu          sync.Mutex
	lockReqs    []*rlockv1.LockRequest
	unlockReqs  []*rlockv1.UnlockRequest
	unlockErrs  []error
	unlockDeads []bool
}

func (c *fakeLockC) Lock(ctx context.Context,
	in *rlockv1.LockRequest, opts ...grpc.CallOption) (*rlockv1.LockResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lockReqs = append(c.lockReqs, in)

	return &rlockv1.LockResponse{
		Acquired: true,
		LeaseID:  []byte("lease"),
	}, nil
}

func (c *fakeLockC) Unlock(ctx context.Context,
	in *rlockv1.UnlockRequest, opts ...grpc.CallOption) (*rlockv1.UnlockResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, hasDeadline := ctx.Deadline()

	c.unlockReqs = append(c.unlockReqs, in)
	c.unlockErrs = append(c.unlockErrs, ctx.Err())
	c.unlockDeads = append(c.unlockDeads, hasDeadline)

	return &rlockv1.UnlockResponse{Released: true}, nil
}

type fakeOcteliumC struct {
	octeliumc.ClientInterface
	lockC *fakeLockC
}

func (c *fakeOcteliumC) LockC() rlockv1.MainServiceClient {
	return c.lockC
}

func TestDoLock(t *testing.T) {
	lockC := &fakeLockC{}
	octeliumC := &fakeOcteliumC{lockC: lockC}

	leaseID, err := doLock(context.Background(), octeliumC)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, []byte("lease"), leaseID)

	assert.Equal(t, 1, len(lockC.lockReqs))
	req := lockC.lockReqs[0]
	assert.Equal(t, getLockKey(), req.Key)
	assert.Equal(t, lockTTL, umetav1.ToDuration(req.Ttl).ToGo())
	assert.Equal(t, lockWait, umetav1.ToDuration(req.Wait).ToGo())

	assert.True(t, lockSectionTimeout < lockTTL)
	assert.True(t, lockSectionTimeout+unlockTimeout < lockTTL)
}

func TestDoUnlockCanceledContext(t *testing.T) {
	lockC := &fakeLockC{}
	octeliumC := &fakeOcteliumC{lockC: lockC}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	doUnlock(ctx, octeliumC, []byte("lease"))

	assert.Equal(t, 1, len(lockC.unlockReqs))
	assert.Equal(t, getLockKey(), lockC.unlockReqs[0].Key)
	assert.Equal(t, []byte("lease"), lockC.unlockReqs[0].LeaseID)
	assert.Nil(t, lockC.unlockErrs[0])
	assert.True(t, lockC.unlockDeads[0])
}

func TestDoUnlockExpiredContext(t *testing.T) {
	lockC := &fakeLockC{}
	octeliumC := &fakeOcteliumC{lockC: lockC}

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()

	doUnlock(ctx, octeliumC, []byte("lease"))

	assert.Equal(t, 1, len(lockC.unlockReqs))
	assert.Nil(t, lockC.unlockErrs[0])
}

func TestGetConnectionIndexes(t *testing.T) {
	assert.Nil(t, GetConnectionIndexes(&corev1.Session{}))
	assert.Nil(t, GetConnectionIndexes(&corev1.Session{
		Status: &corev1.Session_Status{},
	}))

	assert.Equal(t, []ConnIndex{
		{
			Type:  corev1.Session_Status_Connection_QUICV0,
			Index: 0x0a0b,
		},
		{
			Type:  corev1.Session_Status_Connection_QUICV0,
			Index: 0x0c,
		},
	}, GetConnectionIndexes(&corev1.Session{
		Status: &corev1.Session_Status{
			Connection: &corev1.Session_Status_Connection{
				Type: corev1.Session_Status_Connection_QUICV0,
				Addresses: []*metav1.DualStackNetwork{
					{
						V4: "10.11.10.11/32",
						V6: "fdee::2:a0b/128",
					},
					{
						V6: "fdee::2:c/128",
					},
				},
			},
		},
	}))
}
