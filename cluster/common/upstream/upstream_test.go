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

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rlockv1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestHostedServices(t *testing.T) {
	sess := &corev1.Session{Status: &corev1.Session_Status{}}
	assert.Nil(t, GetHostServicesFromConn(sess))
	sess.Status.Connection = &corev1.Session_Status_Connection{}
	assert.Nil(t, GetHostServicesFromConn(sess))
	upstream := &corev1.Session_Status_Connection_Upstream{
		ServiceRef: &metav1.ObjectReference{Name: "service.namespace", Uid: "service"},
		Port:       15000, L4Type: corev1.Session_Status_Connection_Upstream_TCP,
		Backend: &corev1.Session_Status_Connection_Upstream_Backend{Host: "127.0.0.1", Port: 8080},
	}
	assert.Nil(t, GetHostServicesFromUpstream(upstream, sess))
	sess.Status.Connection.Addresses = []*metav1.DualStackNetwork{{V4: "100.64.0.2/32", V6: "fd00::2/128"}}
	sess.Status.Connection.Upstreams = []*corev1.Session_Status_Connection_Upstream{upstream}
	services := GetHostServicesFromConn(sess)
	assert.Len(t, services, 1)
	assert.Equal(t, "service.namespace", services[0].Name)
	assert.EqualValues(t, 15000, services[0].Port)
	assert.Equal(t, "127.0.0.1", services[0].Upstream.Host)
	assert.EqualValues(t, 8080, services[0].Upstream.Port)
	assert.Equal(t, &metav1.DualStackIP{Ipv4: "100.64.0.2", Ipv6: "fd00::2"}, services[0].Address)
	other := &corev1.Session_Status_Connection_Upstream{ServiceRef: &metav1.ObjectReference{Uid: "other"}}
	sess.Status.Connection.Upstreams = []*corev1.Session_Status_Connection_Upstream{upstream, other, upstream, upstream}
	assert.Nil(t, RemoveConnectionUpstreams(context.Background(), nil, sess, &corev1.Service{Metadata: &metav1.Metadata{Uid: "service"}}))
	assert.Equal(t, []*corev1.Session_Status_Connection_Upstream{other}, sess.Status.Connection.Upstreams)
	assert.Nil(t, RemoveConnectionUpstreams(context.Background(), nil, sess, &corev1.Service{Metadata: &metav1.Metadata{Uid: "missing"}}))
	sess.Status.Connection = nil
	assert.Nil(t, RemoveConnectionUpstreams(context.Background(), nil, sess, nil))
}

func TestListenerPort(t *testing.T) {
	sess := &corev1.Session{Metadata: &metav1.Metadata{Name: "session"}, Status: &corev1.Session_Status{}}
	_, err := getListenerPort(sess)
	assert.NotNil(t, err)
	sess.Status.Connection = &corev1.Session_Status_Connection{}
	_, err = getListenerPort(sess)
	assert.NotNil(t, err)
	sess.Status.Connection.ServiceOptions = &corev1.Session_Status_Connection_ServiceOptions{PortStart: 15000}
	port, err := getListenerPort(sess)
	assert.Nil(t, err)
	assert.Equal(t, 15000, port)
	sess.Status.Connection.Upstreams = []*corev1.Session_Status_Connection_Upstream{{Port: 15002}, {Port: 15000}, {Port: 15000}}
	port, err = getListenerPort(sess)
	assert.Nil(t, err)
	assert.Equal(t, 15001, port)
	for i := int32(15000); i < 25000; i++ {
		sess.Status.Connection.Upstreams = append(sess.Status.Connection.Upstreams, &corev1.Session_Status_Connection_Upstream{Port: i})
	}
	_, err = getListenerPort(sess)
	assert.NotNil(t, err)
}

func TestRemoveConnIndex(t *testing.T) {
	network := &cclusterv1.ClusterConnInfo{ActiveIndexesWG: []uint32{1, 2, 2, 3}, ActiveIndexesQUIC: []uint32{2, 3}}
	removeConnIndex(network, 2, corev1.Session_Status_Connection_WIREGUARD)
	assert.Equal(t, []uint32{1, 3}, network.ActiveIndexesWG)
	assert.Equal(t, []uint32{2, 3}, network.ActiveIndexesQUIC)
	removeConnIndex(network, 3, corev1.Session_Status_Connection_QUICV0)
	assert.Equal(t, []uint32{1, 3}, network.ActiveIndexesWG)
	assert.Equal(t, []uint32{2}, network.ActiveIndexesQUIC)
	removeConnIndex(network, 1, corev1.Session_Status_Connection_TYPE_UNKNOWN)
	assert.Equal(t, []uint32{1, 3}, network.ActiveIndexesWG)
}

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

func TestSetDisconnected(t *testing.T) {
	{
		sess := &corev1.Session{
			Status: &corev1.Session_Status{},
		}

		SetDisconnected(sess, pbutils.Now())
		assert.False(t, sess.Status.IsConnected)
		assert.Nil(t, sess.Status.Connection)
		assert.Equal(t, 0, len(sess.Status.LastConnections))
	}

	{
		startedAt := pbutils.Timestamp(time.Now().Add(-2 * time.Hour))
		endedAt := pbutils.Timestamp(time.Now().Add(-1 * time.Hour))
		prev := &corev1.Session_Status_LastConnection{
			StartedAt: pbutils.Timestamp(time.Now().Add(-4 * time.Hour)),
			EndedAt:   pbutils.Timestamp(time.Now().Add(-3 * time.Hour)),
		}

		sess := &corev1.Session{
			Status: &corev1.Session_Status{
				IsConnected: true,
				Connection: &corev1.Session_Status_Connection{
					StartedAt: startedAt,
				},
				LastConnections: []*corev1.Session_Status_LastConnection{prev},
			},
		}

		SetDisconnected(sess, endedAt)
		assert.False(t, sess.Status.IsConnected)
		assert.Nil(t, sess.Status.Connection)
		assert.Equal(t, 2, len(sess.Status.LastConnections))
		assert.True(t, pbutils.IsEqual(startedAt, sess.Status.LastConnections[0].StartedAt))
		assert.True(t, pbutils.IsEqual(endedAt, sess.Status.LastConnections[0].EndedAt))
		assert.Equal(t, prev, sess.Status.LastConnections[1])
	}

	{
		var lastConnections []*corev1.Session_Status_LastConnection
		for range maxLastConnections {
			lastConnections = append(lastConnections, &corev1.Session_Status_LastConnection{
				StartedAt: pbutils.Now(),
				EndedAt:   pbutils.Now(),
			})
		}

		startedAt := pbutils.Now()
		sess := &corev1.Session{
			Status: &corev1.Session_Status{
				IsConnected: true,
				Connection: &corev1.Session_Status_Connection{
					StartedAt: startedAt,
				},
				LastConnections: lastConnections,
			},
		}

		SetDisconnected(sess, pbutils.Now())
		assert.Equal(t, maxLastConnections, len(sess.Status.LastConnections))
		assert.True(t, pbutils.IsEqual(startedAt, sess.Status.LastConnections[0].StartedAt))
		assert.Equal(t, lastConnections[maxLastConnections-2], sess.Status.LastConnections[maxLastConnections-1])
	}
}
