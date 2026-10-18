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

package sesscontroller

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

func getConnIndex(sess *corev1.Session) uint32 {
	return upstream.GetConnectionIndexes(sess)[0].Index
}

func TestGetConnectionLastSeenAt(t *testing.T) {
	startedAt := pbutils.Timestamp(time.Now().Add(-2 * time.Hour))
	lastSeenAt := pbutils.Timestamp(time.Now().Add(-1 * time.Hour))

	assert.Nil(t, getConnectionLastSeenAt(&corev1.Session_Status_Connection{}))

	assert.Equal(t, startedAt, getConnectionLastSeenAt(&corev1.Session_Status_Connection{
		StartedAt: startedAt,
	}))

	assert.Equal(t, lastSeenAt, getConnectionLastSeenAt(&corev1.Session_Status_Connection{
		LastSeenAt: lastSeenAt,
	}))

	assert.Equal(t, lastSeenAt, getConnectionLastSeenAt(&corev1.Session_Status_Connection{
		StartedAt:  startedAt,
		LastSeenAt: lastSeenAt,
	}))

	assert.Equal(t, lastSeenAt, getConnectionLastSeenAt(&corev1.Session_Status_Connection{
		StartedAt:  lastSeenAt,
		LastSeenAt: startedAt,
	}))
}

func TestIsConnectionStale(t *testing.T) {
	now := time.Now()

	tcs := []struct {
		name    string
		sess    *corev1.Session
		isStale bool
	}{
		{
			name: "no status",
			sess: &corev1.Session{},
		},
		{
			name: "not connected",
			sess: &corev1.Session{
				Status: &corev1.Session_Status{},
			},
		},
		{
			name: "not connected with a connection",
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					Connection: &corev1.Session_Status_Connection{
						StartedAt: pbutils.Timestamp(now.Add(-2 * staleConnectionDuration)),
					},
				},
			},
		},
		{
			name: "connected without a connection",
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					IsConnected: true,
				},
			},
		},
		{
			name: "no timestamps",
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					IsConnected: true,
					Connection:  &corev1.Session_Status_Connection{},
				},
			},
		},
		{
			name: "recently started",
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					IsConnected: true,
					Connection: &corev1.Session_Status_Connection{
						StartedAt: pbutils.Timestamp(now.Add(-time.Minute)),
					},
				},
			},
		},
		{
			name: "started long ago and never seen",
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					IsConnected: true,
					Connection: &corev1.Session_Status_Connection{
						StartedAt: pbutils.Timestamp(now.Add(-staleConnectionDuration - time.Minute)),
					},
				},
			},
			isStale: true,
		},
		{
			name: "started long ago and recently seen",
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					IsConnected: true,
					Connection: &corev1.Session_Status_Connection{
						StartedAt:  pbutils.Timestamp(now.Add(-10 * staleConnectionDuration)),
						LastSeenAt: pbutils.Timestamp(now.Add(-20 * time.Minute)),
					},
				},
			},
		},
		{
			name: "seen long ago",
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					IsConnected: true,
					Connection: &corev1.Session_Status_Connection{
						StartedAt:  pbutils.Timestamp(now.Add(-10 * staleConnectionDuration)),
						LastSeenAt: pbutils.Timestamp(now.Add(-staleConnectionDuration - time.Minute)),
					},
				},
			},
			isStale: true,
		},
		{
			name: "seen just within the stale duration",
			sess: &corev1.Session{
				Status: &corev1.Session_Status{
					IsConnected: true,
					Connection: &corev1.Session_Status_Connection{
						StartedAt:  pbutils.Timestamp(now.Add(-10 * staleConnectionDuration)),
						LastSeenAt: pbutils.Timestamp(now.Add(-staleConnectionDuration + time.Minute)),
					},
				},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.isStale, isConnectionStale(tc.sess, now))
		})
	}
}

func TestSelectStaleConnections(t *testing.T) {
	c := NewController(nil)

	now := time.Now()
	staleAt := now.Add(-staleConnectionDuration - time.Minute)

	newSess := func(startedAt, lastSeenAt time.Time) *corev1.Session {
		ret := newConnectedSession(corev1.Session_Status_Connection_WIREGUARD)
		ret.Status.Connection.StartedAt = pbutils.Timestamp(startedAt)
		if !lastSeenAt.IsZero() {
			ret.Status.Connection.LastSeenAt = pbutils.Timestamp(lastSeenAt)
		}
		return ret
	}

	getUIDs := func(sessList []*corev1.Session) []string {
		var ret []string
		for _, sess := range sessList {
			ret = append(ret, sess.Metadata.Uid)
		}
		return ret
	}

	stale := newSess(staleAt, time.Time{})
	fresh := newSess(now.Add(-time.Minute), now.Add(-time.Minute))
	resumed := newSess(now.Add(-10*staleConnectionDuration), staleAt)
	disconnected := newSess(staleAt, time.Time{})
	disconnected.Status.IsConnected = false

	sessList := []*corev1.Session{stale, fresh, resumed, disconnected, {}, {Status: &corev1.Session_Status{}}}

	assert.Empty(t, c.selectStaleConnections(sessList, now))
	assert.Equal(t, 4, len(c.lastSeen))
	assert.Empty(t, c.selectStaleConnections(sessList, now.Add(staleConnectionGrace-time.Minute)))

	resumed = proto.Clone(resumed).(*corev1.Session)
	resumed.Status.Connection.LastSeenAt = pbutils.Timestamp(now.Add(staleConnectionGrace - time.Minute))
	sessList[2] = resumed

	assert.Equal(t, []string{stale.Metadata.Uid},
		getUIDs(c.selectStaleConnections(sessList, now.Add(staleConnectionGrace))))
	assert.Equal(t, now.Add(staleConnectionGrace), c.lastSeen[resumed.Metadata.Uid].since)
	assert.Equal(t, now, c.lastSeen[stale.Metadata.Uid].since)

	assert.Empty(t, c.selectStaleConnections([]*corev1.Session{fresh}, now.Add(staleConnectionGrace)))
	assert.Equal(t, 1, len(c.lastSeen))
	_, ok := c.lastSeen[stale.Metadata.Uid]
	assert.False(t, ok)

	assert.Empty(t, c.selectStaleConnections([]*corev1.Session{stale}, now.Add(2*staleConnectionGrace)))
	assert.Equal(t, []string{stale.Metadata.Uid},
		getUIDs(c.selectStaleConnections([]*corev1.Session{stale}, now.Add(3*staleConnectionGrace))))
}

type racingCoreC struct {
	rcorev1.ResourceServiceClient

	mu       sync.Mutex
	beforeFn func(in *corev1.Session)
	updates  int
}

func (c *racingCoreC) setBeforeUpdate(fn func(in *corev1.Session)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beforeFn = fn
	c.updates = 0
}

func (c *racingCoreC) getUpdates() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.updates
}

func (c *racingCoreC) UpdateSession(ctx context.Context,
	in *corev1.Session, opts ...grpc.CallOption) (*corev1.Session, error) {
	c.mu.Lock()
	fn := c.beforeFn
	c.beforeFn = nil
	c.updates++
	c.mu.Unlock()

	if fn != nil {
		fn(in)
	}

	return c.ResourceServiceClient.UpdateSession(ctx, in, opts...)
}

func TestDisconnectStaleConnections(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	coreC := &racingCoreC{
		ResourceServiceClient: fakeC.OcteliumC.CoreC(),
	}
	c := NewController(&fakeOcteliumC{
		ClientInterface: fakeC.OcteliumC,
		coreC:           coreC,
	})

	getConnInfo := func() *cclusterv1.ClusterConnInfo {
		cfg, err := fakeC.OcteliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: "sys:conn-info"})
		assert.Nil(t, err, "%+v", err)

		ret := &cclusterv1.ClusterConnInfo{}
		err = pbutils.StructToMessage(cfg.Data.GetAttrs(), ret)
		assert.Nil(t, err, "%+v", err)
		return ret
	}

	getSess := func(uid string) *corev1.Session {
		sess, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: uid})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	updateSess := func(sess *corev1.Session) *corev1.Session {
		ret, err := fakeC.OcteliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err, "%+v", err)
		return ret
	}

	connect := func(isQUIC bool, startedAt, lastSeenAt time.Time) *corev1.Session {
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err, "%+v", err)
		err = usr.ConnectWithReq(usr.Ctx(), false, isQUIC)
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usr.Session.Metadata.Uid)
		sess.Status.Connection.StartedAt = pbutils.Timestamp(startedAt)
		if !lastSeenAt.IsZero() {
			sess.Status.Connection.LastSeenAt = pbutils.Timestamp(lastSeenAt)
		}

		return updateSess(sess)
	}

	listSessions := func() []*corev1.Session {
		ret, err := c.listSessions(ctx)
		assert.Nil(t, err, "%+v", err)
		return ret
	}

	disconnectStale := func() {
		sessList := listSessions()
		c.lastSeen = make(map[string]lastSeenObservation)
		c.disconnectStaleConnections(ctx, sessList, time.Now())
		c.disconnectStaleConnections(ctx, sessList, time.Now().Add(staleConnectionGrace))
	}

	now := time.Now()
	staleAt := now.Add(-staleConnectionDuration - time.Minute)

	fresh := connect(false, now.Add(-time.Minute), time.Time{})
	recentlySeen := connect(false, now.Add(-10*staleConnectionDuration), now.Add(-20*time.Minute))
	staleNeverSeen := connect(false, staleAt, time.Time{})
	staleSeen := connect(true, now.Add(-10*staleConnectionDuration), staleAt)

	assert.Equal(t, 3, len(getConnInfo().ActiveIndexesWG))
	assert.Equal(t, 1, len(getConnInfo().ActiveIndexesQUIC))

	t.Run("disconnect", func(t *testing.T) {
		c.disconnectStaleConnections(ctx, listSessions(), time.Now())

		for _, sess := range []*corev1.Session{fresh, recentlySeen, staleNeverSeen, staleSeen} {
			assert.True(t, getSess(sess.Metadata.Uid).Status.IsConnected)
		}

		c.disconnectStaleConnections(ctx, listSessions(), time.Now().Add(staleConnectionGrace))

		for _, sess := range []*corev1.Session{fresh, recentlySeen} {
			cur := getSess(sess.Metadata.Uid)
			assert.True(t, cur.Status.IsConnected)
			assert.NotNil(t, cur.Status.Connection)
			assert.Equal(t, sess.Metadata.ResourceVersion, cur.Metadata.ResourceVersion)
		}

		for _, sess := range []*corev1.Session{staleNeverSeen, staleSeen} {
			cur := getSess(sess.Metadata.Uid)
			assert.False(t, cur.Status.IsConnected)
			assert.Nil(t, cur.Status.Connection)
			assert.Equal(t, 1, len(cur.Status.LastConnections))
			assert.True(t, pbutils.IsEqual(sess.Status.Connection.StartedAt,
				cur.Status.LastConnections[0].StartedAt))
			assert.True(t, pbutils.IsEqual(getConnectionLastSeenAt(sess.Status.Connection),
				cur.Status.LastConnections[0].EndedAt))
		}

		assert.ElementsMatch(t, []uint32{
			getConnIndex(fresh),
			getConnIndex(recentlySeen),
		}, getConnInfo().ActiveIndexesWG)
		assert.Equal(t, 0, len(getConnInfo().ActiveIndexesQUIC))

		resourceVersion := getSess(staleSeen.Metadata.Uid).Metadata.ResourceVersion
		disconnectStale()
		assert.Equal(t, resourceVersion, getSess(staleSeen.Metadata.Uid).Metadata.ResourceVersion)
	})

	t.Run("reconcile", func(t *testing.T) {
		sess := connect(false, staleAt, time.Time{})
		assert.Contains(t, getConnInfo().ActiveIndexesWG, getConnIndex(sess))

		err := c.reconcile(ctx)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, getSess(sess.Metadata.Uid).Status.IsConnected)

		obs := c.lastSeen[sess.Metadata.Uid]
		obs.since = obs.since.Add(-staleConnectionGrace)
		c.lastSeen[sess.Metadata.Uid] = obs

		err = c.reconcile(ctx)
		assert.Nil(t, err, "%+v", err)

		cur := getSess(sess.Metadata.Uid)
		assert.False(t, cur.Status.IsConnected)
		assert.Nil(t, cur.Status.Connection)
		assert.NotContains(t, getConnInfo().ActiveIndexesWG, getConnIndex(sess))

		assert.True(t, getSess(fresh.Metadata.Uid).Status.IsConnected)
		assert.True(t, getSess(recentlySeen.Metadata.Uid).Status.IsConnected)
	})

	t.Run("listed stale copy", func(t *testing.T) {
		stale := proto.Clone(recentlySeen).(*corev1.Session)
		stale.Status.Connection.LastSeenAt = pbutils.Timestamp(staleAt)

		c.disconnectStaleConnections(ctx, []*corev1.Session{stale}, time.Now())
		c.disconnectStaleConnections(ctx, []*corev1.Session{stale}, time.Now().Add(staleConnectionGrace))

		cur := getSess(recentlySeen.Metadata.Uid)
		assert.True(t, cur.Status.IsConnected)
		assert.Equal(t, recentlySeen.Metadata.ResourceVersion, cur.Metadata.ResourceVersion)
	})

	t.Run("deleted", func(t *testing.T) {
		sess := connect(false, staleAt, time.Time{})
		_, err := fakeC.OcteliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)

		err = c.disconnectStaleConnection(ctx, sess.Metadata.Uid,
			getConnectionLastSeenAt(sess.Status.Connection))
		assert.Nil(t, err, "%+v", err)

		err = c.OnDelete(ctx, sess)
		assert.Nil(t, err, "%+v", err)
	})

	t.Run("seen while disconnecting", func(t *testing.T) {
		sess := connect(false, staleAt, time.Time{})

		coreC.setBeforeUpdate(func(in *corev1.Session) {
			cur := getSess(in.Metadata.Uid)
			cur.Status.Connection.LastSeenAt = pbutils.Now()
			updateSess(cur)
		})

		err := c.disconnectStaleConnection(ctx, sess.Metadata.Uid,
			getConnectionLastSeenAt(sess.Status.Connection))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, coreC.getUpdates())

		cur := getSess(sess.Metadata.Uid)
		assert.True(t, cur.Status.IsConnected)
		assert.NotNil(t, cur.Status.Connection)
		assert.Equal(t, 0, len(cur.Status.LastConnections))
		assert.Contains(t, getConnInfo().ActiveIndexesWG, getConnIndex(sess))
	})

	t.Run("updated while disconnecting", func(t *testing.T) {
		sess := connect(false, staleAt, time.Time{})

		coreC.setBeforeUpdate(func(in *corev1.Session) {
			cur := getSess(in.Metadata.Uid)
			cur.Status.TotalAuthentications = cur.Status.TotalAuthentications + 1
			updateSess(cur)
		})

		err := c.disconnectStaleConnection(ctx, sess.Metadata.Uid,
			getConnectionLastSeenAt(sess.Status.Connection))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, coreC.getUpdates())

		cur := getSess(sess.Metadata.Uid)
		assert.False(t, cur.Status.IsConnected)
		assert.Nil(t, cur.Status.Connection)
		assert.Equal(t, sess.Status.TotalAuthentications+1, cur.Status.TotalAuthentications)
		assert.NotContains(t, getConnInfo().ActiveIndexesWG, getConnIndex(sess))
	})
}
