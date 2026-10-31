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

package user

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	sesscontroller "github.com/octelium/octelium/cluster/apiserver/apiserver/controllers/sessions"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func newTestReliabilitySessions(sessUID string) (*corev1.Session_Status_Connection, *corev1.Session_Status_Connection, *corev1.Session, *corev1.Session) {
	cur := &corev1.Session_Status_Connection{
		StartedAt:       pbutils.Now(),
		X25519PublicKey: bytes.Repeat([]byte{1}, 32),
	}
	prev := &corev1.Session_Status_Connection{
		StartedAt:       timestamppb.New(time.Now().Add(-time.Minute)),
		X25519PublicKey: bytes.Repeat([]byte{2}, 32),
	}
	md := &metav1.Metadata{Uid: sessUID, Name: "sess-" + sessUID}
	return cur, prev,
		&corev1.Session{Metadata: md, Status: &corev1.Session_Status{
			Type: corev1.Session_Status_CLIENT, IsConnected: true, Connection: prev,
		}},
		&corev1.Session{Metadata: &metav1.Metadata{Uid: md.Uid, Name: md.Name, UpdatedAt: pbutils.Now()},
			Status: &corev1.Session_Status{Type: corev1.Session_Status_CLIENT}}
}

func newTestReliabilityStream(t *testing.T, ctx context.Context, sessUID string, s *Server,
	conn *corev1.Session_Status_Connection) *fakeConnectStream {
	t.Helper()
	stream := newFakeConnectStream()
	stream.ctx = ctx
	cs := s.connServer.addConnectedSess(ctx, &corev1.Session{Metadata: &metav1.Metadata{Uid: sessUID}}, conn, stream)
	t.Cleanup(func() { s.connServer.removeConnectedSess(cs) })
	return stream
}

func TestSessionDisconnectReachesItsConnection(t *testing.T) {
	s := NewServer(nil)
	ctl := sesscontroller.NewController(nil, s.ConnServer())
	uid := utilrand.GetRandomStringCanonical(8)
	_, prev, old, disconnected := newTestReliabilitySessions(uid)
	stream := newTestReliabilityStream(t, t.Context(), uid, s, prev)
	require.NoError(t, ctl.OnUpdate(t.Context(), disconnected, old))
	select {
	case msg := <-stream.sent:
		require.NotNil(t, msg.GetDisconnect())
		assert.True(t, pbutils.IsEqual(disconnected.Metadata.UpdatedAt, msg.CreatedAt))
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the disconnected Connection did not receive its Disconnect")
	}
}

func TestSessionDeletionDisconnectsConnectedStream(t *testing.T) {
	s := NewServer(nil)
	ctl := sesscontroller.NewController(nil, s.ConnServer())
	uid := utilrand.GetRandomStringCanonical(8)
	cur, _, old, _ := newTestReliabilitySessions(uid)
	old.Status.Connection = cur
	stream := newTestReliabilityStream(t, t.Context(), uid, s, cur)
	require.NoError(t, ctl.OnDelete(t.Context(), old))
	select {
	case msg := <-stream.sent:
		require.NotNil(t, msg.GetDisconnect())
		require.NotNil(t, msg.CreatedAt)
		assert.False(t, msg.CreatedAt.AsTime().Before(cur.StartedAt.AsTime()),
			"a deleted Session must stop its client regardless of the client clock")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "deleting the Session did not disconnect its stream")
	}
}

func getTestReliabilityActiveIndexes(t *testing.T, tst *tests.T) []uint32 {
	t.Helper()
	cfg, err := tst.C.OcteliumC.CoreC().GetConfig(t.Context(), &rmetav1.GetOptions{Name: "sys:conn-info"})
	require.Nil(t, err, "%+v", err)
	ret := &cclusterv1.ClusterConnInfo{}
	require.Nil(t, pbutils.StructToMessage(cfg.Data.GetAttrs(), ret))
	return append(ret.ActiveIndexesWG, ret.ActiveIndexesQUIC...)
}

type testReliabilityConnectStream struct {
	stream *tstConnectStream
	cancel context.CancelFunc
	done   chan error
	state  *userv1.ConnectResponse
}

func startTestReliabilityConnect(t *testing.T, s *Server, ctx context.Context) *testReliabilityConnectStream {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	stream := &tstConnectStream{fakeConnectStream: newFakeConnectStream(), requests: make(chan *userv1.ConnectRequest, 2)}
	stream.ctx = ctx
	stream.requests <- &userv1.ConnectRequest{Type: &userv1.ConnectRequest_Initialize_{Initialize: &userv1.ConnectRequest_Initialize{}}}
	ret := &testReliabilityConnectStream{stream: stream, cancel: cancel, done: make(chan error, 1)}
	go func() { ret.done <- s.Connect(stream) }()
	select {
	case msg := <-stream.sent:
		require.NotNil(t, msg.GetState())
		ret.state = msg
	case err := <-ret.done:
		require.FailNow(t, "the connection ended before sending its state", "%+v", err)
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the connection did not send its state")
	}
	t.Cleanup(cancel)
	return ret
}

func (s *testReliabilityConnectStream) stop(t *testing.T) {
	t.Helper()
	s.cancel()
	select {
	case err := <-s.done:
		assert.Nil(t, err)
	case <-time.After(15 * time.Second):
		require.FailNow(t, "the connection did not exit")
	}
}

func (s *testReliabilityConnectStream) hasAcceptedDisconnect() bool {
	for {
		select {
		case msg := <-s.stream.sent:
			if msg.GetDisconnect() != nil &&
				(msg.CreatedAt == nil || !msg.CreatedAt.AsTime().Before(s.state.CreatedAt.AsTime())) {
				return true
			}
		default:
			return false
		}
	}
}

func TestConnectReconnectRaceKeepsNewConnection(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	s, adminS := newFakeServers(tst.C)
	usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminS, s, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	require.Nil(t, err)
	before := getTestReliabilityActiveIndexes(t, tst)
	first := startTestReliabilityConnect(t, s, usr.Ctx())
	usr.Resync()
	require.NotNil(t, usr.Session.Status.Connection)
	firstStartedAt := usr.Session.Status.Connection.StartedAt.AsTime()
	second := startTestReliabilityConnect(t, s, usr.Ctx())
	assert.True(t, first.hasAcceptedDisconnect() || func() bool {
		select {
		case err := <-first.done:
			first.done <- err
			return true
		case <-time.After(10 * time.Second):
			return false
		}
	}(), "the displaced connection must be told to stop")
	first.stop(t)
	stored, err := s.octeliumC.CoreC().GetSession(t.Context(), &rmetav1.GetOptions{Uid: usr.Session.Metadata.Uid})
	require.Nil(t, err)
	assert.True(t, stored.Status.IsConnected, "the deferred disconnect of the previous stream must not disconnect the new one")
	require.NotNil(t, stored.Status.Connection)
	assert.True(t, stored.Status.Connection.StartedAt.AsTime().After(firstStartedAt))
	assert.Equal(t, len(before)+1, len(getTestReliabilityActiveIndexes(t, tst)),
		"the previous connection addresses must be released when it is replaced")
	assert.False(t, second.hasAcceptedDisconnect(), "the new connection must not receive a Disconnect")
	second.stop(t)
	stored, err = s.octeliumC.CoreC().GetSession(t.Context(), &rmetav1.GetOptions{Uid: usr.Session.Metadata.Uid})
	require.Nil(t, err)
	assert.False(t, stored.Status.IsConnected)
	assert.Nil(t, stored.Status.Connection)
	assert.ElementsMatch(t, before, getTestReliabilityActiveIndexes(t, tst))
}

func TestConnectRepeatedOverlappingReconnectsDoNotLeakAddresses(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	s, adminS := newFakeServers(tst.C)
	usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminS, s, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	require.Nil(t, err)
	before := getTestReliabilityActiveIndexes(t, tst)
	prev := startTestReliabilityConnect(t, s, usr.Ctx())
	for range 5 {
		usr.Resync()
		cur := startTestReliabilityConnect(t, s, usr.Ctx())
		prev.stop(t)
		assert.False(t, cur.hasAcceptedDisconnect())
		assert.Equal(t, len(before)+1, len(getTestReliabilityActiveIndexes(t, tst)))
		prev = cur
	}
	stored, err := s.octeliumC.CoreC().GetSession(t.Context(), &rmetav1.GetOptions{Uid: usr.Session.Metadata.Uid})
	require.Nil(t, err)
	assert.True(t, stored.Status.IsConnected)
	assert.Equal(t, uint32(6), stored.Status.TotalConnections)
	prev.stop(t)
	assert.ElementsMatch(t, before, getTestReliabilityActiveIndexes(t, tst))
	s.connServer.RLock()
	assert.NotContains(t, s.connServer.connectedSessMap, usr.Session.Metadata.Uid)
	s.connServer.RUnlock()
}

func requireTestReliabilityMarkerFirst(t *testing.T, s *Server, sessUID string, stream *fakeConnectStream) {
	t.Helper()
	marker := &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddService_{
		AddService: &userv1.ConnectResponse_AddService{},
	}}
	require.NoError(t, s.connServer.SendMessage(marker, sessUID))
	select {
	case msg := <-stream.sent:
		require.Same(t, marker, msg, "the stream received a message that was not addressed to its Connection: %v", msg)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the marker was not delivered")
	}
}

func requireTestReliabilityDisconnect(t *testing.T, stream *fakeConnectStream) *userv1.ConnectResponse {
	t.Helper()
	select {
	case msg := <-stream.sent:
		require.NotNil(t, msg.GetDisconnect(), "%v", msg)
		return msg
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the stream did not receive a Disconnect")
		return nil
	}
}

func newTestReliabilityDisconnect() *userv1.ConnectResponse {
	return &userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{
		Disconnect: &userv1.ConnectResponse_Disconnect{},
	}}
}

func TestSendMessageToConnectionOnlyReachesThatConnection(t *testing.T) {
	s := NewServer(nil)
	uid := utilrand.GetRandomStringCanonical(8)
	cur, prev, _, _ := newTestReliabilitySessions(uid)
	stream := newTestReliabilityStream(t, t.Context(), uid, s, cur)
	require.NoError(t, s.connServer.SendMessageToConnection(newTestReliabilityDisconnect(), uid, prev))
	require.NoError(t, s.connServer.SendMessageToConnection(newTestReliabilityDisconnect(), uid, nil))
	require.NoError(t, s.connServer.SendMessageToConnection(newTestReliabilityDisconnect(), uid,
		&corev1.Session_Status_Connection{StartedAt: cur.StartedAt, X25519PublicKey: prev.X25519PublicKey}))
	requireTestReliabilityMarkerFirst(t, s, uid, stream)
	require.NoError(t, s.connServer.SendMessageToConnection(newTestReliabilityDisconnect(), uid,
		&corev1.Session_Status_Connection{StartedAt: prev.StartedAt, X25519PublicKey: bytes.Clone(cur.X25519PublicKey)}))
	msg := requireTestReliabilityDisconnect(t, stream)
	assert.NotNil(t, msg.CreatedAt)
	createdAt := timestamppb.New(time.Now().Add(-time.Hour))
	msg = newTestReliabilityDisconnect()
	msg.CreatedAt = createdAt
	require.NoError(t, s.connServer.SendMessageToConnection(msg, uid, cur))
	assert.True(t, pbutils.IsEqual(createdAt, requireTestReliabilityDisconnect(t, stream).CreatedAt))
	assert.NoError(t, s.connServer.SendMessageToConnection(newTestReliabilityDisconnect(), "missing", cur))
}

func TestSendMessageToConnectionWithoutKeysMatchesStartedAt(t *testing.T) {
	s := NewServer(nil)
	uid := utilrand.GetRandomStringCanonical(8)
	conn := &corev1.Session_Status_Connection{StartedAt: pbutils.Now()}
	stream := newTestReliabilityStream(t, t.Context(), uid, s, conn)
	require.NoError(t, s.connServer.SendMessageToConnection(newTestReliabilityDisconnect(), uid,
		&corev1.Session_Status_Connection{StartedAt: timestamppb.New(conn.StartedAt.AsTime().Add(time.Nanosecond))}))
	requireTestReliabilityMarkerFirst(t, s, uid, stream)
	require.NoError(t, s.connServer.SendMessageToConnection(newTestReliabilityDisconnect(), uid,
		&corev1.Session_Status_Connection{StartedAt: timestamppb.New(conn.StartedAt.AsTime())}))
	requireTestReliabilityDisconnect(t, stream)
}

func TestSendMessageToDisplacedConnectionDoesNotReachItsReplacement(t *testing.T) {
	s := NewServer(nil)
	uid := utilrand.GetRandomStringCanonical(8)
	cur, prev, _, _ := newTestReliabilitySessions(uid)
	prevStream := newTestReliabilityStream(t, t.Context(), uid, s, prev)
	curStream := newTestReliabilityStream(t, t.Context(), uid, s, cur)
	requireTestReliabilityDisconnect(t, prevStream)
	require.NoError(t, s.connServer.SendMessageToConnection(newTestReliabilityDisconnect(), uid, prev))
	requireTestReliabilityMarkerFirst(t, s, uid, curStream)
}

func TestSessionDisconnectAcrossReplicasOnlyReachesTheEndedConnection(t *testing.T) {
	for _, skew := range []time.Duration{-time.Hour, -50 * time.Millisecond, 0, 50 * time.Millisecond, time.Hour} {
		t.Run(skew.String(), func(t *testing.T) {
			replicaA, replicaB := NewServer(nil), NewServer(nil)
			ctlA := sesscontroller.NewController(nil, replicaA.ConnServer())
			ctlB := sesscontroller.NewController(nil, replicaB.ConnServer())
			uid := utilrand.GetRandomStringCanonical(8)
			cur, prev, old, disconnected := newTestReliabilitySessions(uid)
			disconnected.Metadata.UpdatedAt = timestamppb.New(cur.StartedAt.AsTime().Add(skew))
			prevStream := newTestReliabilityStream(t, t.Context(), uid, replicaA, prev)
			curStream := newTestReliabilityStream(t, t.Context(), uid, replicaB, cur)
			require.NoError(t, ctlA.OnUpdate(t.Context(), disconnected, old))
			require.NoError(t, ctlB.OnUpdate(t.Context(), disconnected, old))
			msg := requireTestReliabilityDisconnect(t, prevStream)
			assert.True(t, pbutils.IsEqual(disconnected.Metadata.UpdatedAt, msg.CreatedAt))
			requireTestReliabilityMarkerFirst(t, replicaB, uid, curStream)
			deleted := pbutils.Clone(old).(*corev1.Session)
			deleted.Status.Connection = cur
			require.NoError(t, ctlB.OnDelete(t.Context(), deleted))
			requireTestReliabilityDisconnect(t, curStream)
		})
	}
}

func TestSessionDisconnectWithoutEndedConnectionKeepsSessionDelivery(t *testing.T) {
	s := NewServer(nil)
	ctl := sesscontroller.NewController(nil, s.ConnServer())
	uid := utilrand.GetRandomStringCanonical(8)
	cur, _, old, disconnected := newTestReliabilitySessions(uid)
	old.Status.Connection = nil
	stream := newTestReliabilityStream(t, t.Context(), uid, s, cur)
	require.NoError(t, ctl.OnUpdate(t.Context(), disconnected, old))
	msg := requireTestReliabilityDisconnect(t, stream)
	assert.True(t, pbutils.IsEqual(disconnected.Metadata.UpdatedAt, msg.CreatedAt))
}

func TestConnectReconnectAcrossReplicasKeepsNewConnection(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	replicaA, adminS := newFakeServers(tst.C)
	replicaB, _ := newFakeServers(tst.C)
	usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminS, replicaA, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	require.Nil(t, err)
	sessUID := usr.Session.Metadata.Uid
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	release := make(chan struct{})
	connectedCh := make(chan *corev1.Session, 16)
	endedCh := make(chan string, 4)
	for name, s := range map[string]*Server{"A": replicaA, "B": replicaB} {
		ctl := sesscontroller.NewController(tst.C.OcteliumC, s.ConnServer())
		require.Nil(t, watchers.NewCoreV1(tst.C.OcteliumC).Session(ctx, nil,
			func(ctx context.Context, sess *corev1.Session) error {
				if sess.Metadata.Uid == sessUID && sess.Status.IsConnected {
					connectedCh <- sess
				}
				return nil
			},
			func(ctx context.Context, new, old *corev1.Session) error {
				if new.Metadata.Uid != sessUID {
					return nil
				}
				isEnded := old.Status.IsConnected && !new.Status.IsConnected
				if isEnded {
					select {
					case <-release:
					case <-ctx.Done():
						return nil
					}
				}
				err := ctl.OnUpdate(ctx, new, old)
				if isEnded {
					endedCh <- name
				} else if new.Status.IsConnected {
					connectedCh <- new
				}
				return err
			}, nil))
	}
	first := startTestReliabilityConnect(t, replicaA, usr.Ctx())
	usr.Resync()
	require.NotNil(t, usr.Session.Status.Connection)
	firstConn := usr.Session.Status.Connection
	for seen := 0; seen < 2; {
		select {
		case sess := <-connectedCh:
			if isSameConnection(sess.Status.Connection, firstConn) {
				seen++
			}
		case <-time.After(10 * time.Second):
			require.FailNow(t, "the Session watchers did not observe the first Connection")
		}
	}
	second := startTestReliabilityConnect(t, replicaB, usr.Ctx())
	stored, err := replicaB.octeliumC.CoreC().GetSession(t.Context(), &rmetav1.GetOptions{Uid: sessUID})
	require.Nil(t, err)
	require.NotNil(t, stored.Status.Connection)
	require.False(t, isSameConnection(stored.Status.Connection, firstConn))
	require.Eventually(t, func() bool {
		replicaB.connServer.RLock()
		defer replicaB.connServer.RUnlock()
		cs, ok := replicaB.connServer.connectedSessMap[sessUID]
		return ok && isSameConnection(cs.conn, stored.Status.Connection)
	}, 10*time.Second, 10*time.Millisecond)
	close(release)
	var ended []string
	for len(ended) < 2 {
		select {
		case name := <-endedCh:
			ended = append(ended, name)
		case <-time.After(10 * time.Second):
			require.FailNow(t, "the Session watchers did not observe the end of the first Connection", "%v", ended)
		}
	}
	assert.ElementsMatch(t, []string{"A", "B"}, ended)
	requireTestReliabilityMarkerFirst(t, replicaB, sessUID, second.stream.fakeConnectStream)
	requireTestReliabilityDisconnect(t, first.stream.fakeConnectStream)
	first.stop(t)
	stored, err = replicaB.octeliumC.CoreC().GetSession(t.Context(), &rmetav1.GetOptions{Uid: sessUID})
	require.Nil(t, err)
	assert.True(t, stored.Status.IsConnected, "the end of the first stream must not disconnect the second Connection")
	second.stop(t)
}

func TestConnectReliabilityKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to run unresolved regressions listed in tmp/client-reliability-report.md")
	}
	t.Run("RL-08-disconnect-of-previous-connection-reaches-new-stream", func(t *testing.T) {
		s := NewServer(nil)
		ctl := sesscontroller.NewController(nil, s.ConnServer())
		uid := utilrand.GetRandomStringCanonical(8)
		cur, _, old, disconnected := newTestReliabilitySessions(uid)
		disconnected.Metadata.UpdatedAt = timestamppb.New(cur.StartedAt.AsTime().Add(50 * time.Millisecond))
		stream := newTestReliabilityStream(t, t.Context(), uid, s, cur)
		require.NoError(t, ctl.OnUpdate(t.Context(), disconnected, old))
		select {
		case msg := <-stream.sent:
			assert.Nil(t, msg.GetDisconnect(),
				"the Disconnect of the previous Connection is delivered to the new one and only clock ordering protects the client")
		case <-time.After(500 * time.Millisecond):
		}
	})
	t.Run("RL-25-stale-session-snapshot-leaks-previous-addresses", func(t *testing.T) {
		tst, err := tests.Initialize(nil)
		require.Nil(t, err)
		t.Cleanup(func() { tst.Destroy() })
		s, adminS := newFakeServers(tst.C)
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminS, s, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		require.Nil(t, err)
		before := getTestReliabilityActiveIndexes(t, tst)
		_, err = s.DoInitConnect(usr.Ctx(), &userv1.ConnectRequest_Initialize{})
		require.Nil(t, err)
		stream := startTestReliabilityConnect(t, s, usr.Ctx())
		stream.stop(t)
		assert.ElementsMatch(t, before, getTestReliabilityActiveIndexes(t, tst),
			"a Connection replaced through a stale Session snapshot keeps its addresses allocated")
	})
}
