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
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func newFakeServers(fakeC *tests.FakeClient) (*Server, *admin.Server) {

	return NewServer(fakeC.OcteliumC), admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
}

type fakeConnectStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent chan *userv1.ConnectResponse
}

func newFakeConnectStream() *fakeConnectStream {
	return &fakeConnectStream{
		ctx:  context.Background(),
		sent: make(chan *userv1.ConnectResponse, 16),
	}
}

func (s *fakeConnectStream) Context() context.Context {
	return s.ctx
}

func (s *fakeConnectStream) Send(msg *userv1.ConnectResponse) error {
	s.sent <- msg
	return nil
}

func (s *fakeConnectStream) Recv() (*userv1.ConnectRequest, error) {
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}

func TestConnServerDisplace(t *testing.T) {
	srv := NewServer(nil)
	sess := &corev1.Session{
		Metadata: &metav1.Metadata{
			Uid: utilrand.GetRandomStringCanonical(8),
		},
	}

	first := newFakeConnectStream()
	firstCS := srv.connServer.addConnectedSess(first.ctx, sess, nil, first)

	second := newFakeConnectStream()
	secondCS := srv.connServer.addConnectedSess(second.ctx, sess, nil, second)

	select {
	case msg := <-first.sent:
		assert.NotNil(t, msg.GetDisconnect(), "the displaced stream got %v", msg)
	case <-time.After(10 * time.Second):
		t.Fatalf("The displaced stream has not been notified")
	}

	select {
	case msg := <-second.sent:
		t.Fatalf("The new stream must not be notified. Got %v", msg)
	case <-time.After(time.Second):
	}

	select {
	case <-firstCS.Done():
	case <-time.After(sessionDisplaceGrace + 10*time.Second):
		t.Fatalf("The displaced stream has not been closed")
	}

	select {
	case <-secondCS.Done():
		t.Fatalf("The new stream has been closed")
	default:
	}

	srv.connServer.removeConnectedSess(firstCS)

	srv.connServer.RLock()
	cur := srv.connServer.connectedSessMap[sess.Metadata.Uid]
	srv.connServer.RUnlock()
	assert.Equal(t, secondCS, cur)
}

func TestConnServerBroadcastMessageByL3Mode(t *testing.T) {
	srv := NewServer(nil)

	newConnected := func(conn *corev1.Session_Status_Connection) (*fakeConnectStream, *connectedSession) {
		sess := &corev1.Session{
			Metadata: &metav1.Metadata{
				Uid: utilrand.GetRandomStringCanonical(8),
			},
		}
		stream := newFakeConnectStream()
		return stream, srv.connServer.addConnectedSess(stream.ctx, sess, conn, stream)
	}

	v4, v4CS := newConnected(&corev1.Session_Status_Connection{L3Mode: corev1.Session_Status_Connection_V4})
	v6, v6CS := newConnected(&corev1.Session_Status_Connection{L3Mode: corev1.Session_Status_Connection_V6})
	both, bothCS := newConnected(&corev1.Session_Status_Connection{L3Mode: corev1.Session_Status_Connection_BOTH})
	unknown, unknownCS := newConnected(nil)
	otherV4, otherV4CS := newConnected(&corev1.Session_Status_Connection{L3Mode: corev1.Session_Status_Connection_V4})

	for _, cs := range []*connectedSession{v4CS, v6CS, bothCS, unknownCS, otherV4CS} {
		t.Cleanup(func() { srv.connServer.removeConnectedSess(cs) })
	}

	newMsg := func(server string) *userv1.ConnectResponse {
		return &userv1.ConnectResponse{
			Event: &userv1.ConnectResponse_UpdateDNS_{
				UpdateDNS: &userv1.ConnectResponse_UpdateDNS{
					Dns: &userv1.DNS{
						Servers: []string{server},
					},
				},
			},
		}
	}

	calls := map[corev1.Session_Status_Connection_L3Mode]int{}
	err := srv.connServer.BroadcastMessageByL3Mode(
		func(l3Mode corev1.Session_Status_Connection_L3Mode) *userv1.ConnectResponse {
			calls[l3Mode]++
			switch l3Mode {
			case corev1.Session_Status_Connection_V4:
				return newMsg("1.2.3.4")
			case corev1.Session_Status_Connection_V6:
				return nil
			default:
				return newMsg("::1")
			}
		})
	assert.Nil(t, err)

	assert.Equal(t, map[corev1.Session_Status_Connection_L3Mode]int{
		corev1.Session_Status_Connection_V4:   1,
		corev1.Session_Status_Connection_V6:   1,
		corev1.Session_Status_Connection_BOTH: 1,
	}, calls, "the message must be built once per L3 mode")

	recv := func(stream *fakeConnectStream) *userv1.ConnectResponse {
		select {
		case msg := <-stream.sent:
			return msg
		case <-time.After(10 * time.Second):
			t.Fatalf("The stream has not received the message")
			return nil
		}
	}

	for _, stream := range []*fakeConnectStream{v4, otherV4} {
		msg := recv(stream)
		assert.Equal(t, []string{"1.2.3.4"}, msg.GetUpdateDNS().GetDns().GetServers())
		assert.NotNil(t, msg.CreatedAt)
	}

	for _, stream := range []*fakeConnectStream{both, unknown} {
		msg := recv(stream)
		assert.Equal(t, []string{"::1"}, msg.GetUpdateDNS().GetDns().GetServers())
	}

	select {
	case msg := <-v6.sent:
		t.Fatalf("The stream must not receive a message for its L3 mode. Got %v", msg)
	case <-time.After(time.Second):
	}
}

func tstConnectedSession(t *testing.T, uid string, size int) *connectedSession {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &connectedSession{sess: &corev1.Session{Metadata: &metav1.Metadata{Uid: uid}}, ctx: ctx, cancel: cancel, sendCh: make(chan *userv1.ConnectResponse, size)}
}

func TestConnServerBackpressure(t *testing.T) {
	for _, method := range []string{"Broadcast", "Unicast", "L3Mode"} {
		t.Run(method, func(t *testing.T) {
			s := NewServer(nil)
			require.Same(t, s.connServer, s.ConnServer())
			slow, fast := tstConnectedSession(t, "slow", 1), tstConnectedSession(t, "fast", 2)
			slow.l3Mode, fast.l3Mode = corev1.Session_Status_Connection_V4, corev1.Session_Status_Connection_V6
			slow.sendCh <- &userv1.ConnectResponse{}
			s.connServer.connectedSessMap = map[string]*connectedSession{"slow": slow, "fast": fast}
			msg := &userv1.ConnectResponse{CreatedAt: timestamppb.Now()}
			ts := msg.CreatedAt
			switch method {
			case "Broadcast":
				require.Nil(t, s.ConnServer().BroadcastMessage(msg))
			case "Unicast":
				require.Nil(t, s.ConnServer().SendMessage(msg, "slow"))
				require.Nil(t, s.ConnServer().SendMessage(msg, "fast"))
			case "L3Mode":
				require.Nil(t, s.ConnServer().BroadcastMessageByL3Mode(func(mode corev1.Session_Status_Connection_L3Mode) *userv1.ConnectResponse { return msg }))
			}
			assert.ErrorIs(t, slow.ctx.Err(), context.Canceled)
			assert.Nil(t, fast.ctx.Err())
			require.Len(t, fast.sendCh, 1)
			assert.Same(t, msg, <-fast.sendCh)
			assert.Same(t, ts, msg.CreatedAt)
		})
	}
}

func TestConnServerMessages(t *testing.T) {
	s := NewServer(nil)
	assert.Nil(t, s.ConnServer().BroadcastMessage(&userv1.ConnectResponse{}))
	msg := &userv1.ConnectResponse{}
	assert.Nil(t, s.ConnServer().SendMessage(msg, "missing"))
	assert.Nil(t, msg.CreatedAt)
	first, second := tstConnectedSession(t, "first", 4), tstConnectedSession(t, "second", 4)
	s.connServer.connectedSessMap = map[string]*connectedSession{"first": first, "second": second}
	require.Nil(t, s.ConnServer().SendMessage(msg, "first"))
	require.Len(t, first.sendCh, 1)
	assert.Same(t, msg, <-first.sendCh)
	assert.Empty(t, second.sendCh)
	assert.NotNil(t, msg.CreatedAt)
	msg = &userv1.ConnectResponse{}
	require.Nil(t, s.ConnServer().BroadcastMessage(msg))
	assert.Same(t, msg, <-first.sendCh)
	assert.Same(t, msg, <-second.sendCh)
	assert.NotNil(t, msg.CreatedAt)
	msg = &userv1.ConnectResponse{}
	require.Nil(t, s.ConnServer().BroadcastMessageByL3Mode(func(mode corev1.Session_Status_Connection_L3Mode) *userv1.ConnectResponse { return msg }))
	assert.NotNil(t, msg.CreatedAt)
	assert.Same(t, msg, <-first.sendCh)
	assert.Same(t, msg, <-second.sendCh)
	for range 4 {
		assert.True(t, first.enqueue(msg))
	}
	assert.False(t, first.enqueue(msg))
}

type tstSendStream struct {
	userv1.MainService_ConnectServer
	send func(*userv1.ConnectResponse) error
}

func (s *tstSendStream) Send(msg *userv1.ConnectResponse) error {
	return s.send(msg)
}

func TestConnServerSendFailure(t *testing.T) {
	cs := tstConnectedSession(t, "session", 1)
	cs.stream = &tstSendStream{send: func(msg *userv1.ConnectResponse) error { return fmt.Errorf("stream closed") }}
	cs.sendCh <- &userv1.ConnectResponse{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		cs.runSendLoop()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "the failed stream did not exit")
	}
	assert.ErrorIs(t, cs.ctx.Err(), context.Canceled)
}

func TestConnServerConcurrentMessages(t *testing.T) {
	s := NewServer(nil)
	cs := tstConnectedSession(t, "session", 1024)
	s.connServer.connectedSessMap["session"] = cs
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 64 {
				assert.Nil(t, s.ConnServer().SendMessage(&userv1.ConnectResponse{}, "session"))
			}
		})
	}
	wg.Wait()
	assert.Nil(t, cs.ctx.Err())
	require.Len(t, cs.sendCh, 1024)
	for range 1024 {
		assert.NotNil(t, (<-cs.sendCh).CreatedAt)
	}
}
