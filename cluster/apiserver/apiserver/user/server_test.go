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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
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
