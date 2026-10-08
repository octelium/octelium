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

package harness

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const testAPIName = "octelium-api.example.com"

func testTLS(t *testing.T, names ...string) (*tls.Config, *x509.CertPool) {
	t.Helper()

	crt, err := utils_cert.GenerateSelfSignedCert(names[0], names, time.Hour)
	require.NoError(t, err)

	crtPEM, err := crt.GetCertPEM()
	require.NoError(t, err)
	keyPEM, err := crt.GetPrivateKeyPEM()
	require.NoError(t, err)

	pair, err := tls.X509KeyPair([]byte(crtPEM), []byte(keyPEM))
	require.NoError(t, err)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM([]byte(crtPEM)))

	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, pool
}

type fakeConnect struct {
	stream userv1.MainService_ConnectServer
	token  string
	init   *userv1.ConnectRequest_Initialize
	done   chan struct{}
}

type fakeUserServer struct {
	userv1.UnimplementedMainServiceServer

	withholdState atomic.Bool
	failNext      atomic.Int32
	keepAlives    atomic.Int32
	disconnects   atomic.Int32

	mu     sync.Mutex
	active map[string]*fakeConnect
	ended  []string
	opened int
}

func tokenOf(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	if vals := md.Get(AuthHeader); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func (s *fakeUserServer) Connect(stream userv1.MainService_ConnectServer) error {
	tkn := tokenOf(stream.Context())
	if tkn == "" {
		return status.Error(codes.Unauthenticated, "no token")
	}

	if s.failNext.Load() > 0 {
		s.failNext.Add(-1)
		return status.Error(codes.Unavailable, "upstream connect error or disconnect/reset before headers. reset reason: overflow")
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	fc := &fakeConnect{
		stream: stream,
		token:  tkn,
		init:   req.GetInitialize(),
		done:   make(chan struct{}),
	}

	s.mu.Lock()
	s.active[tkn] = fc
	s.opened++
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if s.active[tkn] == fc {
			delete(s.active, tkn)
		}
		s.ended = append(s.ended, tkn)
		s.mu.Unlock()
	}()

	if !s.withholdState.Load() {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return err
		}

		if err := stream.Send(&userv1.ConnectResponse{
			CreatedAt: pbutils.Now(),
			Event: &userv1.ConnectResponse_State{
				State: &userv1.ConnectionState{
					X25519Key: key[:],
					Addresses: []*metav1.DualStackNetwork{{V4: "100.65.0.7/32", V6: "fdee::7/128"}},
					Gateways: []*userv1.Gateway{
						{Id: "gw-1", Addresses: []string{"192.0.2.1"}, CIDRs: []string{"100.64.0.0/24"}},
					},
				},
			},
		}); err != nil {
			return err
		}
	}

	errCh := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			if msg.GetKeepAlive() != nil {
				s.keepAlives.Add(1)
			}
		}
	}()

	select {
	case <-stream.Context().Done():
		return nil
	case <-errCh:
		return nil
	case <-fc.done:
		return status.Error(codes.Unavailable, "the server went away")
	}
}

func (s *fakeUserServer) Disconnect(ctx context.Context, _ *userv1.DisconnectRequest) (*userv1.DisconnectResponse, error) {
	s.disconnects.Add(1)

	s.mu.Lock()
	fc := s.active[tokenOf(ctx)]
	s.mu.Unlock()

	if fc != nil {
		fc.stream.Send(&userv1.ConnectResponse{
			Event: &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}},
		})
	}

	return &userv1.DisconnectResponse{}, nil
}

func (s *fakeUserServer) get(tkn string) *fakeConnect {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[tkn]
}

func (s *fakeUserServer) opens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opened
}

type fakeAPI struct {
	srv    *fakeUserServer
	dialer *IngressDialer
}

func newFakeAPI(t *testing.T, opts ...grpc.ServerOption) *fakeAPI {
	t.Helper()

	srvTLS, pool := testTLS(t, testAPIName)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	fake := &fakeUserServer{active: map[string]*fakeConnect{}}

	grpcSrv := grpc.NewServer(append([]grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(srvTLS)),
	}, opts...)...)
	userv1.RegisterMainServiceServer(grpcSrv, fake)

	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)

	return &fakeAPI{
		srv: fake,
		dialer: &IngressDialer{
			Addr:       lis.Addr().String(),
			ServerName: testAPIName,
			TLSConfig:  &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

func testSession(name string) *FleetSession {
	return &FleetSession{UID: name, AccessToken: "token-" + name}
}

func newTestPool(t *testing.T, api *fakeAPI, perConn int) *VConnPool {
	t.Helper()

	pool := NewVConnPool(api.dialer, perConn)
	t.Cleanup(pool.Close)
	return pool
}

func waitFor(t *testing.T, what string, budget time.Duration, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("Timed out after %s waiting for %s", budget, what)
}

func TestVClientLifecycle(t *testing.T) {
	api := newFakeAPI(t)
	pool := newTestPool(t, api, 1)

	sess := testSession("lifecycle")
	c := NewVClient(sess, pool, VClientOpts{
		L3Mode: userv1.ConnectRequest_Initialize_V6,
		Tunnel: userv1.ConnectRequest_Initialize_QUICV0,
	})

	var hookCalls atomic.Int32
	c.OnGateways(func(gws []*userv1.Gateway) { hookCalls.Add(1) })

	require.NoError(t, c.Connect(t.Context()))
	assert.True(t, c.IsConnected())
	assert.Equal(t, 1, c.Connects())
	assert.Equal(t, int32(1), hookCalls.Load(), "the initial state must reach the gateway hooks")

	fc := api.srv.get(sess.AccessToken)
	require.NotNil(t, fc, "the server must see the access token")
	assert.Equal(t, userv1.ConnectRequest_Initialize_V6, fc.init.L3Mode)
	assert.Equal(t, userv1.ConnectRequest_Initialize_QUICV0, fc.init.ConnectionType)

	state := c.State()
	require.NotNil(t, state)
	pub, err := c.X25519PublicKey()
	require.NoError(t, err)
	key, err := wgtypes.NewKey(state.X25519Key)
	require.NoError(t, err)
	wantPub := key.PublicKey()
	assert.Equal(t, wantPub[:], pub)

	require.NoError(t, fc.stream.Send(&userv1.ConnectResponse{
		Event: &userv1.ConnectResponse_UpdateGateway_{
			UpdateGateway: &userv1.ConnectResponse_UpdateGateway{
				Gateway: &userv1.Gateway{Id: "gw-1", Addresses: []string{"192.0.2.99"}},
			},
		},
	}))
	require.NoError(t, fc.stream.Send(&userv1.ConnectResponse{
		Event: &userv1.ConnectResponse_AddGateway_{
			AddGateway: &userv1.ConnectResponse_AddGateway{
				Gateway: &userv1.Gateway{Id: "gw-2", Addresses: []string{"192.0.2.2"}},
			},
		},
	}))
	require.NoError(t, fc.stream.Send(&userv1.ConnectResponse{
		Event: &userv1.ConnectResponse_UpdateDNS_{
			UpdateDNS: &userv1.ConnectResponse_UpdateDNS{Dns: &userv1.DNS{Servers: []string{"100.64.0.53"}}},
		},
	}))

	waitFor(t, "the DNS update", 5*time.Second, func() bool {
		return c.EventCount(EventUpdateDNS) == 1
	})

	assert.Equal(t, 1, c.EventCount(EventUpdateGateway))
	assert.Equal(t, 1, c.EventCount(EventAddGateway))
	assert.Equal(t, int32(3), hookCalls.Load())
	assert.Equal(t, []string{"100.64.0.53"}, c.State().Dns.Servers)

	gws := map[string]*userv1.Gateway{}
	for _, gw := range c.Gateways() {
		gws[gw.Id] = gw
	}
	require.Len(t, gws, 2)
	assert.Equal(t, []string{"192.0.2.99"}, gws["gw-1"].Addresses)

	at, msg := c.LastEvent(EventUpdateGateway)
	assert.False(t, at.IsZero())
	assert.NotNil(t, msg.GetUpdateGateway())

	require.NoError(t, c.Disconnect(t.Context()))
	assert.Equal(t, int32(1), api.srv.disconnects.Load())
	assert.False(t, c.IsConnected())
	assert.True(t, c.DisconnectedByServer())
	assert.Equal(t, 1, c.EventCount(EventDisconnect))

	waitFor(t, "the dedicated connection to be released", 5*time.Second, func() bool {
		return pool.Len() == 0
	})
}

func TestVClientInitTimeout(t *testing.T) {
	api := newFakeAPI(t)
	api.srv.withholdState.Store(true)
	pool := newTestPool(t, api, 1)

	c := NewVClient(testSession("timeout"), pool, VClientOpts{InitBudget: 300 * time.Millisecond})

	started := time.Now()
	err := c.Connect(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out after 300ms")
	assert.Less(t, time.Since(started), 5*time.Second)
	assert.False(t, c.IsConnected())
	assert.Equal(t, 1, c.FailedConnects())

	waitFor(t, "the connection of the failed attempt to be released", 5*time.Second, func() bool {
		return pool.Len() == 0
	})
}

func TestVClientInterruptedInit(t *testing.T) {
	api := newFakeAPI(t)
	api.srv.withholdState.Store(true)
	pool := newTestPool(t, api, 1)

	c := NewVClient(testSession("interrupted"), pool, VClientOpts{})

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	err := c.Connect(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "interrupted")
}

func TestVClientSuperviseReconnects(t *testing.T) {
	api := newFakeAPI(t)
	pool := newTestPool(t, api, 1)

	sess := testSession("supervised")
	c := NewVClient(sess, pool, VClientOpts{})

	require.NoError(t, c.Connect(t.Context()))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	superviseDone := make(chan struct{})
	go func() {
		defer close(superviseDone)
		c.Supervise(ctx, SuperviseOpts{BackoffMin: 20 * time.Millisecond, BackoffMax: 50 * time.Millisecond})
	}()

	api.srv.failNext.Store(2)
	close(api.srv.get(sess.AccessToken).done)

	waitFor(t, "the client to reconnect after the stream failed", 10*time.Second, func() bool {
		return c.Connects() == 2 && c.IsConnected()
	})

	assert.Equal(t, 2, c.FailedConnects(), "the two rejected attempts are retried")
	assert.Equal(t, 2, api.srv.opens())

	require.NoError(t, c.Disconnect(t.Context()))

	select {
	case <-superviseDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Supervise must stop once the Cluster disconnects the client")
	}
}

func TestVClientIgnoresStaleEvents(t *testing.T) {
	api := newFakeAPI(t)
	pool := newTestPool(t, api, 1)

	sess := testSession("stale")
	c := NewVClient(sess, pool, VClientOpts{})
	require.NoError(t, c.Connect(t.Context()))
	defer c.Drop()

	fc := api.srv.get(sess.AccessToken)

	require.NoError(t, fc.stream.Send(&userv1.ConnectResponse{
		CreatedAt: timestamppb.New(time.Now().Add(-time.Minute)),
		Event:     &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}},
	}))
	require.NoError(t, fc.stream.Send(&userv1.ConnectResponse{
		CreatedAt: timestamppb.New(time.Now().Add(time.Second)),
		Event:     &userv1.ConnectResponse_UpdateDNS_{UpdateDNS: &userv1.ConnectResponse_UpdateDNS{}},
	}))

	waitFor(t, "the fresh event", 5*time.Second, func() bool {
		return c.EventCount(EventUpdateDNS) == 1
	})

	assert.True(t, c.IsConnected(),
		"a Disconnect of a previous Connection must not end the current one")
	assert.Equal(t, 1, c.StaleEvents())
	assert.Zero(t, c.EventCount(EventDisconnect))
}

func TestVClientDropIsNotAGracefulDisconnect(t *testing.T) {
	api := newFakeAPI(t)
	pool := newTestPool(t, api, 1)

	sess := testSession("dropped")
	c := NewVClient(sess, pool, VClientOpts{})
	require.NoError(t, c.Connect(t.Context()))

	c.Drop()
	require.NoError(t, c.WaitDone(t.Context()))

	assert.False(t, c.DisconnectedByServer())
	assert.Error(t, c.StreamErr())
	assert.Zero(t, api.srv.disconnects.Load())
}

func TestVClientKeepAlive(t *testing.T) {
	api := newFakeAPI(t)
	pool := newTestPool(t, api, 1)

	c := NewVClient(testSession("keepalive"), pool, VClientOpts{KeepAlive: 50 * time.Millisecond})
	require.NoError(t, c.Connect(t.Context()))
	defer c.Drop()

	waitFor(t, "keep-alive messages", 5*time.Second, func() bool {
		return api.srv.keepAlives.Load() >= 3
	})
}

func TestVClientPauseReading(t *testing.T) {
	api := newFakeAPI(t)
	pool := newTestPool(t, api, 1)

	sess := testSession("paused")
	c := NewVClient(sess, pool, VClientOpts{})
	require.NoError(t, c.Connect(t.Context()))
	defer c.Drop()

	c.PauseReading()

	fc := api.srv.get(sess.AccessToken)
	for range 3 {
		require.NoError(t, fc.stream.Send(&userv1.ConnectResponse{
			Event: &userv1.ConnectResponse_UpdateDNS_{UpdateDNS: &userv1.ConnectResponse_UpdateDNS{}},
		}))
	}

	time.Sleep(200 * time.Millisecond)
	assert.Zero(t, c.EventCount(EventUpdateDNS), "a paused client must not consume events")

	c.ResumeReading()
	waitFor(t, "the buffered events after resuming", 5*time.Second, func() bool {
		return c.EventCount(EventUpdateDNS) == 3
	})
}

func TestVConnPoolSharing(t *testing.T) {
	api := newFakeAPI(t)
	pool := newTestPool(t, api, 4)

	var clients []*VClient
	for i := range 10 {
		c := NewVClient(testSession(string(rune('a'+i))), pool, VClientOpts{})
		require.NoError(t, c.Connect(t.Context()))
		clients = append(clients, c)
	}

	assert.Equal(t, 3, pool.Dialed(), "10 streams at 4 per connection need 3 connections")
	assert.Equal(t, 3, pool.Len())

	for _, c := range clients {
		c.Drop()
		require.NoError(t, c.WaitDone(t.Context()))
	}

	assert.Equal(t, 3, pool.Len(), "idle shared connections are kept for reuse")

	c := NewVClient(testSession("reuse"), pool, VClientOpts{})
	require.NoError(t, c.Connect(t.Context()))
	defer c.Drop()

	assert.Equal(t, 3, pool.Dialed(), "a new stream reuses an idle shared connection")
}

func TestVClientFreeze(t *testing.T) {
	api := newFakeAPI(t, grpc.KeepaliveParams(keepalive.ServerParameters{
		Time:    time.Second,
		Timeout: time.Second,
	}))
	pool := newTestPool(t, api, 1)

	sess := testSession("frozen")
	c := NewVClient(sess, pool, VClientOpts{})
	require.NoError(t, c.Connect(t.Context()))

	c.Freeze()

	waitFor(t, "the server to drop the frozen client", 15*time.Second, func() bool {
		return api.srv.get(sess.AccessToken) == nil
	})

	assert.True(t, c.IsConnected(),
		"a frozen client cannot notice that the server dropped it")

	c.Thaw()

	select {
	case <-c.Done():
	case <-time.After(15 * time.Second):
		t.Fatal("the thawed client must notice the dropped stream")
	}

	assert.False(t, c.DisconnectedByServer())
}

func TestSessionUIDFromToken(t *testing.T) {
	uid := uuid.New()

	content, err := pbutils.Marshal(&authv1.TokenT0{
		Content: &authv1.TokenT0_Content{
			Type:    authv1.TokenT0_Content_ACCESS_TOKEN,
			Subject: uid[:],
		},
		Signature: []byte("signature"),
	})
	require.NoError(t, err)

	got, err := SessionUIDFromToken(base64.RawURLEncoding.EncodeToString(append([]byte{0x1}, content...)))
	require.NoError(t, err)
	assert.Equal(t, uid.String(), got)

	_, err = SessionUIDFromToken(base64.RawURLEncoding.EncodeToString(append([]byte{0x2}, content...)))
	require.Error(t, err, "an unknown token version must be rejected")

	_, err = SessionUIDFromToken("not-a-token")
	require.Error(t, err)

	_, err = SessionUIDFromToken("")
	require.Error(t, err)
}
