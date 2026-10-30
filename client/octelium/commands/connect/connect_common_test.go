// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connect

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/client/octelium/commands/connect/controller"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestParsePublishService(t *testing.T) {

	{
		_, err := parsePublishedService("svc1")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1:")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1::")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1.ns1")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("1.2.3.4")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1:0.0.0.0")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1:localhost")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1:9999999")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1:0")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1::8080")
		assert.NotNil(t, err)
	}
	{
		res, err := parsePublishedService("svc1:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1", res.svc)
		assert.Equal(t, "localhost", res.addr)
		assert.Equal(t, 9090, res.port)
	}
	{
		res, err := parsePublishedService("svc1.ns1:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1.ns1", res.svc)
		assert.Equal(t, "localhost", res.addr)
		assert.Equal(t, 9090, res.port)
	}
	{
		res, err := parsePublishedService("svc1:0.0.0.0:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1", res.svc)
		assert.Equal(t, "0.0.0.0", res.addr)
		assert.Equal(t, 9090, res.port)
	}
	{
		res, err := parsePublishedService("svc1:[::1]:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1", res.svc)
		assert.Equal(t, "::1", res.addr)
		assert.Equal(t, 9090, res.port)
	}
	{
		res, err := parsePublishedService("svc1.ns1:0.0.0.0:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1.ns1", res.svc)
		assert.Equal(t, "0.0.0.0", res.addr)
		assert.Equal(t, 9090, res.port)
	}
	{
		res, err := parsePublishedService("svc1.ns1:[::1]:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1.ns1", res.svc)
		assert.Equal(t, "::1", res.addr)
		assert.Equal(t, 9090, res.port)
	}

	{
		res, err := parsePublishedService("svc1:localhost:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1", res.svc)
		assert.Equal(t, "localhost", res.addr)
		assert.Equal(t, 9090, res.port)
	}
}

func TestGetReconnectBackoff(t *testing.T) {
	for range 100 {
		var prev time.Duration

		for attempt := 1; attempt < 20; attempt++ {
			ret := getReconnectBackoff(attempt)

			assert.GreaterOrEqual(t, ret, reconnectBackoffMin)
			assert.LessOrEqual(t, ret, reconnectBackoffMax)
			assert.GreaterOrEqual(t, ret, prev)

			prev = ret
		}
	}

	assert.Equal(t, reconnectBackoffMax, getReconnectBackoff(20))
}

var allCodes = []codes.Code{
	codes.Canceled, codes.Unknown, codes.InvalidArgument, codes.DeadlineExceeded,
	codes.NotFound, codes.AlreadyExists, codes.PermissionDenied, codes.ResourceExhausted,
	codes.FailedPrecondition, codes.Aborted, codes.OutOfRange, codes.Unimplemented,
	codes.Internal, codes.Unavailable, codes.DataLoss, codes.Unauthenticated,
}

func TestIsRejectedErr(t *testing.T) {
	for _, code := range allCodes {
		want := code == codes.InvalidArgument || code == codes.PermissionDenied || code == codes.NotFound

		err := status.Error(code, "err")
		assert.Equal(t, want, isRejectedErr(err), code.String())
		assert.Equal(t, want, isRejectedErr(errors.Wrap(err, "Could not connect to API Server")), code.String())
	}

	assert.False(t, isRejectedErr(nil))
	assert.False(t, isRejectedErr(errors.New("Could not get initial state message after a timeout")))
}

func TestShouldReconnect(t *testing.T) {
	errs := []error{
		nil,
		errors.New("Could not initialize controller"),
	}
	for _, code := range allCodes {
		errs = append(errs, status.Error(code, "err"))
	}

	for _, err := range errs {
		assert.False(t, shouldReconnect(tryConnectRet{err: err}, false),
			"%+v: a stop requested by the Cluster, the user or a failed cleanup is final", err)
		assert.False(t, shouldReconnect(tryConnectRet{err: err}, true),
			"%+v: a stop requested by the Cluster, the user or a failed cleanup is final", err)

		assert.True(t, shouldReconnect(tryConnectRet{err: err, needsReconnect: true}, true),
			"%+v: a client that has connected before must never give up", err)

		assert.Equal(t, !isRejectedErr(err),
			shouldReconnect(tryConnectRet{err: err, needsReconnect: true}, false),
			"%+v: only a rejected request stops a client that has never connected", err)
	}
}

type fakeConnectServer struct {
	userv1.UnimplementedMainServiceServer

	mu       sync.Mutex
	errs     []error
	attempts int
}

func (s *fakeConnectServer) Connect(stream userv1.MainService_ConnectServer) error {
	s.mu.Lock()
	err := s.errs[min(s.attempts, len(s.errs)-1)]
	s.attempts++
	s.mu.Unlock()

	if _, recvErr := stream.Recv(); recvErr != nil {
		return recvErr
	}

	return err
}

func (s *fakeConnectServer) getAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func runFakeConnect(t *testing.T, errs ...error) (*fakeConnectServer, *Connector, *[]*Event) {
	t.Helper()

	t.Setenv("OCTELIUM_DEV", "false")
	t.Setenv("OCTELIUM_PRODUCTION", "true")

	dir, err := os.MkdirTemp("", "octelium-connect-")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, os.RemoveAll(dir))
	})

	socketPath := filepath.Join(dir, "proxy.sock")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", socketPath)

	lis, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	srv := &fakeConnectServer{errs: errs}
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)

	var mu sync.Mutex
	var events []*Event

	c, err := NewConnector("example.com", &Opts{
		L3Mode: "v4",
		OnEvent: func(ev *Event) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	})
	require.NoError(t, err)

	return srv, c, &events
}

func TestRunStopsOnRejectionBeforeConnecting(t *testing.T) {
	for _, code := range []codes.Code{codes.InvalidArgument, codes.PermissionDenied, codes.NotFound} {
		t.Run(code.String(), func(t *testing.T) {
			srv, c, events := runFakeConnect(t, status.Error(code, "rejected"))

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			err := c.Run(ctx)
			assert.Equal(t, code, status.Code(err))
			assert.True(t, isRejectedErr(err))
			assert.Equal(t, 1, srv.getAttempts())

			require.NotEmpty(t, *events)
			last := (*events)[len(*events)-1]
			assert.Equal(t, EventTypeDisconnected, last.Type)
			assert.Equal(t, code, status.Code(last.Err))
		})
	}
}

func TestRunStopsOnRejectionWithLongTestName(t *testing.T) {
	t.Setenv("GOTMPDIR", t.TempDir())

	t.Run(strings.Repeat("long", 32), func(t *testing.T) {
		_, c, _ := runFakeConnect(t, status.Error(codes.NotFound, "rejected"))

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		assert.Equal(t, codes.NotFound, status.Code(c.Run(ctx)))
	})
}

func TestRunRetriesBeforeConnecting(t *testing.T) {
	for _, code := range []codes.Code{codes.Unauthenticated, codes.Unavailable} {
		t.Run(code.String(), func(t *testing.T) {
			srv, c, events := runFakeConnect(t,
				status.Error(code, "transient"), status.Error(codes.NotFound, "rejected"))

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			err := c.Run(ctx)
			assert.Equal(t, codes.NotFound, status.Code(err))
			assert.Equal(t, 2, srv.getAttempts())

			var retried bool
			for _, ev := range *events {
				if ev.Type == EventTypeConnecting && status.Code(ev.Err) == code {
					retried = true
				}
			}
			assert.True(t, retried, "the client must keep connecting after %s", code)
		})
	}
}

type testConnectStream struct {
	grpc.ClientStream
	sendFn func(*userv1.ConnectRequest) error
	recvFn func() (*userv1.ConnectResponse, error)
}

func (s *testConnectStream) Send(req *userv1.ConnectRequest) error {
	return s.sendFn(req)
}

func (s *testConnectStream) Recv() (*userv1.ConnectResponse, error) {
	return s.recvFn()
}

type testConnectAPI struct {
	userv1.UnimplementedMainServiceServer
	connectFn    func(userv1.MainService_ConnectServer) error
	getServiceFn func(context.Context, *metav1.GetOptions) (*userv1.Service, error)
	listFn       func(context.Context, *userv1.ListServiceOptions) (*userv1.ServiceList, error)
}

func (s *testConnectAPI) Connect(stream userv1.MainService_ConnectServer) error {
	return s.connectFn(stream)
}

func (s *testConnectAPI) GetService(ctx context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
	return s.getServiceFn(ctx, req)
}

func (s *testConnectAPI) ListService(ctx context.Context, req *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
	return s.listFn(ctx, req)
}

func newTestConnectAPIClient(t *testing.T, srv *testConnectAPI) userv1.MainServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	return userv1.NewMainServiceClient(conn)
}

func clearTestConnectEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"OCTELIUM_QUIC", "OCTELIUM_FULL_DNS", "OCTELIUM_KEEPALIVE", "OCTELIUM_MTU",
		"OCTELIUM_ESSH", "OCTELIUM_ESSH_USER", "OCTELIUM_ESSH_PORT", "OCTELIUM_ESSH_IP_ADDRS",
		"OCTELIUM_ESOCKS5", "OCTELIUM_ESOCKS5_PORT", "OCTELIUM_ESOCKS5_IP_ADDRS",
		"OCTELIUM_LOCAL_DNS_SERVER",
	} {
		t.Setenv(key, "")
	}
}

func testStateStream(state *userv1.ConnectionState) *testConnectStream {
	return &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
		return &userv1.ConnectResponse{
			CreatedAt: timestamppb.Now(),
			Event:     &userv1.ConnectResponse_State{State: state},
		}, nil
	}}
}

func TestConnectorDefaultsAndEvents(t *testing.T) {
	_, err := NewConnector("", nil)
	require.Error(t, err)
	c, err := NewConnector("example.com", nil)
	require.NoError(t, err)
	require.NotNil(t, c.opts)
	assert.NotPanics(t, func() { c.setEvent(&Event{Type: EventTypeConnecting}) })
	var got *Event
	c.opts.OnEvent = func(ev *Event) { got = ev }
	ev := &Event{Type: EventTypeReconnecting, Err: io.EOF}
	c.setEvent(ev)
	assert.Same(t, ev, got)
}

func TestArgsToOptsPreservesPublishedServiceOrder(t *testing.T) {
	a := &args{
		L3Mode: "v6", IgnoreDNS: true, ServeServices: []string{"ssh.ns1"},
		ImplementationMode: "gvisor", UseESSH: true, ESSHUser: "alice", UseESOCKS5: true,
		UseLocalDNS: true, LocalDNSListenAddr: "[::1]:1053", UseFullDNS: true, TunnelMode: "quicv0",
		PublishServices: []string{"web:65535", "dns.ns1:[::1]:1053", "web:127.0.0.1:8080"},
	}
	o, err := a.toOpts()
	require.NoError(t, err)
	assert.Equal(t, &Opts{
		L3Mode: "v6", IgnoreDNS: true, ServeServices: []string{"ssh.ns1"},
		ImplementationMode: "gvisor", UseESSH: true, ESSHUser: "alice", UseESOCKS5: true,
		UseLocalDNS: true, LocalDNSListenAddr: "[::1]:1053", UseFullDNS: true, TunnelMode: "quicv0",
		PublishServices: []*PublishedService{
			{Name: "web", Address: "localhost", Port: 65535},
			{Name: "dns.ns1", Address: "::1", Port: 1053},
			{Name: "web", Address: "127.0.0.1", Port: 8080},
		},
	}, o)
	for _, arg := range []string{"", "web:-1", "web:65536", "web:example.com:8080", "web:1.2.3.4:abc", "web:a:b:c"} {
		t.Run(arg, func(t *testing.T) {
			o, err := (&args{PublishServices: []string{"valid:8080", arg}}).toOpts()
			assert.Error(t, err)
			assert.Nil(t, o)
		})
	}
}

func TestSendInitializeRequestNegotiation(t *testing.T) {
	clearTestConnectEnv(t)
	for _, tt := range []struct {
		mode string
		want userv1.ConnectRequest_Initialize_L3Mode
	}{
		{"v4", userv1.ConnectRequest_Initialize_V4},
		{"v6", userv1.ConnectRequest_Initialize_V6},
		{"both", userv1.ConnectRequest_Initialize_BOTH},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			c, err := NewConnector("example.com", &Opts{
				L3Mode: tt.mode, IgnoreDNS: true, TunnelMode: "quicv0",
				ServeServices: []string{"web", "ssh.ns1"}, UseESSH: true, UseESOCKS5: true,
			})
			require.NoError(t, err)
			var got *userv1.ConnectRequest
			err = c.sendInitializeRequest(&testConnectStream{sendFn: func(req *userv1.ConnectRequest) error {
				got = req
				return nil
			}}, []*cliconfigv1.Connection_Preferences_PublishedService{
				{Name: "dns.ns1", HostAddress: "::1", HostPort: 1053},
			})
			require.NoError(t, err)
			init := got.GetInitialize()
			require.NotNil(t, init)
			assert.Equal(t, tt.want, init.L3Mode)
			assert.Equal(t, userv1.ConnectRequest_Initialize_QUICV0, init.ConnectionType)
			assert.True(t, init.IgnoreDNS)
			assert.True(t, init.ESSHEnable)
			assert.True(t, init.ESOCKS5Enable)
			assert.Equal(t, int32(defaultESSHPort), init.ESSHPort)
			assert.Equal(t, int32(defaultESOCKS5Port), init.ESOCKS5Port)
			assert.Equal(t, []*userv1.ConnectRequest_Initialize_PublishedService{
				{Name: "dns.ns1", Address: "::1", Port: 1053},
			}, init.PublishedServices)
			assert.Equal(t, []*userv1.ConnectRequest_Initialize_ServiceOptions_Service{
				{Name: "web.default"}, {Name: "ssh.ns1"},
			}, init.ServiceOptions.Services)
			assert.GreaterOrEqual(t, init.ServiceOptions.PortStart, int32(20000))
			assert.LessOrEqual(t, init.ServiceOptions.PortStart, int32(24000))
		})
	}
}

func TestSendInitializeRequestServeAllAndErrors(t *testing.T) {
	clearTestConnectEnv(t)
	for _, serveAll := range []bool{false, true} {
		c, err := NewConnector("example.com", &Opts{L3Mode: "v4", ServeAll: serveAll})
		require.NoError(t, err)
		err = c.sendInitializeRequest(&testConnectStream{sendFn: func(req *userv1.ConnectRequest) error {
			assert.Equal(t, serveAll, req.GetInitialize().GetServiceOptions().GetServeAll())
			if !serveAll {
				assert.Nil(t, req.GetInitialize().ServiceOptions)
			}
			assert.Equal(t, userv1.ConnectRequest_Initialize_UNSET, req.GetInitialize().ConnectionType)
			return io.ErrClosedPipe
		}}, nil)
		assert.ErrorIs(t, err, io.ErrClosedPipe)
	}
	c, err := NewConnector("example.com", &Opts{L3Mode: "v4", ServeServices: []string{"invalid.name.extra"}})
	require.NoError(t, err)
	assert.Error(t, c.sendInitializeRequest(&testConnectStream{sendFn: func(*userv1.ConnectRequest) error {
		t.Fatal("invalid service names must be rejected before sending")
		return nil
	}}, nil))
}

func TestGetStateMsgSkipsUnknownEvents(t *testing.T) {
	want := &userv1.ConnectionState{L3Mode: userv1.ConnectionState_V6}
	createdAt := timestamppb.Now()
	messages := []*userv1.ConnectResponse{
		nil, {}, {Event: &userv1.ConnectResponse_UpdateDNS_{}},
		{CreatedAt: createdAt, Event: &userv1.ConnectResponse_State{State: want}},
	}
	var n int
	stream := &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
		msg := messages[n]
		n++
		return msg, nil
	}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	got, at, err := getStateMsg(ctx, stream)
	require.NoError(t, err)
	assert.Same(t, want, got)
	assert.Same(t, createdAt, at)
	assert.Equal(t, len(messages), n)
}

func TestGetStateMsgPreservesStreamErrors(t *testing.T) {
	for _, code := range allCodes {
		t.Run(code.String(), func(t *testing.T) {
			want := status.Error(code, "initialization failed")
			state, at, err := getStateMsg(t.Context(), &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
				return nil, want
			}})
			assert.Same(t, want, err)
			assert.Nil(t, state)
			assert.Nil(t, at)
		})
	}
	_, _, err := getStateMsg(t.Context(), &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
		return nil, io.EOF
	}})
	assert.ErrorIs(t, err, io.EOF)
}

func TestGetConnectionConfigPreferences(t *testing.T) {
	clearTestConnectEnv(t)
	t.Setenv("OCTELIUM_KEEPALIVE", "45")
	t.Setenv("OCTELIUM_MTU", "1400")
	t.Setenv("OCTELIUM_ESSH_PORT", "2222")
	t.Setenv("OCTELIUM_ESSH_USER", "environment-user")
	t.Setenv("OCTELIUM_ESSH_IP_ADDRS", "127.0.0.1, ::1")
	t.Setenv("OCTELIUM_ESOCKS5_PORT", "1081")
	t.Setenv("OCTELIUM_ESOCKS5_IP_ADDRS", "127.0.0.2, ::2")
	c, err := NewConnector("example.com", &Opts{
		L3Mode: "both", TunnelMode: "quicv0", IgnoreDNS: true, ServeAll: true,
		UseESSH: true, ESSHUser: "option-user", UseESOCKS5: true,
		MTU: 1280, UserHome: t.TempDir(), UseFullDNS: true, LocalDNSListenAddr: "::1",
	})
	require.NoError(t, err)
	published := []*cliconfigv1.Connection_Preferences_PublishedService{{Name: "web.default"}}
	state := &userv1.ConnectionState{L3Mode: userv1.ConnectionState_V6}
	cfg, at, err := c.getConnectionConfig(t.Context(), testStateStream(state), published)
	require.NoError(t, err)
	assert.Same(t, state, cfg.Connection)
	assert.True(t, cfg.CreatedAt.IsValid())
	assert.True(t, at.IsValid())
	assert.Equal(t, "example.com", cfg.Info.Cluster.Domain)
	p := cfg.Preferences
	assert.Equal(t, int32(1280), p.Mtu)
	assert.Equal(t, int32(45), p.KeepAliveSeconds)
	assert.Equal(t, cliconfigv1.Connection_Preferences_V6, p.L3Mode)
	assert.Equal(t, cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0, p.ConnectionType)
	assert.Equal(t, published, p.PublishedServices)
	assert.Equal(t, c.opts.UserHome, p.UserHome)
	assert.True(t, p.IgnoreDNS)
	assert.True(t, p.ServeOpts.IsEnabled)
	assert.Equal(t, cliconfigv1.Connection_Preferences_ServeOpts_USERSPACE, p.ServeOpts.ProxyMode)
	assert.Equal(t, runtime.GOOS != "windows", p.ESSH.IsEnabled)
	assert.Equal(t, "option-user", p.ESSH.User)
	assert.Equal(t, int32(2222), p.ESSH.Port)
	assert.Equal(t, []string{"127.0.0.1", "::1"}, p.ESSH.ListenIPAddresses)
	assert.True(t, p.ESOCKS5.IsEnabled)
	assert.Equal(t, int32(1081), p.ESOCKS5.Port)
	assert.Equal(t, []string{"127.0.0.2", "::2"}, p.ESOCKS5.ListenIPAddresses)
	assert.True(t, p.FullDNS)
	assert.True(t, p.LocalDNS.IsEnabled)
	assert.Equal(t, "[::1]:53", p.LocalDNS.ListenAddress)
	switch runtime.GOOS {
	case "linux":
		require.NotNil(t, p.LinuxPrefs)
		assert.Equal(t, cliutils.IsContainerRuntime(), p.RuntimeMode == cliconfigv1.Connection_Preferences_CONTAINER)
		assert.False(t, p.LinuxPrefs.EnforceImplementationMode)
		assert.Regexp(t, `^octelium-[a-z0-9]{6}$`, p.DeviceName)
	case "darwin":
		require.NotNil(t, p.MacosPrefs)
		assert.Equal(t, "utun", p.DeviceName)
	case "windows":
		require.NotNil(t, p.WindowsPrefs)
		assert.Equal(t, "octelium", p.DeviceName)
	}
}

func TestGetConnectionConfigEnvironmentBoundaries(t *testing.T) {
	clearTestConnectEnv(t)
	for _, tt := range []struct {
		value string
		mtu   int32
		ka    int32
	}{
		{"", 0, 30}, {"invalid", 0, 30}, {"-1", 0, 30}, {"0", 0, 30},
		{"1500", 1500, 1500}, {"1501", 0, 1501}, {"2147483648", 0, 30},
	} {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv("OCTELIUM_MTU", tt.value)
			t.Setenv("OCTELIUM_KEEPALIVE", tt.value)
			c, err := NewConnector("example.com", nil)
			require.NoError(t, err)
			cfg, _, err := c.getConnectionConfig(t.Context(), testStateStream(&userv1.ConnectionState{}), nil)
			require.NoError(t, err)
			assert.Equal(t, tt.mtu, cfg.Preferences.Mtu)
			assert.Equal(t, tt.ka, cfg.Preferences.KeepAliveSeconds)
			assert.Equal(t, cliconfigv1.Connection_Preferences_BOTH, cfg.Preferences.L3Mode)
			assert.False(t, cfg.Preferences.ServeOpts.IsEnabled)
		})
	}
}

func TestGetConnectionConfigDNSAndImplementationModes(t *testing.T) {
	clearTestConnectEnv(t)
	for _, tt := range []struct {
		addr string
		want string
	}{
		{"", ""}, {"127.0.0.1", "127.0.0.1:53"}, {"::1", "[::1]:53"},
		{"[::1]:1053", "[::1]:1053"}, {"127.0.0.1:1053", "127.0.0.1:1053"},
		{"invalid", ""},
	} {
		t.Run(tt.addr, func(t *testing.T) {
			c, err := NewConnector("example.com", &Opts{UseLocalDNS: true, LocalDNSListenAddr: tt.addr})
			require.NoError(t, err)
			cfg, _, err := c.getConnectionConfig(t.Context(), testStateStream(&userv1.ConnectionState{L3Mode: userv1.ConnectionState_V4}), nil)
			require.NoError(t, err)
			assert.True(t, cfg.Preferences.LocalDNS.IsEnabled)
			assert.Equal(t, tt.want, cfg.Preferences.LocalDNS.ListenAddress)
			assert.Equal(t, cliconfigv1.Connection_Preferences_V4, cfg.Preferences.L3Mode)
		})
	}
	if runtime.GOOS == "linux" {
		for _, tt := range []struct {
			mode string
			want cliconfigv1.Connection_Preferences_Linux_ImplementationMode
		}{
			{"kernel", cliconfigv1.Connection_Preferences_Linux_WG_KERNEL},
			{"tun", cliconfigv1.Connection_Preferences_Linux_WG_USERSPACE},
			{"gvisor", cliconfigv1.Connection_Preferences_Linux_WG_NETSTACK},
		} {
			c, err := NewConnector("example.com", &Opts{ImplementationMode: tt.mode})
			require.NoError(t, err)
			cfg, _, err := c.getConnectionConfig(t.Context(), testStateStream(&userv1.ConnectionState{}), nil)
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.Preferences.LinuxPrefs.ImplementationMode)
			assert.True(t, cfg.Preferences.LinuxPrefs.EnforceImplementationMode)
		}
	}
}

func TestConnectEnvironmentFeatureFlags(t *testing.T) {
	clearTestConnectEnv(t)
	for _, value := range []string{"true", "false", "TRUE", "1", ""} {
		t.Run(value, func(t *testing.T) {
			for _, key := range []string{"OCTELIUM_QUIC", "OCTELIUM_FULL_DNS", "OCTELIUM_ESSH", "OCTELIUM_ESOCKS5"} {
				t.Setenv(key, value)
			}
			t.Setenv("OCTELIUM_ESSH_USER", "environment-user")
			c, err := NewConnector("example.com", &Opts{L3Mode: "v4"})
			require.NoError(t, err)
			assert.Equal(t, value == "true", c.isQUICV0())
			assert.Equal(t, value == "true", c.isFullDNS())
			cfg, _, err := c.getConnectionConfig(t.Context(), testStateStream(&userv1.ConnectionState{}), nil)
			require.NoError(t, err)
			assert.Equal(t, value == "true" && runtime.GOOS != "windows", cfg.Preferences.ESSH.IsEnabled)
			assert.Equal(t, value == "true", cfg.Preferences.ESOCKS5.IsEnabled)
			assert.Equal(t, "environment-user", cfg.Preferences.ESSH.User)
			assert.Equal(t, value == "true", cfg.Preferences.FullDNS)
		})
	}
}

func TestPublishedServicesGRPCLookup(t *testing.T) {
	for _, typ := range []userv1.Service_Spec_Type{
		userv1.Service_Spec_TCP, userv1.Service_Spec_UDP, userv1.Service_Spec_DNS, userv1.Service_Spec_HTTP,
	} {
		t.Run(typ.String(), func(t *testing.T) {
			var calls []string
			cl := newTestConnectAPIClient(t, &testConnectAPI{
				getServiceFn: func(_ context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
					calls = append(calls, req.Name)
					return &userv1.Service{
						Metadata: &metav1.Metadata{Name: req.Name},
						Spec:     &userv1.Service_Spec{Port: 443, Type: typ},
						Status:   &userv1.Service_Status{Namespace: "default"},
					}, nil
				},
			})
			c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{
				{Name: "web", Address: "localhost", Port: 8443},
				{Name: "web", Address: "::1", Port: 9443},
			}})
			require.NoError(t, err)
			got, err := c.getPublishedServices(t.Context(), cl)
			require.NoError(t, err)
			assert.Equal(t, []string{"web.default", "web.default"}, calls)
			require.Len(t, got, 2)
			wantType := cliconfigv1.Connection_Preferences_PublishedService_TCP
			if typ == userv1.Service_Spec_UDP || typ == userv1.Service_Spec_DNS {
				wantType = cliconfigv1.Connection_Preferences_PublishedService_UDP
			}
			assert.Equal(t, &cliconfigv1.Connection_Preferences_PublishedService{
				Name: "web.default", Namespace: "default", Fqdn: "web.default.local.example.com",
				Port: 443, HostAddress: "localhost", HostPort: 8443, L4Type: wantType,
			}, got[0])
			assert.Equal(t, "::1", got[1].HostAddress)
			assert.Equal(t, int32(9443), got[1].HostPort)
		})
	}
}

func TestPublishedServicesFallbackAndErrors(t *testing.T) {
	for _, code := range allCodes {
		t.Run(code.String(), func(t *testing.T) {
			var listCalls atomic.Int32
			cl := newTestConnectAPIClient(t, &testConnectAPI{
				getServiceFn: func(context.Context, *metav1.GetOptions) (*userv1.Service, error) {
					return nil, status.Error(code, "lookup failed")
				},
				listFn: func(context.Context, *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
					listCalls.Add(1)
					return &userv1.ServiceList{Items: []*userv1.Service{{
						Metadata: &metav1.Metadata{Name: "web.default"},
						Spec:     &userv1.Service_Spec{Type: userv1.Service_Spec_TCP, Port: 80},
						Status:   &userv1.Service_Status{Namespace: "default"},
					}}}, nil
				},
			})
			c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{
				{Name: "web", Address: "127.0.0.1", Port: 8080},
			}})
			require.NoError(t, err)
			got, err := c.getPublishedServices(t.Context(), cl)
			if code == codes.Unimplemented {
				require.NoError(t, err)
				require.Len(t, got, 1)
				assert.Equal(t, "web.default", got[0].Name)
				assert.Equal(t, int32(1), listCalls.Load())
			} else if code == codes.NotFound {
				assert.NoError(t, err)
				assert.Empty(t, got)
				assert.Zero(t, listCalls.Load())
			} else {
				assert.Equal(t, code, status.Code(err))
				assert.Nil(t, got)
				assert.Zero(t, listCalls.Load())
			}
		})
	}
}

func TestPublishedServicesLegacyLookup(t *testing.T) {
	c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{{Name: "web", Port: 8080}}})
	require.NoError(t, err)
	cl := newTestConnectAPIClient(t, &testConnectAPI{
		listFn: func(context.Context, *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
			return nil, status.Error(codes.Unavailable, "restarting")
		},
	})
	_, err = c.getPublishedServicesWithList(t.Context(), cl)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = c.doGetPublishedServiceWithList(&userv1.ServiceList{}, c.opts.PublishServices[0])
	assert.ErrorContains(t, err, "web does not exist")
	c.opts.PublishServices = nil
	got, err := c.getPublishedServices(t.Context(), nil)
	assert.NoError(t, err)
	assert.Empty(t, got)
}

func TestConnectResponseTimestampOrdering(t *testing.T) {
	initialized := time.Now().UTC()
	c := &stateController{initAt: initialized}
	for _, tt := range []struct {
		name string
		resp *userv1.ConnectResponse
		want bool
	}{
		{"nil", nil, false}, {"missing", &userv1.ConnectResponse{}, false},
		{"invalid", &userv1.ConnectResponse{CreatedAt: &timestamppb.Timestamp{Nanos: -1}}, false},
		{"zero", &userv1.ConnectResponse{CreatedAt: timestamppb.New(time.Time{})}, false},
		{"older", &userv1.ConnectResponse{CreatedAt: timestamppb.New(initialized.Add(-time.Nanosecond))}, true},
		{"equal", &userv1.ConnectResponse{CreatedAt: timestamppb.New(initialized)}, false},
		{"newer", &userv1.ConnectResponse{CreatedAt: timestamppb.New(initialized.Add(time.Nanosecond))}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, c.shouldSkipConnectResponseMessage(tt.resp))
		})
	}
	c.initAt = time.Time{}
	assert.False(t, c.shouldSkipConnectResponseMessage(&userv1.ConnectResponse{CreatedAt: timestamppb.Now()}))
}

func TestStateLoopSkipsStaleDisconnectAndUnknownEvents(t *testing.T) {
	c := newTestStateController()
	c.initAt = time.Now()
	messages := []*userv1.ConnectResponse{
		nil, {},
		{CreatedAt: timestamppb.New(c.initAt.Add(-time.Second)), Event: &userv1.ConnectResponse_Disconnect_{}},
		{CreatedAt: timestamppb.New(c.initAt), Event: &userv1.ConnectResponse_Disconnect_{}},
	}
	var n int
	c.streamC = &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
		msg := messages[n]
		n++
		return msg, nil
	}}
	c.doStartLoop(t.Context())
	assert.Equal(t, len(messages), n)
	select {
	case <-c.apiserverDisconnectCh:
	default:
		t.Fatal("a current disconnect event must close the connection")
	}
	assert.Empty(t, c.getConnErrCh)
}

func TestStateLoopStreamErrorsAlwaysReconnect(t *testing.T) {
	for _, code := range allCodes {
		t.Run(code.String(), func(t *testing.T) {
			c := newTestStateController()
			c.streamC = &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
				return nil, status.Error(code, "stream interrupted")
			}}
			c.doStartLoop(t.Context())
			ret := c.waitDisconnected(t.Context(), nil)
			assert.Equal(t, code, status.Code(ret.err))
			assert.True(t, ret.isConnected)
			assert.True(t, ret.needsReconnect)
			assert.True(t, shouldReconnect(ret, true))
		})
	}
}

func TestStateServiceEventsWithoutProxy(t *testing.T) {
	for _, mode := range []cliconfigv1.Connection_Preferences_ServeOpts_ProxyMode{
		cliconfigv1.Connection_Preferences_ServeOpts_NONE,
		cliconfigv1.Connection_Preferences_ServeOpts_USERSPACE,
	} {
		c := newStateController(&cliconfigv1.Connection{
			Preferences: &cliconfigv1.Connection_Preferences{
				ServeOpts: &cliconfigv1.Connection_Preferences_ServeOpts{ProxyMode: mode},
			},
		}, nil, nil, nil)
		for _, msg := range []*userv1.ConnectResponse{
			{Event: &userv1.ConnectResponse_AddService_{AddService: &userv1.ConnectResponse_AddService{}}},
			{Event: &userv1.ConnectResponse_UpdateService_{UpdateService: &userv1.ConnectResponse_UpdateService{}}},
			{Event: &userv1.ConnectResponse_DeleteService_{DeleteService: &userv1.ConnectResponse_DeleteService{Name: "removed.default"}}},
			{},
		} {
			assert.NoError(t, c.handleState(t.Context(), msg))
		}
	}
}

func newTestRunningConnector(t *testing.T, srv *testConnectAPI) (*Connector, *db.DB) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the forced gVisor implementation is selected by Linux preferences")
	}
	clearTestConnectEnv(t)
	t.Setenv("OCTELIUM_DEV", "false")
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	dir, err := os.MkdirTemp("", "octelium-stream-")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "api.sock")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", socket)
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)
	dbC, err := db.Open("memory")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, dbC.Close()) })
	c, err := NewConnector("example.com", &Opts{
		L3Mode: "v4", IgnoreDNS: true, ImplementationMode: "gvisor",
		LocalDNSListenAddr: "127.0.0.1:0", UserHome: t.TempDir(),
	})
	require.NoError(t, err)
	return c, dbC
}

func testConnectInitialState() *userv1.ConnectResponse {
	return &userv1.ConnectResponse{
		CreatedAt: timestamppb.Now(),
		Event: &userv1.ConnectResponse_State{State: &userv1.ConnectionState{
			L3Mode: userv1.ConnectionState_V4, X25519Key: make([]byte, 32),
			Addresses: []*metav1.DualStackNetwork{{V4: "100.64.0.2/32"}},
			Cidr:      &metav1.DualStackNetwork{V4: "100.64.0.0/16"},
		}},
	}
}

func TestRunGRPCReconnectAfterEstablishedStreamErrors(t *testing.T) {
	for _, streamErr := range []error{io.EOF, status.Error(codes.Unavailable, "API restart"), status.Error(codes.NotFound, "service removed"), status.Error(codes.PermissionDenied, "policy updated")} {
		t.Run(streamErr.Error(), func(t *testing.T) {
			var attempts atomic.Int32
			connected := make(chan struct{}, 1)
			srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
				attempt := attempts.Add(1)
				req, err := stream.Recv()
				if err != nil {
					return err
				}
				if req.GetInitialize() == nil {
					return status.Error(codes.InvalidArgument, "missing initialize")
				}
				if attempt == 2 {
					return status.Error(codes.InvalidArgument, "temporary initialization error")
				}
				if err := stream.Send(testConnectInitialState()); err != nil {
					return err
				}
				if attempt == 1 {
					select {
					case <-connected:
					case <-stream.Context().Done():
						return stream.Context().Err()
					}
					if streamErr == io.EOF {
						return nil
					}
					return streamErr
				}
				<-stream.Context().Done()
				return stream.Context().Err()
			}}
			c, dbC := newTestRunningConnector(t, srv)
			ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 20*time.Second)
			defer cancel()
			var events []*Event
			var successes int
			c.opts.OnEvent = func(ev *Event) {
				events = append(events, ev)
				if ev.Type == EventTypeConnected {
					successes++
					if successes == 1 {
						connected <- struct{}{}
					} else {
						cancel()
					}
				}
			}
			require.NoError(t, c.Run(ctx))
			assert.Equal(t, int32(3), attempts.Load())
			assert.Equal(t, 2, successes)
			var reconnects int
			for _, ev := range events {
				if ev.Type == EventTypeReconnecting {
					reconnects++
				}
			}
			assert.Equal(t, 2, reconnects)
			assert.Equal(t, EventTypeDisconnected, events[len(events)-1].Type)
			_, err := dbC.GetConnectionCleanup("example.com")
			assert.True(t, dbC.ErrorIsNotFound(err))
		})
	}
}

func TestRunGRPCExplicitDisconnectAndCancellation(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "server-disconnect"}[disconnect], func(t *testing.T) {
			connected := make(chan struct{})
			var attempts atomic.Int32
			c, dbC := newTestRunningConnector(t, &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
				attempts.Add(1)
				if _, err := stream.Recv(); err != nil {
					return err
				}
				if err := stream.Send(testConnectInitialState()); err != nil {
					return err
				}
				if disconnect {
					select {
					case <-connected:
					case <-stream.Context().Done():
						return stream.Context().Err()
					}
					if err := stream.Send(&userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}}}); err != nil {
						return err
					}
				}
				<-stream.Context().Done()
				return nil
			}})
			ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 5*time.Second)
			defer cancel()
			var types []EventType
			c.opts.OnEvent = func(ev *Event) {
				types = append(types, ev.Type)
				if ev.Type == EventTypeConnected {
					close(connected)
					if !disconnect {
						cancel()
					}
				}
			}
			require.NoError(t, c.Run(ctx))
			assert.Equal(t, int32(1), attempts.Load())
			assert.Equal(t, []EventType{EventTypeConnecting, EventTypeConnected, EventTypeDisconnected}, types)
		})
	}
}

func TestRunCancellationInterruptsReconnectBackoff(t *testing.T) {
	_, c, _ := runFakeConnect(t, status.Error(codes.Unavailable, "restarting"))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	c.opts.OnEvent = func(ev *Event) {
		if ev.Type == EventTypeConnecting && ev.Err != nil {
			cancel()
		}
	}
	started := time.Now()
	assert.NoError(t, c.Run(ctx))
	assert.Less(t, time.Since(started), reconnectBackoffMin)
}

func TestGetConnectionConfigReturnsInitializationError(t *testing.T) {
	c, err := NewConnector("example.com", nil)
	require.NoError(t, err)
	cfg, at, err := c.getConnectionConfig(t.Context(), &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
		return nil, status.Error(codes.Unauthenticated, "refresh needed")
	}}, nil)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Nil(t, cfg)
	assert.Nil(t, at)
}

func newTestConnectCtl(t *testing.T) (*ctl, *db.DB, context.Context) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the forced gVisor implementation is selected by Linux preferences")
	}
	clearTestConnectEnv(t)
	c, err := NewConnector("example.com", &Opts{
		IgnoreDNS: true, ImplementationMode: "gvisor", UserHome: t.TempDir(),
		LocalDNSListenAddr: "127.0.0.1:0",
	})
	require.NoError(t, err)
	cfg, at, err := c.getConnectionConfig(t.Context(), testStateStream(testConnectInitialState().GetState()), nil)
	require.NoError(t, err)
	dbC, err := db.Open("memory")
	require.NoError(t, err)
	t.Cleanup(func() { dbC.Close() })
	ctx, cancel := context.WithCancel(cliutils.WithDB(t.Context(), dbC))
	stream := &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	ret, err := newCtl(ctx, stream, cfg, at)
	require.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, ret.close())
	})
	return ret, dbC, ctx
}

func TestCtlCloseConcurrentAndIdempotent(t *testing.T) {
	c, dbC, ctx := newTestConnectCtl(t)
	require.NoError(t, c.start(ctx))
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, c.close())
		}()
	}
	wg.Wait()
	assert.ErrorContains(t, c.devCtl.Start(ctx), "already closed")
	_, err := dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
}

func TestNewCtlRejectsInvalidInitialKey(t *testing.T) {
	clearTestConnectEnv(t)
	c, err := NewConnector("example.com", nil)
	require.NoError(t, err)
	for _, n := range []int{0, 1, 31, 33, 64} {
		cfg, at, err := c.getConnectionConfig(t.Context(), testStateStream(&userv1.ConnectionState{X25519Key: make([]byte, n)}), nil)
		require.NoError(t, err)
		got, err := newCtl(t.Context(), nil, cfg, at)
		assert.Error(t, err)
		assert.Nil(t, got)
	}
}

func TestStateControllerAppliesNetworkUpdates(t *testing.T) {
	c, _, ctx := newTestConnectCtl(t)
	require.NoError(t, c.devCtl.Start(ctx))
	state := c.stateController
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	gw := &userv1.Gateway{
		Id: "gw-test", Addresses: []string{"192.0.2.1"}, CIDRs: []string{"100.64.0.0/16"},
		Wireguard: &userv1.Gateway_WireGuard{Port: 51820, PublicKey: key.PublicKey().String()},
	}
	require.NoError(t, state.handleState(ctx, &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddGateway_{
		AddGateway: &userv1.ConnectResponse_AddGateway{Gateway: gw},
	}}))
	updated := proto.Clone(gw).(*userv1.Gateway)
	updated.Addresses = []string{"192.0.2.2"}
	require.NoError(t, state.handleState(ctx, &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateGateway_{
		UpdateGateway: &userv1.ConnectResponse_UpdateGateway{Gateway: updated},
	}}))
	require.NoError(t, state.handleState(ctx, &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateDNS_{
		UpdateDNS: &userv1.ConnectResponse_UpdateDNS{Dns: &userv1.DNS{Servers: []string{"100.64.0.54"}}},
	}}))
	assert.Equal(t, []string{"100.64.0.54"}, c.devCtl.GetClusterDNSServers())
	require.NoError(t, state.handleState(ctx, &userv1.ConnectResponse{Event: &userv1.ConnectResponse_DeleteGateway_{
		DeleteGateway: &userv1.ConnectResponse_DeleteGateway{Id: gw.Id},
	}}))
	assert.Empty(t, state.c.Connection.Gateways)
	for _, msg := range []*userv1.ConnectResponse{
		{Event: &userv1.ConnectResponse_AddGateway_{AddGateway: &userv1.ConnectResponse_AddGateway{}}},
		{Event: &userv1.ConnectResponse_UpdateGateway_{UpdateGateway: &userv1.ConnectResponse_UpdateGateway{Gateway: gw}}},
	} {
		assert.Error(t, state.handleState(ctx, msg))
	}
	replacement := proto.Clone(testConnectInitialState().GetState()).(*userv1.ConnectionState)
	replacement.Addresses[0].V4 = "100.64.0.3/32"
	require.NoError(t, state.handleState(ctx, &userv1.ConnectResponse{Event: &userv1.ConnectResponse_State{State: replacement}}))
}

func TestConnectKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to run unresolved regressions listed in tmp/client-test-report.md")
	}
	t.Run("CL-001-published-service-not-found", func(t *testing.T) {
		cl := newTestConnectAPIClient(t, &testConnectAPI{getServiceFn: func(context.Context, *metav1.GetOptions) (*userv1.Service, error) {
			return nil, status.Error(codes.NotFound, "published Service is temporarily absent")
		}})
		c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{{Name: "web", Port: 8080}}})
		require.NoError(t, err)
		published, err := c.getPublishedServices(t.Context(), cl)
		assert.NoError(t, err)
		assert.Empty(t, published)
	})
	t.Run("CL-002-empty-service-response", func(t *testing.T) {
		c, err := NewConnector("example.com", nil)
		require.NoError(t, err)
		assert.NotPanics(t, func() {
			c.getPublishedServiceFromService(&userv1.Service{}, &PublishedService{Name: "web", Port: 8080})
		})
	})
	t.Run("CL-003-failed-state-update-needs-recovery", func(t *testing.T) {
		c, _, parent := newTestConnectCtl(t)
		ctx, cancel := context.WithCancel(parent)
		defer cancel()
		require.NoError(t, c.devCtl.Start(ctx))
		bad := proto.Clone(testConnectInitialState().GetState()).(*userv1.ConnectionState)
		bad.Addresses[0].V4 = "invalid"
		processed, done := make(chan struct{}), make(chan struct{})
		var received bool
		c.stateController.streamC = &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
			if !received {
				received = true
				return &userv1.ConnectResponse{Event: &userv1.ConnectResponse_State{State: bad}}, nil
			}
			close(processed)
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		go func() {
			c.stateController.doStartLoop(ctx)
			close(done)
		}()
		select {
		case <-processed:
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("the state update was not processed")
		}
		assert.NotEmpty(t, c.stateController.getConnErrCh, "a failed full-state update must trigger recovery")
		cancel()
		<-done
	})
	t.Run("CL-004-canceled-initialization-cause", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, _, err := getStateMsg(ctx, &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
			return nil, context.Canceled
		}})
		assert.ErrorIs(t, err, context.Canceled)
	})
	t.Run("CL-005-invalid-embedded-listener-ports", func(t *testing.T) {
		clearTestConnectEnv(t)
		t.Setenv("OCTELIUM_ESSH_PORT", "-1")
		t.Setenv("OCTELIUM_ESOCKS5_PORT", "65536")
		c, err := NewConnector("example.com", &Opts{L3Mode: "v4", UseESSH: true, UseESOCKS5: true})
		require.NoError(t, err)
		assert.Error(t, c.sendInitializeRequest(&testConnectStream{sendFn: func(req *userv1.ConnectRequest) error {
			assert.Greater(t, req.GetInitialize().ESSHPort, int32(0))
			assert.LessOrEqual(t, req.GetInitialize().ESOCKS5Port, int32(65535))
			return nil
		}}, nil))
	})
	t.Run("CL-006-invalid-explicit-IP-mode", func(t *testing.T) {
		c, err := NewConnector("example.com", &Opts{L3Mode: "ipv5"})
		require.NoError(t, err)
		assert.Error(t, c.sendInitializeRequest(&testConnectStream{sendFn: func(*userv1.ConnectRequest) error { return nil }}, nil))
	})
}

func newTestClosedStateController(t *testing.T) *stateController {
	t.Helper()
	cfg := &cliconfigv1.Connection{
		Connection: &userv1.ConnectionState{L3Mode: userv1.ConnectionState_V4, X25519Key: make([]byte, 32)},
		Info:       &cliconfigv1.Connection_Info{Cluster: &cliconfigv1.Connection_Info_Cluster{Domain: "example.com"}},
		Preferences: &cliconfigv1.Connection_Preferences{
			DeviceName: "invalid/state-test", IgnoreDNS: true, UserHome: t.TempDir(),
			LinuxPrefs:   &cliconfigv1.Connection_Preferences_Linux{},
			MacosPrefs:   &cliconfigv1.Connection_Preferences_MacOS{},
			WindowsPrefs: &cliconfigv1.Connection_Preferences_Windows{},
			ServeOpts: &cliconfigv1.Connection_Preferences_ServeOpts{
				IsEnabled: true, ProxyMode: cliconfigv1.Connection_Preferences_ServeOpts_USERSPACE,
			},
		},
	}
	dev, err := controller.NewController(cfg)
	require.NoError(t, err)
	_ = dev.Close()
	require.ErrorContains(t, dev.Reconfigure(), "already closed")
	svcProxy, err := proxy.NewController(t.Context(), cfg, nil)
	require.NoError(t, err)
	require.NoError(t, svcProxy.Close())
	return newStateController(cfg, dev, svcProxy, nil)
}

func TestStateLoopApplicationErrorsRequestReconnect(t *testing.T) {
	for _, tt := range []struct {
		name string
		msg  *userv1.ConnectResponse
	}{
		{"state", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_State{State: &userv1.ConnectionState{}}}},
		{"add-gateway", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddGateway_{
			AddGateway: &userv1.ConnectResponse_AddGateway{Gateway: &userv1.Gateway{Id: "gw"}},
		}}},
		{"update-gateway", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateGateway_{
			UpdateGateway: &userv1.ConnectResponse_UpdateGateway{Gateway: &userv1.Gateway{Id: "gw"}},
		}}},
		{"delete-gateway", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_DeleteGateway_{
			DeleteGateway: &userv1.ConnectResponse_DeleteGateway{Id: "gw"},
		}}},
		{"dns", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateDNS_{
			UpdateDNS: &userv1.ConnectResponse_UpdateDNS{Dns: &userv1.DNS{Servers: []string{"100.64.0.53"}}},
		}}},
		{"add-service", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddService_{
			AddService: &userv1.ConnectResponse_AddService{Service: &userv1.HostedService{Name: "web.default"}},
		}}},
		{"update-service", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateService_{
			UpdateService: &userv1.ConnectResponse_UpdateService{Service: &userv1.HostedService{Name: "web.default"}},
		}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClosedStateController(t)
			var reads int
			c.streamC = &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
				reads++
				if reads == 1 {
					return tt.msg, nil
				}
				return nil, io.EOF
			}}
			c.doStartLoop(t.Context())
			assert.Equal(t, 1, reads, "no further events may be applied after a failed update")
			require.Len(t, c.getConnErrCh, 1)
			ret := c.waitDisconnected(t.Context(), nil)
			assert.ErrorContains(t, ret.err, "Could not apply connection state")
			assert.ErrorContains(t, ret.err, "already closed")
			assert.NotContains(t, ret.err.Error(), "Abruptly disconnected by API Server")
			assert.NotErrorIs(t, ret.err, io.EOF)
			assert.True(t, ret.needsReconnect)
			assert.True(t, ret.isConnected)
			assert.False(t, ret.isResumed)
			assert.True(t, shouldReconnect(ret, true))
			assert.Empty(t, c.getConnErrCh)
			select {
			case <-c.apiserverDisconnectCh:
				t.Fatal("an application failure must not become an explicit server disconnect")
			default:
			}
		})
	}
}

func TestStateLoopReceiveErrorsPreserveCauseAndContext(t *testing.T) {
	for _, want := range []error{io.EOF, context.Canceled, status.Error(codes.Unavailable, "API restart")} {
		t.Run(want.Error(), func(t *testing.T) {
			c := newTestStateController()
			c.streamC = &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) { return nil, want }}
			c.doStartLoop(t.Context())
			ret := c.waitDisconnected(t.Context(), nil)
			assert.ErrorIs(t, ret.err, want)
			assert.ErrorContains(t, ret.err, "Abruptly disconnected by API Server")
			assert.NotContains(t, ret.err.Error(), "Could not apply connection state")
			assert.Equal(t, status.Code(want), status.Code(ret.err))
			assert.True(t, ret.needsReconnect)
		})
	}
}

func testUnknownConnectResponse(t *testing.T) *userv1.ConnectResponse {
	t.Helper()
	msg := &userv1.ConnectResponse{}
	wire := protowire.AppendBytes(protowire.AppendTag(nil, 1000, protowire.BytesType), nil)
	require.NoError(t, proto.Unmarshal(wire, msg))
	require.Nil(t, msg.Event)
	require.NotEmpty(t, msg.ProtoReflect().GetUnknown())
	return msg
}

func TestStateLoopLegacyOptionalMessagesDoNotReconnect(t *testing.T) {
	for _, mode := range []cliconfigv1.Connection_Preferences_ServeOpts_ProxyMode{
		cliconfigv1.Connection_Preferences_ServeOpts_NONE,
		cliconfigv1.Connection_Preferences_ServeOpts_USERSPACE,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			cfg := &cliconfigv1.Connection{
				Connection: &userv1.ConnectionState{L3Mode: userv1.ConnectionState_V4},
				Preferences: &cliconfigv1.Connection_Preferences{
					L3Mode:    cliconfigv1.Connection_Preferences_V4,
					ServeOpts: &cliconfigv1.Connection_Preferences_ServeOpts{ProxyMode: mode},
				},
			}
			svcProxy, err := proxy.NewController(t.Context(), cfg, nil)
			require.NoError(t, err)
			require.NoError(t, svcProxy.Start(t.Context()))
			t.Cleanup(func() { assert.NoError(t, svcProxy.Close()) })
			c := newStateController(cfg, &controller.Controller{}, svcProxy, nil)
			c.initAt = time.Now()
			messages := []*userv1.ConnectResponse{
				nil, {}, testUnknownConnectResponse(t),
				{Event: &userv1.ConnectResponse_UpdateDNS_{UpdateDNS: &userv1.ConnectResponse_UpdateDNS{}}},
				{Event: &userv1.ConnectResponse_AddService_{AddService: &userv1.ConnectResponse_AddService{
					Service: &userv1.HostedService{Name: "legacy.default"},
				}}},
				{Event: &userv1.ConnectResponse_UpdateService_{UpdateService: &userv1.ConnectResponse_UpdateService{
					Service: &userv1.HostedService{Name: "legacy.default", Upstream: &userv1.HostedService_Upstream{}},
				}}},
				{Event: &userv1.ConnectResponse_DeleteService_{DeleteService: &userv1.ConnectResponse_DeleteService{Name: "absent.default"}}},
				{CreatedAt: timestamppb.New(c.initAt.Add(-time.Second)), Event: &userv1.ConnectResponse_State{}},
				{Event: &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}}},
			}
			var reads int
			c.streamC = &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
				if reads >= len(messages) {
					return nil, io.EOF
				}
				msg := messages[reads]
				reads++
				return msg, nil
			}}
			c.doStartLoop(t.Context())
			assert.Equal(t, len(messages), reads)
			assert.Empty(t, c.getConnErrCh)
			ret := c.waitDisconnected(t.Context(), nil)
			assert.NoError(t, ret.err)
			assert.False(t, ret.needsReconnect)
			assert.True(t, ret.isConnected)
		})
	}
}

func TestStateLoopCanceledBeforeReceivingDoesNotReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := newTestStateController()
	c.streamC = &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
		t.Fatal("the state loop must not receive after cancellation")
		return nil, io.EOF
	}}
	c.doStartLoop(ctx)
	assert.Empty(t, c.getConnErrCh)
	ret := c.waitDisconnected(ctx, nil)
	assert.NoError(t, ret.err)
	assert.False(t, ret.needsReconnect)
}

func testInvalidStateUpdate() *userv1.ConnectResponse {
	msg := testConnectInitialState()
	msg.GetState().Addresses[0].V4 = "invalid"
	return msg
}

func testPublishedPortIsListening(addr string) bool {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return errors.Is(err, syscall.EADDRINUSE)
	}
	lis.Close()
	return false
}

func TestRunGRPCStateUpdateFailureRecoversWithFreshState(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "current"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			for _, tt := range []struct {
				name string
				msg  func() *userv1.ConnectResponse
			}{
				{"state", testInvalidStateUpdate},
				{"add-gateway", func() *userv1.ConnectResponse {
					return &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddGateway_{
						AddGateway: &userv1.ConnectResponse_AddGateway{Gateway: &userv1.Gateway{
							Id: "invalid-key", Addresses: []string{"192.0.2.1"},
							Wireguard: &userv1.Gateway_WireGuard{Port: 51820, PublicKey: "invalid"},
						}},
					}}
				}},
				{"update-gateway", func() *userv1.ConnectResponse {
					return &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateGateway_{
						UpdateGateway: &userv1.ConnectResponse_UpdateGateway{Gateway: &userv1.Gateway{Id: "missing"}},
					}}
				}},
			} {
				t.Run(tt.name, func(t *testing.T) {
					var attempts, getCalls, listCalls atomic.Int32
					firstConnected, recovered, firstClosed := make(chan struct{}), make(chan struct{}), make(chan struct{})
					initializations := make(chan *userv1.ConnectRequest, 2)
					unknown := testUnknownConnectResponse(t)
					newService := func() *userv1.Service {
						return &userv1.Service{
							Metadata: &metav1.Metadata{Name: "web.default"},
							Spec:     &userv1.Service_Spec{Type: userv1.Service_Spec_TCP, Port: 80},
							Status:   &userv1.Service_Status{Namespace: "default"},
						}
					}
					srv := &testConnectAPI{
						getServiceFn: func(_ context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
							getCalls.Add(1)
							if legacy {
								return nil, status.Error(codes.Unimplemented, "legacy API")
							}
							if req.Name != "web.default" {
								return nil, status.Error(codes.InvalidArgument, "unexpected service name")
							}
							return newService(), nil
						},
						listFn: func(context.Context, *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
							listCalls.Add(1)
							return &userv1.ServiceList{Items: []*userv1.Service{newService()}}, nil
						},
						connectFn: func(stream userv1.MainService_ConnectServer) error {
							attempt := attempts.Add(1)
							if attempt > 2 {
								return status.Error(codes.Internal, "unexpected extra connection")
							}
							req, err := stream.Recv()
							if err != nil {
								return err
							}
							initializations <- req
							send := func(msg *userv1.ConnectResponse) error {
								if legacy {
									msg.CreatedAt = nil
								} else {
									msg.CreatedAt = timestamppb.Now()
								}
								return stream.Send(msg)
							}
							state := testConnectInitialState()
							if attempt == 2 {
								select {
								case <-firstClosed:
								case <-stream.Context().Done():
									return stream.Context().Err()
								}
								state.GetState().Addresses[0].V4 = "100.64.0.3/32"
							}
							if err := send(state); err != nil {
								return err
							}
							if attempt == 1 {
								defer close(firstClosed)
								select {
								case <-firstConnected:
								case <-stream.Context().Done():
									return stream.Context().Err()
								}
								if err := send(proto.Clone(unknown).(*userv1.ConnectResponse)); err != nil {
									return err
								}
								update := testConnectInitialState()
								update.GetState().Addresses[0].V4 = "100.64.0.4/32"
								if err := send(update); err != nil {
									return err
								}
								if err := send(tt.msg()); err != nil {
									return err
								}
							} else {
								select {
								case <-recovered:
								case <-stream.Context().Done():
									return stream.Context().Err()
								}
								if err := send(&userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{
									Disconnect: &userv1.ConnectResponse_Disconnect{},
								}}); err != nil {
									return err
								}
							}
							<-stream.Context().Done()
							return nil
						},
					}
					c, dbC := newTestRunningConnector(t, srv)
					reserved, err := net.Listen("tcp", "127.0.0.1:0")
					require.NoError(t, err)
					addr := reserved.Addr().String()
					port := reserved.Addr().(*net.TCPAddr).Port
					require.NoError(t, reserved.Close())
					c.opts.PublishServices = []*PublishedService{{Name: "web", Address: "127.0.0.1", Port: port}}
					ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 15*time.Second)
					defer cancel()
					var events []EventType
					var successes int
					c.opts.OnEvent = func(ev *Event) {
						events = append(events, ev.Type)
						switch ev.Type {
						case EventTypeConnected:
							successes++
							assert.Eventually(t, func() bool {
								return testPublishedPortIsListening(addr)
							}, 2*time.Second, 10*time.Millisecond)
							if successes == 1 {
								close(firstConnected)
							} else if successes == 2 {
								assert.Equal(t, "100.64.0.3/32", ev.Connection.Connection.Addresses[0].V4)
								assert.Empty(t, ev.Connection.Connection.Gateways)
								close(recovered)
							}
						case EventTypeReconnecting:
							assert.ErrorContains(t, ev.Err, "Could not apply connection state")
							_, err := dbC.GetConnectionCleanup("example.com")
							assert.True(t, dbC.ErrorIsNotFound(err), "the old controller must finish cleanup before retrying")
							lis, err := net.Listen("tcp", addr)
							if assert.NoError(t, err, "the old published listener must be released before reconnecting") {
								assert.NoError(t, lis.Close())
							}
						}
					}
					require.NoError(t, c.Run(ctx))
					assert.NoError(t, ctx.Err(), "recovery must finish before the test deadline")
					assert.Equal(t, []EventType{EventTypeConnecting, EventTypeConnected, EventTypeReconnecting, EventTypeConnected, EventTypeDisconnected}, events)
					assert.Equal(t, int32(2), attempts.Load())
					assert.Equal(t, 2, successes)
					assert.Equal(t, int32(2), getCalls.Load())
					if legacy {
						assert.Equal(t, int32(2), listCalls.Load())
					} else {
						assert.Zero(t, listCalls.Load())
					}
					require.Len(t, initializations, 2)
					first, second := <-initializations, <-initializations
					assert.True(t, proto.Equal(first, second), "recovery must use the same initialization protocol and options")
					require.NotNil(t, first.GetInitialize())
					assert.Equal(t, userv1.ConnectRequest_Initialize_V4, first.GetInitialize().L3Mode)
					require.Len(t, first.GetInitialize().PublishedServices, 1)
					assert.Equal(t, "web.default", first.GetInitialize().PublishedServices[0].Name)
					_, err = dbC.GetConnectionCleanup("example.com")
					assert.True(t, dbC.ErrorIsNotFound(err))
				})
			}
		})
	}
}

func TestRunGRPCStateUpdateFailureHonorsCancellation(t *testing.T) {
	var attempts atomic.Int32
	ready := make(chan struct{})
	c, dbC := newTestRunningConnector(t, &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(testConnectInitialState()); err != nil {
			return err
		}
		select {
		case <-ready:
		case <-stream.Context().Done():
			return nil
		}
		if err := stream.Send(testInvalidStateUpdate()); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}})
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 5*time.Second)
	defer cancel()
	var events []EventType
	c.opts.OnEvent = func(ev *Event) {
		events = append(events, ev.Type)
		if ev.Type == EventTypeConnected {
			close(ready)
		}
		if ev.Type == EventTypeReconnecting {
			cancel()
		}
	}
	require.NoError(t, c.Run(ctx))
	assert.Equal(t, int32(1), attempts.Load())
	assert.Equal(t, []EventType{EventTypeConnecting, EventTypeConnected, EventTypeReconnecting, EventTypeDisconnected}, events)
	_, err := dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
}

func TestRunGRPCStateUpdateFailureStopsIfCleanupFails(t *testing.T) {
	var attempts atomic.Int32
	ready := make(chan struct{})
	c, dbC := newTestRunningConnector(t, &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(testConnectInitialState()); err != nil {
			return err
		}
		select {
		case <-ready:
		case <-stream.Context().Done():
			return nil
		}
		if err := stream.Send(testInvalidStateUpdate()); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}})
	require.NoError(t, os.MkdirAll(filepath.Join(c.opts.UserHome, ".ssh", "known_hosts"), 0700))
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 5*time.Second)
	defer cancel()
	var events []EventType
	c.opts.OnEvent = func(ev *Event) {
		events = append(events, ev.Type)
		if ev.Type == EventTypeConnected {
			close(ready)
		}
	}
	err := c.Run(ctx)
	assert.ErrorContains(t, err, "Could not apply connection state")
	assert.Equal(t, int32(1), attempts.Load())
	assert.Equal(t, []EventType{EventTypeConnecting, EventTypeConnected, EventTypeDisconnected}, events)
	journal, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, journal.Phase)
}

func TestRunGRPCRepeatedStateUpdateFailuresKeepRetryingWithBackoff(t *testing.T) {
	var attempts atomic.Int32
	ready := make(chan struct{}, 1)
	started := make(chan time.Time, 4)
	c, dbC := newTestRunningConnector(t, &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := attempts.Add(1)
		if attempt > 4 {
			return status.Error(codes.Internal, "unexpected extra connection")
		}
		started <- time.Now()
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(testConnectInitialState()); err != nil {
			return err
		}
		select {
		case <-ready:
		case <-stream.Context().Done():
			return nil
		}
		msg := testInvalidStateUpdate()
		if attempt == 4 {
			msg = &userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{
				Disconnect: &userv1.ConnectResponse_Disconnect{},
			}}
		}
		if err := stream.Send(msg); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}})
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 20*time.Second)
	defer cancel()
	var connected, reconnecting int
	c.opts.OnEvent = func(ev *Event) {
		if ev.Type == EventTypeConnected {
			connected++
			ready <- struct{}{}
		}
		if ev.Type == EventTypeReconnecting {
			reconnecting++
			assert.ErrorContains(t, ev.Err, "Could not apply connection state")
			_, err := dbC.GetConnectionCleanup("example.com")
			assert.True(t, dbC.ErrorIsNotFound(err))
		}
	}
	require.NoError(t, c.Run(ctx))
	assert.NoError(t, ctx.Err())
	assert.Equal(t, int32(4), attempts.Load())
	assert.Equal(t, 4, connected)
	assert.Equal(t, 3, reconnecting)
	require.Len(t, started, 4)
	previous := <-started
	for range 3 {
		current := <-started
		assert.GreaterOrEqual(t, current.Sub(previous), reconnectBackoffMin)
		previous = current
	}
}

type testPublishedServiceClient struct {
	userv1.MainServiceClient
	getFn  func(context.Context, *metav1.GetOptions) (*userv1.Service, error)
	listFn func(context.Context, *userv1.ListServiceOptions) (*userv1.ServiceList, error)
}

func (c *testPublishedServiceClient) GetService(ctx context.Context, req *metav1.GetOptions, _ ...grpc.CallOption) (*userv1.Service, error) {
	if c.getFn == nil {
		return nil, status.Error(codes.Unimplemented, "legacy API")
	}
	return c.getFn(ctx, req)
}

func (c *testPublishedServiceClient) ListService(ctx context.Context, req *userv1.ListServiceOptions, _ ...grpc.CallOption) (*userv1.ServiceList, error) {
	return c.listFn(ctx, req)
}

func testPublishedAPIService(name string, typ userv1.Service_Spec_Type, port uint32) *userv1.Service {
	name = cliutils.GetServiceFullNameFromName(name)
	_, namespace, _ := strings.Cut(name, ".")
	return &userv1.Service{
		Metadata: &metav1.Metadata{Name: name},
		Spec:     &userv1.Service_Spec{Type: typ, Port: port},
		Status:   &userv1.Service_Status{Namespace: namespace},
	}
}

func TestPublishedServicesMissingDoNotDiscardHealthyMappings(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "legacy"}[legacy], func(t *testing.T) {
			requested := []*PublishedService{
				{Name: "missing", Address: "localhost", Port: 8081},
				{Name: "web", Address: "127.0.0.1", Port: 8080},
				{Name: "dns.ns1", Address: "::1", Port: 1053},
				{Name: "also-missing.ns1", Address: "localhost", Port: 8082},
				{Name: "web.default", Address: "::1", Port: 9090},
			}
			before := make([]PublishedService, len(requested))
			for i, svc := range requested {
				before[i] = *svc
			}
			var getCalls, listCalls int
			cl := &testPublishedServiceClient{
				getFn: func(_ context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
					getCalls++
					if legacy {
						return nil, status.Error(codes.Unimplemented, "legacy API")
					}
					switch req.Name {
					case "web.default":
						return testPublishedAPIService("web", userv1.Service_Spec_HTTP, 80), nil
					case "dns.ns1":
						return testPublishedAPIService("dns.ns1", userv1.Service_Spec_DNS, 53), nil
					default:
						return nil, status.Error(codes.NotFound, "missing")
					}
				},
				listFn: func(context.Context, *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
					listCalls++
					return &userv1.ServiceList{Items: []*userv1.Service{
						testPublishedAPIService("web", userv1.Service_Spec_HTTP, 80),
						testPublishedAPIService("dns.ns1", userv1.Service_Spec_DNS, 53),
					}}, nil
				},
			}
			c, err := NewConnector("example.com", &Opts{PublishServices: requested})
			require.NoError(t, err)
			got, err := c.getPublishedServices(t.Context(), cl)
			require.NoError(t, err)
			require.Len(t, got, 3)
			assert.Equal(t, []string{"web.default", "dns.ns1", "web.default"}, []string{got[0].Name, got[1].Name, got[2].Name})
			assert.Equal(t, int32(8080), got[0].HostPort)
			assert.Equal(t, int32(9090), got[2].HostPort)
			assert.Equal(t, cliconfigv1.Connection_Preferences_PublishedService_UDP, got[1].L4Type)
			assert.Equal(t, []*PublishedService{requested[0], requested[3]}, c.getPendingPublishedServices(got))
			for i, svc := range requested {
				assert.Equal(t, before[i], *svc)
			}
			if legacy {
				assert.Equal(t, 1, getCalls)
				assert.Equal(t, 1, listCalls)
			} else {
				assert.Equal(t, len(requested), getCalls)
				assert.Zero(t, listCalls)
			}
		})
	}
}

func TestPublishedServicesListRPCErrorsAreNotMissingMappings(t *testing.T) {
	for _, code := range allCodes {
		t.Run(code.String(), func(t *testing.T) {
			cl := &testPublishedServiceClient{listFn: func(context.Context, *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
				return nil, status.Error(code, "list failed")
			}}
			c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{{Name: "web", Port: 8080}}})
			require.NoError(t, err)
			got, err := c.getPublishedServices(t.Context(), cl)
			assert.Nil(t, got)
			assert.Equal(t, code, status.Code(err))
		})
	}
}

func TestPublishedServicesLegacyPaginationFindsLaterServices(t *testing.T) {
	var pages []uint32
	cl := &testPublishedServiceClient{listFn: func(_ context.Context, req *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
		page := req.GetCommon().GetPage()
		pages = append(pages, page)
		var items []*userv1.Service
		switch page {
		case 0:
			items = []*userv1.Service{nil, {}, testPublishedAPIService("other", userv1.Service_Spec_TCP, 80)}
		case 1:
			items = []*userv1.Service{testPublishedAPIService("dns.ns1", userv1.Service_Spec_UDP, 5353)}
		case 2:
			items = []*userv1.Service{testPublishedAPIService("late.ns1", userv1.Service_Spec_TCP, 8443)}
		default:
			t.Fatal("lookup must stop after finding all requested services")
		}
		return &userv1.ServiceList{Items: items, ListResponseMeta: &metav1.ListResponseMeta{Page: page, HasMore: true}}, nil
	}}
	c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{
		{Name: "late.ns1", Port: 8080}, {Name: "dns.ns1", Port: 1053},
	}})
	require.NoError(t, err)
	got, err := c.getPublishedServices(t.Context(), cl)
	require.NoError(t, err)
	assert.Equal(t, []uint32{0, 1, 2}, pages)
	require.Len(t, got, 2)
	assert.Equal(t, "late.ns1", got[0].Name)
	assert.Equal(t, "dns.ns1", got[1].Name)
}

func TestPublishedServicesLegacyRepeatedPageReturnsError(t *testing.T) {
	var calls int
	cl := &testPublishedServiceClient{listFn: func(context.Context, *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
		calls++
		return &userv1.ServiceList{
			Items:            []*userv1.Service{testPublishedAPIService("other", userv1.Service_Spec_TCP, 80)},
			ListResponseMeta: &metav1.ListResponseMeta{HasMore: true},
		}, nil
	}}
	c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{{Name: "missing", Port: 8080}}})
	require.NoError(t, err)
	_, err = c.getPublishedServices(t.Context(), cl)
	assert.ErrorContains(t, err, "same Service list page")
	assert.Equal(t, 2, calls)
	assert.False(t, isRejectedErr(err))
}

func TestPublishedServicesInvalidOptionsDoNotReachAPI(t *testing.T) {
	for _, svc := range []*PublishedService{
		nil, {Name: "web", Port: 0}, {Name: "web", Port: -1}, {Name: "web", Port: 65536},
		{Name: "", Port: 8080}, {Name: "web..ns1", Port: 8080}, {Name: ".ns1", Port: 8080},
		{Name: "web", Address: "not an IP", Port: 8080},
	} {
		c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{svc}})
		require.NoError(t, err)
		_, err = c.getPublishedServices(t.Context(), &testPublishedServiceClient{getFn: func(context.Context, *metav1.GetOptions) (*userv1.Service, error) {
			t.Fatal("invalid options must be rejected before service lookup")
			return nil, nil
		}})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	c, err := NewConnector("example.com", &Opts{PublishServices: make([]*PublishedService, 129)})
	require.NoError(t, err)
	_, err = c.getPublishedServices(t.Context(), nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestPublishedServicesIncompleteResponsesReturnErrors(t *testing.T) {
	for _, response := range []*userv1.Service{nil, {}, {Metadata: &metav1.Metadata{Name: "web.default"}}, {
		Metadata: &metav1.Metadata{Name: "web.default"}, Spec: &userv1.Service_Spec{Port: 80},
	}} {
		c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{{Name: "web", Port: 8080}}})
		require.NoError(t, err)
		_, err = c.getPublishedServices(t.Context(), &testPublishedServiceClient{getFn: func(context.Context, *metav1.GetOptions) (*userv1.Service, error) {
			return response, nil
		}})
		assert.Error(t, err)
		assert.NotEqual(t, codes.NotFound, status.Code(err))
	}
}

func TestPendingPublicationsMatchCanonicalNamesAndHostMappings(t *testing.T) {
	c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{
		{Name: "web", Address: "localhost", Port: 8080},
		{Name: "web.default", Address: "localhost", Port: 8080},
		{Name: "web", Address: "localhost", Port: 8081},
		{Name: "web", Address: "::1", Port: 8080},
	}})
	require.NoError(t, err)
	pending := c.getPendingPublishedServices([]*cliconfigv1.Connection_Preferences_PublishedService{
		{Name: "web.default", HostAddress: "localhost", HostPort: 8080},
	})
	assert.Equal(t, c.opts.PublishServices[2:], pending)
	assert.Empty(t, c.getPendingPublishedServices([]*cliconfigv1.Connection_Preferences_PublishedService{
		{Name: "web", HostAddress: "localhost", HostPort: 8080},
		{Name: "web", HostAddress: "localhost", HostPort: 8081},
		{Name: "web", HostAddress: "::1", HostPort: 8080},
	}))
}

func TestRetryPendingPublicationsLifecycle(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "legacy"}[legacy], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var calls atomic.Int32
				var listCalls, additions int
				resolve := func(ctx context.Context) (*userv1.Service, error) {
					deadline, ok := ctx.Deadline()
					assert.True(t, ok)
					assert.LessOrEqual(t, deadline.Sub(time.Now()), publishedServiceLookupTimeout)
					switch calls.Load() {
					case 1:
						return nil, status.Error(codes.NotFound, "not created")
					case 2:
						return nil, status.Error(codes.Unavailable, "API restarting")
					default:
						return testPublishedAPIService("late.ns1", userv1.Service_Spec_UDP, 5353), nil
					}
				}
				cl := &testPublishedServiceClient{
					getFn: func(ctx context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
						calls.Add(1)
						assert.Equal(t, "late.ns1", req.Name)
						if legacy {
							return nil, status.Error(codes.Unimplemented, "legacy API")
						}
						return resolve(ctx)
					},
					listFn: func(ctx context.Context, _ *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
						listCalls++
						svc, err := resolve(ctx)
						if status.Code(err) == codes.NotFound {
							return &userv1.ServiceList{}, nil
						}
						if err != nil {
							return nil, err
						}
						return &userv1.ServiceList{Items: []*userv1.Service{svc}}, nil
					},
				}
				c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{
					{Name: "web", Address: "localhost", Port: 8080},
					{Name: "late.ns1", Address: "127.0.0.1", Port: 1053},
				}})
				require.NoError(t, err)
				active := []*cliconfigv1.Connection_Preferences_PublishedService{{Name: "web.default", HostAddress: "localhost", HostPort: 8080}}
				done := make(chan struct{})
				go func() {
					defer close(done)
					c.retryPublishedServices(ctx, cl, func(svc *cliconfigv1.Connection_Preferences_PublishedService) error {
						additions++
						assert.Equal(t, "late.ns1", svc.Name)
						assert.Equal(t, int32(5353), svc.Port)
						assert.Equal(t, int32(1053), svc.HostPort)
						assert.Equal(t, cliconfigv1.Connection_Preferences_PublishedService_UDP, svc.L4Type)
						if additions == 1 {
							return errors.New("temporary local failure")
						}
						return nil
					}, active)
				}()
				synctest.Wait()
				for i := 1; i <= 4; i++ {
					time.Sleep(publishedServiceRetryInterval)
					synctest.Wait()
					assert.Equal(t, int32(i), calls.Load())
				}
				select {
				case <-done:
				default:
					t.Fatal("the retry task must finish once all pending publications are added")
				}
				time.Sleep(24 * time.Hour)
				synctest.Wait()
				assert.Equal(t, int32(4), calls.Load())
				assert.Equal(t, 2, additions)
				assert.Len(t, active, 1)
				if legacy {
					assert.Equal(t, 4, listCalls)
				} else {
					assert.Zero(t, listCalls)
				}
			})
		})
	}
}

func TestPendingPublicationLookupDeadlineAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{{Name: "late", Port: 8080}}})
		require.NoError(t, err)
		cl := &testPublishedServiceClient{getFn: func(ctx context.Context, _ *metav1.GetOptions) (*userv1.Service, error) {
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		}}
		start := time.Now()
		_, err = c.getPublishedServices(context.Background(), cl)
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
		assert.Equal(t, publishedServiceLookupTimeout, time.Since(start))
	})
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		lookup := make(chan context.Context, 1)
		cl := &testPublishedServiceClient{getFn: func(ctx context.Context, _ *metav1.GetOptions) (*userv1.Service, error) {
			lookup <- ctx
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		}}
		c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{{Name: "late", Port: 8080}}})
		require.NoError(t, err)
		done := make(chan struct{})
		go func() {
			defer close(done)
			c.retryPublishedServices(ctx, cl, func(*cliconfigv1.Connection_Preferences_PublishedService) error {
				t.Error("a canceled lookup must not activate a publication")
				return nil
			}, nil)
		}()
		synctest.Wait()
		time.Sleep(publishedServiceRetryInterval)
		synctest.Wait()
		lookupCtx := <-lookup
		cancel()
		synctest.Wait()
		assert.ErrorIs(t, lookupCtx.Err(), context.Canceled)
		select {
		case <-done:
		default:
			t.Fatal("the retry task must stop promptly when its lookup is canceled")
		}
	})
}

func TestRunGRPCMissingPublicationsRecoverWhileConnected(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, scenario := range []string{"initial", "all-missing", "deleted-after-connect"} {
			t.Run(fmt.Sprintf("%s/legacy=%t", scenario, legacy), func(t *testing.T) {
				var available, recreated atomic.Bool
				available.Store(scenario == "deleted-after-connect")
				var attempts, healthyLookups atomic.Int32
				restart := make(chan struct{})
				requests := make(chan []string, 4)
				withHealthy := scenario != "all-missing"
				service := func(name string) (*userv1.Service, error) {
					if name == "healthy.default" {
						return testPublishedAPIService(name, userv1.Service_Spec_TCP, 8080), nil
					}
					if !available.Load() {
						return nil, status.Error(codes.NotFound, "Service not found")
					}
					if recreated.Load() {
						return testPublishedAPIService(name, userv1.Service_Spec_UDP, 5353), nil
					}
					return testPublishedAPIService(name, userv1.Service_Spec_TCP, 8081), nil
				}
				srv := &testConnectAPI{
					getServiceFn: func(_ context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
						if legacy {
							return nil, status.Error(codes.Unimplemented, "legacy API")
						}
						if req.Name == "healthy.default" {
							healthyLookups.Add(1)
						}
						return service(req.Name)
					},
					listFn: func(_ context.Context, req *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
						if req.GetCommon().GetPage() == 0 {
							return &userv1.ServiceList{
								Items:            []*userv1.Service{testPublishedAPIService("unrelated.default", userv1.Service_Spec_HTTP, 80)},
								ListResponseMeta: &metav1.ListResponseMeta{HasMore: true},
							}, nil
						}
						ret := &userv1.ServiceList{}
						if withHealthy {
							svc, _ := service("healthy.default")
							ret.Items = append(ret.Items, svc)
						}
						if svc, err := service("late.ns1"); err == nil {
							ret.Items = append(ret.Items, svc)
						}
						return ret, nil
					},
					connectFn: func(stream userv1.MainService_ConnectServer) error {
						attempt := attempts.Add(1)
						req, err := stream.Recv()
						if err != nil {
							return err
						}
						var names []string
						for _, svc := range req.GetInitialize().PublishedServices {
							names = append(names, svc.Name)
						}
						requests <- names
						state := testConnectInitialState()
						if legacy {
							state.CreatedAt = nil
						}
						if err := stream.Send(state); err != nil {
							return err
						}
						if scenario == "deleted-after-connect" && attempt == 1 {
							select {
							case <-restart:
								return status.Error(codes.Unavailable, "API restarting")
							case <-stream.Context().Done():
								return stream.Context().Err()
							}
						}
						<-stream.Context().Done()
						return stream.Context().Err()
					},
				}
				c, dbC := newTestRunningConnector(t, srv)
				port := func() int {
					lis, err := net.Listen("tcp", "127.0.0.1:0")
					require.NoError(t, err)
					defer lis.Close()
					return lis.Addr().(*net.TCPAddr).Port
				}
				healthyPort, latePort := port(), port()
				if withHealthy {
					c.opts.PublishServices = append(c.opts.PublishServices, &PublishedService{Name: "healthy", Address: "127.0.0.1", Port: healthyPort})
				}
				c.opts.PublishServices = append(c.opts.PublishServices, &PublishedService{Name: "late.ns1", Address: "127.0.0.1", Port: latePort})
				connected := make(chan *cliconfigv1.Connection, 4)
				c.opts.OnEvent = func(ev *Event) {
					if ev.Type == EventTypeConnected {
						connected <- proto.Clone(ev.Connection).(*cliconfigv1.Connection)
					}
				}
				ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 30*time.Second)
				var runErr error
				done := make(chan struct{})
				go func() {
					defer close(done)
					runErr = c.Run(ctx)
				}()
				t.Cleanup(func() {
					cancel()
					select {
					case <-done:
						assert.NoError(t, runErr)
					case <-time.After(5 * time.Second):
						t.Error("the client did not stop after cancellation")
					}
				})
				waitConnected := func(expectLate bool) *cliconfigv1.Connection {
					select {
					case cfg := <-connected:
						var names []string
						if withHealthy {
							names = append(names, "healthy.default")
						}
						if expectLate {
							names = append(names, "late.ns1")
						}
						assert.Equal(t, names, <-requests)
						assert.Len(t, cfg.Preferences.PublishedServices, len(names))
						return cfg
					case <-done:
						t.Fatalf("the client exited before connecting: %+v", runErr)
					case <-time.After(10 * time.Second):
						t.Fatal("the client did not connect while a publication was missing")
					}
					return nil
				}
				cfg := waitConnected(scenario == "deleted-after-connect")
				if scenario == "deleted-after-connect" {
					available.Store(false)
					close(restart)
					cfg = waitConnected(false)
				}
				connections := attempts.Load()
				lateAddr := net.JoinHostPort("127.0.0.1", fmt.Sprint(latePort))
				assert.False(t, testPublishedPortIsListening(lateAddr))
				if withHealthy {
					healthyAddr := net.JoinHostPort("127.0.0.1", fmt.Sprint(healthyPort))
					require.Eventually(t, func() bool { return testPublishedPortIsListening(healthyAddr) }, time.Second, 10*time.Millisecond)
				}
				recreated.Store(true)
				available.Store(true)
				require.Eventually(t, func() bool {
					conn, err := net.ListenPacket("udp", lateAddr)
					if err == nil {
						conn.Close()
						return false
					}
					return errors.Is(err, syscall.EADDRINUSE)
				}, publishedServiceRetryInterval+3*time.Second, 20*time.Millisecond)
				assert.False(t, testPublishedPortIsListening(lateAddr), "the recreated UDP Service must not use the old TCP configuration")
				assert.Equal(t, connections, attempts.Load(), "recovering a publication must preserve the established API stream")
				if withHealthy && !legacy {
					assert.Equal(t, connections, healthyLookups.Load())
				}
				select {
				case <-done:
					t.Fatalf("publication recovery stopped the connection: %+v", runErr)
				default:
				}
				assert.NotNil(t, cfg)
				cancel()
				<-done
				assert.NoError(t, runErr)
				_, err := dbC.GetConnectionCleanup("example.com")
				assert.True(t, dbC.ErrorIsNotFound(err))
				conn, err := net.ListenPacket("udp", lateAddr)
				require.NoError(t, err)
				require.NoError(t, conn.Close())
			})
		}
	}
}

func TestRunGRPCMissingPublicationPreservesControlRejections(t *testing.T) {
	for _, code := range []codes.Code{codes.NotFound, codes.PermissionDenied, codes.InvalidArgument} {
		t.Run(code.String(), func(t *testing.T) {
			var attempts atomic.Int32
			c, dbC := newTestRunningConnector(t, &testConnectAPI{
				getServiceFn: func(context.Context, *metav1.GetOptions) (*userv1.Service, error) {
					return nil, status.Error(codes.NotFound, "publication not found")
				},
				connectFn: func(stream userv1.MainService_ConnectServer) error {
					attempts.Add(1)
					req, err := stream.Recv()
					if err != nil {
						return err
					}
					assert.Empty(t, req.GetInitialize().PublishedServices)
					return status.Error(code, "control connection rejected")
				},
			})
			c.opts.PublishServices = []*PublishedService{{Name: "late", Port: 8080}}
			c.opts.OnEvent = func(ev *Event) {
				assert.NotEqual(t, EventTypeConnected, ev.Type)
			}
			ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 5*time.Second)
			defer cancel()
			err := c.Run(ctx)
			assert.Equal(t, code, status.Code(err))
			assert.Equal(t, int32(1), attempts.Load())
		})
	}
}

func TestPublishedServicesSlowSuccessfulLookupsHaveSeparateDeadlines(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{
			{Name: "first", Port: 8081}, {Name: "second", Port: 8082}, {Name: "third", Port: 8083},
		}})
		require.NoError(t, err)
		cl := &testPublishedServiceClient{getFn: func(ctx context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
			select {
			case <-ctx.Done():
				return nil, status.FromContextError(ctx.Err()).Err()
			case <-time.After(6 * time.Second):
				return testPublishedAPIService(req.Name, userv1.Service_Spec_TCP, 80), nil
			}
		}}
		start := time.Now()
		published, err := c.getPublishedServices(t.Context(), cl)
		require.NoError(t, err)
		assert.Len(t, published, 3)
		assert.Equal(t, 18*time.Second, time.Since(start))
	})
}

func TestRetryPendingPublicationsPreservesControlForAPIErrors(t *testing.T) {
	for code := codes.Canceled; code <= codes.Unauthenticated; code++ {
		if code == codes.NotFound || code == codes.Unimplemented {
			continue
		}
		t.Run(code.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var calls atomic.Int32
				cl := &testPublishedServiceClient{getFn: func(_ context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
					if calls.Add(1) == 1 {
						return nil, status.Error(code, "pending lookup failed")
					}
					return testPublishedAPIService(req.Name, userv1.Service_Spec_TCP, 80), nil
				}}
				c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{{Name: "late", Port: 8080}}})
				require.NoError(t, err)
				var additions atomic.Int32
				done := make(chan struct{})
				go func() {
					defer close(done)
					c.retryPublishedServices(ctx, cl, func(*cliconfigv1.Connection_Preferences_PublishedService) error {
						additions.Add(1)
						return nil
					}, nil)
				}()
				synctest.Wait()
				time.Sleep(publishedServiceRetryInterval)
				synctest.Wait()
				assert.Equal(t, int32(1), calls.Load())
				assert.Zero(t, additions.Load())
				assert.NoError(t, ctx.Err())
				select {
				case <-done:
					t.Fatal("a pending lookup error must leave publication recovery running")
				default:
				}
				time.Sleep(publishedServiceRetryInterval)
				synctest.Wait()
				<-done
				assert.Equal(t, int32(2), calls.Load())
				assert.Equal(t, int32(1), additions.Load())
			})
		})
	}
}

func TestRetryPendingPublicationsResolveAtDifferentTimes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, err := NewConnector("example.com", &Opts{PublishServices: []*PublishedService{
			{Name: "first", Port: 8081}, {Name: "second", Port: 8082},
		}})
		require.NoError(t, err)
		var lookups, added []string
		var secondLookups int
		cl := &testPublishedServiceClient{getFn: func(_ context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
			lookups = append(lookups, req.Name)
			if req.Name == "second.default" {
				secondLookups++
				if secondLookups < 3 {
					return nil, status.Error(codes.NotFound, "Service not created yet")
				}
			}
			return testPublishedAPIService(req.Name, userv1.Service_Spec_TCP, 80), nil
		}}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			c.retryPublishedServices(ctx, cl, func(svc *cliconfigv1.Connection_Preferences_PublishedService) error {
				added = append(added, svc.Name)
				return nil
			}, nil)
		}()
		synctest.Wait()
		for range 3 {
			time.Sleep(publishedServiceRetryInterval)
			synctest.Wait()
		}
		<-done
		assert.Equal(t, []string{"first.default", "second.default", "second.default", "second.default"}, lookups)
		assert.Equal(t, []string{"first.default", "second.default"}, added)
	})
}

func newTestServedTCPBackend(t *testing.T) *net.TCPAddr {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				io.Copy(conn, conn)
			})
		}
	})
	t.Cleanup(func() { cancel(); lis.Close(); wg.Wait() })
	return lis.Addr().(*net.TCPAddr)
}

func testServedGoNetRoundTrip(ctx context.Context, c *ctl, port int) bool {
	ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	conn, err := c.devCtl.GetNetstackNet().DialContextTCP(ctx, &net.TCPAddr{IP: net.ParseIP("100.64.0.2"), Port: port})
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	msg := []byte("served over the API connection")
	if _, err := conn.Write(msg); err != nil {
		return false
	}
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	return err == nil && string(buf) == string(msg)
}

func TestServedTCPRecoveryOverGRPC(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy-%t", legacy), func(t *testing.T) {
			clearTestConnectEnv(t)
			t.Setenv("OCTELIUM_DEV", "false")
			t.Setenv("OCTELIUM_PRODUCTION", "true")
			backend := newTestServedTCPBackend(t)
			service := func(name string, port uint32) *userv1.HostedService {
				return &userv1.HostedService{
					Name: name, Port: port, L4Type: userv1.HostedService_TCP,
					Address:  &metav1.DualStackIP{Ipv4: "100.64.0.2"},
					Upstream: &userv1.HostedService_Upstream{Host: "127.0.0.1", Port: int32(backend.Port)},
				}
			}
			events := make(chan *userv1.ConnectResponse, 8)
			api := newTestConnectAPIClient(t, &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
				req, err := stream.Recv()
				if err != nil {
					return err
				}
				if !req.GetInitialize().GetServiceOptions().GetServeAll() {
					return status.Error(codes.InvalidArgument, "missing serve-all request")
				}
				initial := testConnectInitialState()
				initial.GetState().ServiceOptions = &userv1.ConnectionState_ServiceOptions{Services: []*userv1.HostedService{service("healthy.default", 22001)}}
				if legacy {
					initial.CreatedAt = nil
				}
				if err := stream.Send(initial); err != nil {
					return err
				}
				for {
					select {
					case msg := <-events:
						if !legacy {
							msg.CreatedAt = timestamppb.Now()
						}
						if err := stream.Send(msg); err != nil {
							return err
						}
					case <-stream.Context().Done():
						return nil
					}
				}
			}})
			dbC, err := db.Open("memory")
			require.NoError(t, err)
			defer dbC.Close()
			ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 15*time.Second)
			defer cancel()
			connector, err := NewConnector("example.com", &Opts{
				L3Mode: "v4", IgnoreDNS: true, ImplementationMode: "gvisor", ServeAll: true,
				LocalDNSListenAddr: "127.0.0.1:0", UserHome: t.TempDir(),
			})
			require.NoError(t, err)
			stream, err := api.Connect(ctx)
			require.NoError(t, err)
			require.NoError(t, connector.sendInitializeRequest(stream, nil))
			cfg, initAt, err := connector.getConnectionConfig(ctx, stream, nil)
			require.NoError(t, err)
			c, err := newCtl(ctx, stream, cfg, initAt)
			require.NoError(t, err)
			defer func() { cancel(); assert.NoError(t, c.close()) }()
			require.NoError(t, c.start(ctx))
			require.Eventually(t, func() bool { return testServedGoNetRoundTrip(ctx, c, 22001) }, 3*time.Second, 10*time.Millisecond)
			blocker, err := c.devCtl.GetNetstackNet().ListenTCP(&net.TCPAddr{IP: net.ParseIP("100.64.0.2"), Port: 22000})
			require.NoError(t, err)
			defer blocker.Close()
			pending := service("pending.default", 22000)
			events <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddService_{AddService: &userv1.ConnectResponse_AddService{Service: pending}}}
			events <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateService_{UpdateService: &userv1.ConnectResponse_UpdateService{Service: proto.Clone(pending).(*userv1.HostedService)}}}
			time.Sleep(150 * time.Millisecond)
			require.True(t, testServedGoNetRoundTrip(ctx, c, 22001))
			require.NoError(t, blocker.Close())
			require.Eventually(t, func() bool { return testServedGoNetRoundTrip(ctx, c, 22000) }, 6*time.Second, 10*time.Millisecond)
			select {
			case err := <-c.stateController.getConnErrCh:
				t.Fatalf("a listener bind failure disrupted the control stream: %v", err)
			default:
			}
			events <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_DeleteService_{DeleteService: &userv1.ConnectResponse_DeleteService{Name: pending.Name}}}
			require.Eventually(t, func() bool {
				lis, err := c.devCtl.GetNetstackNet().ListenTCP(&net.TCPAddr{IP: net.ParseIP("100.64.0.2"), Port: 22000})
				if err != nil {
					return false
				}
				lis.Close()
				return true
			}, 2*time.Second, 10*time.Millisecond)
			require.True(t, testServedGoNetRoundTrip(ctx, c, 22001))
			events <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}}}
			result := c.stateController.waitDisconnected(ctx, func(context.Context) error { return nil })
			assert.True(t, result.isConnected)
			assert.False(t, result.needsReconnect)
			assert.NoError(t, result.err)
			cancel()
			require.NoError(t, c.close())
			_, err = dbC.GetConnectionCleanup("example.com")
			assert.True(t, dbC.ErrorIsNotFound(err))
		})
	}
}

func testMalformedServedResponses() []struct {
	name string
	msg  *userv1.ConnectResponse
} {
	return []struct {
		name string
		msg  *userv1.ConnectResponse
	}{
		{"AddNilWrapper", &userv1.ConnectResponse{Event: (*userv1.ConnectResponse_AddService_)(nil)}},
		{"AddNilMessage", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddService_{}}},
		{"AddNilService", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddService_{AddService: &userv1.ConnectResponse_AddService{}}}},
		{"AddEmptyService", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddService_{AddService: &userv1.ConnectResponse_AddService{Service: &userv1.HostedService{}}}}},
		{"UpdateNilWrapper", &userv1.ConnectResponse{Event: (*userv1.ConnectResponse_UpdateService_)(nil)}},
		{"UpdateNilMessage", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateService_{}}},
		{"UpdateNilService", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateService_{UpdateService: &userv1.ConnectResponse_UpdateService{}}}},
		{"UpdateEmptyService", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateService_{UpdateService: &userv1.ConnectResponse_UpdateService{Service: &userv1.HostedService{}}}}},
		{"DeleteNilWrapper", &userv1.ConnectResponse{Event: (*userv1.ConnectResponse_DeleteService_)(nil)}},
		{"DeleteNilMessage", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_DeleteService_{}}},
		{"DeleteEmptyName", &userv1.ConnectResponse{Event: &userv1.ConnectResponse_DeleteService_{DeleteService: &userv1.ConnectResponse_DeleteService{}}}},
	}
}

func newTestServingStateController(t *testing.T) *stateController {
	t.Helper()
	cfg := &cliconfigv1.Connection{
		Connection: &userv1.ConnectionState{L3Mode: userv1.ConnectionState_V4},
		Preferences: &cliconfigv1.Connection_Preferences{
			L3Mode:    cliconfigv1.Connection_Preferences_V4,
			ServeOpts: &cliconfigv1.Connection_Preferences_ServeOpts{IsEnabled: true, ProxyMode: cliconfigv1.Connection_Preferences_ServeOpts_USERSPACE},
		},
	}
	p, err := proxy.NewController(t.Context(), cfg, nil)
	require.NoError(t, err)
	require.NoError(t, p.Start(t.Context()))
	t.Cleanup(func() { assert.NoError(t, p.Close()) })
	return newStateController(cfg, nil, p, nil)
}

func TestServedMalformedStateEventsReturnErrors(t *testing.T) {
	for _, tt := range testMalformedServedResponses() {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestServingStateController(t)
			var err error
			require.NotPanics(t, func() { err = c.handleState(t.Context(), tt.msg) })
			require.Error(t, err)
			require.NoError(t, c.handleState(t.Context(), &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddService_{
				AddService: &userv1.ConnectResponse_AddService{Service: &userv1.HostedService{Name: "legacy.default"}},
			}}))
			require.NoError(t, c.handleState(t.Context(), &userv1.ConnectResponse{Event: &userv1.ConnectResponse_DeleteService_{
				DeleteService: &userv1.ConnectResponse_DeleteService{Name: "legacy.default"},
			}}))
		})
	}
}

func TestServedMalformedEventsIgnoredWhenNotServing(t *testing.T) {
	for _, cfg := range []*cliconfigv1.Connection{nil, {}, {Preferences: &cliconfigv1.Connection_Preferences{}}, {
		Preferences: &cliconfigv1.Connection_Preferences{ServeOpts: &cliconfigv1.Connection_Preferences_ServeOpts{}},
	}, {
		Preferences: &cliconfigv1.Connection_Preferences{ServeOpts: &cliconfigv1.Connection_Preferences_ServeOpts{ProxyMode: cliconfigv1.Connection_Preferences_ServeOpts_USERSPACE}},
	}} {
		c := newStateController(cfg, nil, nil, nil)
		for _, tt := range testMalformedServedResponses() {
			require.NotPanics(t, func() { assert.NoError(t, c.handleState(t.Context(), tt.msg)) })
		}
	}
	c := newTestServingStateController(t)
	c.c.Preferences.ServeOpts.ProxyMode = cliconfigv1.Connection_Preferences_ServeOpts_NONE
	for _, tt := range testMalformedServedResponses() {
		require.NotPanics(t, func() { assert.NoError(t, c.handleState(t.Context(), tt.msg)) })
	}
	require.NoError(t, c.handleState(t.Context(), nil))
}

func TestServedMalformedStateEventsRequestResynchronization(t *testing.T) {
	for _, tt := range testMalformedServedResponses() {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestServingStateController(t)
			var reads int
			c.streamC = &testConnectStream{recvFn: func() (*userv1.ConnectResponse, error) {
				reads++
				if reads == 1 {
					return tt.msg, nil
				}
				return &userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{}}, nil
			}}
			require.NotPanics(t, func() { c.doStartLoop(t.Context()) })
			assert.Equal(t, 1, reads)
			ret := c.waitDisconnected(t.Context(), nil)
			assert.ErrorContains(t, ret.err, "Could not apply connection state")
			assert.True(t, ret.needsReconnect)
			assert.True(t, ret.isConnected)
			assert.True(t, shouldReconnect(ret, true))
			select {
			case <-c.apiserverDisconnectCh:
				t.Fatal("a malformed Service event must not be an explicit server disconnect")
			default:
			}
		})
	}
}

func newTestMalformedServedBackend(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return conn.LocalAddr().(*net.UDPAddr)
}

func testMalformedServedRoundTrip(addr string) bool {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	msg := []byte("recovered hosted Service")
	if _, err := conn.Write(msg); err != nil {
		return false
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	return err == nil && string(buf[:n]) == string(msg)
}

func TestRunGRPCMalformedServedStateRecovers(t *testing.T) {
	for _, scenario := range []string{"AddMissingService", "UpdateMissingService", "DeleteMissingName", "InitialNilService", "InitialEmptyService"} {
		t.Run(scenario, func(t *testing.T) {
			backend := newTestMalformedServedBackend(t)
			reserved, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			addr := reserved.LocalAddr().String()
			port := uint32(reserved.LocalAddr().(*net.UDPAddr).Port)
			require.NoError(t, reserved.Close())
			initialFailure := strings.HasPrefix(scenario, "Initial")
			firstReady, recovered := make(chan struct{}), make(chan struct{})
			var attempts atomic.Int32
			srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
				attempt := attempts.Add(1)
				if attempt > 2 {
					return status.Error(codes.Internal, "unexpected extra connection")
				}
				req, err := stream.Recv()
				if err != nil {
					return err
				}
				if !req.GetInitialize().GetServiceOptions().GetServeAll() {
					return status.Error(codes.InvalidArgument, "missing serve-all request")
				}
				initial := testConnectInitialState()
				initial.GetState().ServiceOptions = &userv1.ConnectionState_ServiceOptions{Services: []*userv1.HostedService{{
					Name: "healthy.default", Port: port, L4Type: userv1.HostedService_UDP,
					Address:  &metav1.DualStackIP{Ipv4: "127.0.0.1"},
					Upstream: &userv1.HostedService_Upstream{Host: "127.0.0.1", Port: int32(backend.Port)},
				}}}
				if attempt == 1 && initialFailure {
					var bad *userv1.HostedService
					if scenario == "InitialEmptyService" {
						bad = &userv1.HostedService{}
					}
					initial.GetState().ServiceOptions.Services = append(initial.GetState().ServiceOptions.Services, bad)
				}
				if err := stream.Send(initial); err != nil {
					return err
				}
				if attempt == 1 && !initialFailure {
					select {
					case <-firstReady:
					case <-stream.Context().Done():
						return nil
					}
					msg := &userv1.ConnectResponse{}
					switch scenario {
					case "AddMissingService":
						msg.Event = &userv1.ConnectResponse_AddService_{AddService: &userv1.ConnectResponse_AddService{}}
					case "UpdateMissingService":
						msg.Event = &userv1.ConnectResponse_UpdateService_{UpdateService: &userv1.ConnectResponse_UpdateService{}}
					case "DeleteMissingName":
						msg.Event = &userv1.ConnectResponse_DeleteService_{DeleteService: &userv1.ConnectResponse_DeleteService{}}
					}
					if err := stream.Send(msg); err != nil {
						return err
					}
				} else if attempt == 2 {
					select {
					case <-recovered:
					case <-stream.Context().Done():
						return nil
					}
					if err := stream.Send(&userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}}}); err != nil {
						return err
					}
				}
				<-stream.Context().Done()
				return nil
			}}
			c, dbC := newTestRunningConnector(t, srv)
			c.opts.ServeAll = true
			var connected, errorsSeen int
			c.opts.OnEvent = func(event *Event) {
				if event.Err != nil {
					errorsSeen++
					assert.ErrorContains(t, event.Err, "without a name")
					_, err := dbC.GetConnectionCleanup("example.com")
					assert.True(t, dbC.ErrorIsNotFound(err))
				}
				if event.Type != EventTypeConnected {
					return
				}
				connected++
				assert.Eventually(t, func() bool { return testMalformedServedRoundTrip(addr) }, 3*time.Second, 10*time.Millisecond)
				if attempts.Load() == 1 {
					close(firstReady)
				} else {
					close(recovered)
				}
			}
			ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 15*time.Second)
			defer cancel()
			require.NoError(t, c.Run(ctx))
			assert.NoError(t, ctx.Err())
			assert.Equal(t, int32(2), attempts.Load())
			assert.Equal(t, 1, errorsSeen)
			wantConnected := 2
			if initialFailure {
				wantConnected = 1
			}
			assert.Equal(t, wantConnected, connected)
			probe, err := net.ListenPacket("udp", addr)
			require.NoError(t, err, "the recovered connection must release its served listener")
			assert.NoError(t, probe.Close())
		})
	}
}
