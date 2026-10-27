package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/octelium/octelium/client/common/authenticator"
	authmiddleware "github.com/octelium/octelium/client/common/client/middleware/auth"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/grpc/status"
)

func TestGetDefaultKubeConfig(t *testing.T) {
	key := "HOME"
	if runtime.GOOS == "windows" {
		key = "USERPROFILE"
	}
	t.Setenv(key, t.TempDir())
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	ret, err := GetDefaultKubeConfig()
	require.NoError(t, err)
	assert.Equal(t, home+"/.kube/config", ret)
}

func TestAuthInterceptors(t *testing.T) {
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "static-token")
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("existing", "value"))
	wantErr := status.Error(codes.PermissionDenied, "denied")
	calls := 0
	check := func(arg context.Context, method string, opts []grpc.CallOption) {
		calls++
		assert.Equal(t, "/test/Method", method)
		assert.Len(t, opts, 1)
		md, _ := metadata.FromOutgoingContext(arg)
		assert.Equal(t, []string{"value"}, md.Get("existing"))
		assert.Equal(t, []string{"static-token"}, md.Get("x-octelium-auth"))
	}
	err := authmiddleware.UnaryClientInterceptor("example.com")(ctx, "/test/Method", "request", "response", nil,
		func(arg context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			check(arg, method, opts)
			assert.Equal(t, "request", req)
			assert.Equal(t, "response", reply)
			return wantErr
		}, grpc.WaitForReady(true))
	assert.ErrorIs(t, err, wantErr)
	stream, err := authmiddleware.StreamClientInterceptor("example.com")(ctx, &grpc.StreamDesc{}, nil, "/test/Method",
		func(arg context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			check(arg, method, opts)
			return nil, wantErr
		}, grpc.WaitForReady(true))
	assert.Nil(t, stream)
	assert.ErrorIs(t, err, wantErr)
	assert.Equal(t, 2, calls)
	md, _ := metadata.FromOutgoingContext(ctx)
	assert.Empty(t, md.Get("x-octelium-auth"))
}

func TestAuthInterceptorsRequireAuthentication(t *testing.T) {
	for _, key := range []string{"OCTELIUM_AUTH_PROXY_SOCKET", "OCTELIUM_ACCESS_TOKEN", "OCTELIUM_AUTH_TOKEN", "OCTELIUM_AUTH_ASSERTION"} {
		t.Setenv(key, "")
	}
	d, err := db.Open("mem")
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	ctx := authenticator.WithNonInteractive(cliutils.WithDB(context.Background(), d))
	called := false
	err = authmiddleware.UnaryClientInterceptor("example.invalid")(ctx, "/test/Method", nil, nil, nil,
		func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
			called = true
			return nil
		})
	assert.ErrorIs(t, err, authenticator.ErrAuthenticationRequired)
	stream, err := authmiddleware.StreamClientInterceptor("example.invalid")(ctx, &grpc.StreamDesc{}, nil, "/test/Method",
		func(context.Context, *grpc.StreamDesc, *grpc.ClientConn, string, ...grpc.CallOption) (grpc.ClientStream, error) {
			called = true
			return nil, nil
		})
	assert.ErrorIs(t, err, authenticator.ErrAuthenticationRequired)
	assert.Nil(t, stream)
	assert.False(t, called)
	conn, err := GetGRPCClientConn(ctx, "example.invalid")
	assert.ErrorIs(t, err, authenticator.ErrAuthenticationRequired)
	assert.Nil(t, conn)
}

func TestClientGRPCE2E(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		name := "TLS"
		if proxy {
			name = "UnixProxy"
		}
		t.Run(name, func(t *testing.T) {
			if proxy && runtime.GOOS == "windows" {
				t.Skip("Unix socket transport")
			}
			t.Setenv("OCTELIUM_ACCESS_TOKEN", "static-token")
			t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
			t.Setenv("OCTELIUM_INSECURE_TLS", "true")
			t.Setenv("OCTELIUM_PRODUCTION", "true")
			t.Setenv("OCTELIUM_DEV", "false")
			received := make(chan metadata.MD, 2)
			opts := []grpc.ServerOption{
				grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
					md, _ := metadata.FromIncomingContext(ctx)
					received <- md
					return handler(ctx, req)
				}),
				grpc.StreamInterceptor(func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
					md, _ := metadata.FromIncomingContext(stream.Context())
					received <- md
					return handler(srv, stream)
				}),
			}
			var lis net.Listener
			var err error
			if proxy {
				dir, err := os.MkdirTemp("", "oct-grpc-")
				require.NoError(t, err)
				t.Cleanup(func() { os.RemoveAll(dir) })
				socket := filepath.Join(dir, "proxy.sock")
				lis, err = net.Listen("unix", socket)
				require.NoError(t, err)
				t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", socket)
			} else {
				certServer := httptest.NewTLSServer(nil)
				cert := certServer.TLS.Certificates[0]
				certServer.Close()
				opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})))
				lis, err = net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				previous := resolver.Get("passthrough")
				r := manual.NewBuilderWithScheme("passthrough")
				r.InitialState(resolver.State{Addresses: []resolver.Address{{Addr: lis.Addr().String()}}})
				resolver.Register(r)
				t.Cleanup(func() { resolver.Register(previous) })
			}
			srv := grpc.NewServer(opts...)
			healthSrv := health.NewServer()
			healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
			grpc_health_v1.RegisterHealthServer(srv, healthSrv)
			go srv.Serve(lis)
			t.Cleanup(srv.Stop)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := GetGRPCClientConn(ctx, "example.invalid")
			require.NoError(t, err)
			t.Cleanup(func() { conn.Close() })
			c := grpc_health_v1.NewHealthClient(conn)
			resp, err := c.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
			require.NoError(t, err)
			assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
			stream, err := c.Watch(ctx, &grpc_health_v1.HealthCheckRequest{})
			require.NoError(t, err)
			resp, err = stream.Recv()
			require.NoError(t, err)
			assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
			for range 2 {
				md := <-received
				want := "static-token"
				if proxy {
					want = ""
				}
				assert.Equal(t, []string{want}, md.Get("x-octelium-auth"))
				assert.Contains(t, md.Get("user-agent")[0], "octelium-cli/")
			}
		})
	}
}
