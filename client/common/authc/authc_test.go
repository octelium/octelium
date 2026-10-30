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

package authc

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/grpc/status"
)

func TestGetTLSConfig(t *testing.T) {
	for _, itm := range []struct {
		dev      string
		insecure string
		want     bool
	}{
		{"false", "false", false}, {"true", "false", true}, {"false", "true", true},
	} {
		t.Setenv("OCTELIUM_PRODUCTION", "true")
		t.Setenv("OCTELIUM_DEV", itm.dev)
		t.Setenv("OCTELIUM_INSECURE_TLS", itm.insecure)
		ret, err := getTLSConfig()
		require.NoError(t, err)
		assert.Equal(t, uint16(tls.VersionTLS12), ret.MinVersion)
		assert.Equal(t, itm.want, ret.InsecureSkipVerify)
	}
}

func TestRefreshTokenInterceptors(t *testing.T) {
	for _, itm := range []struct {
		name     string
		token    string
		tokenErr error
		callback bool
	}{
		{"token", "refresh", nil, true},
		{"empty", "", nil, true},
		{"lookup error", "refresh", errors.New("missing"), true},
		{"no callback", "", nil, false},
	} {
		t.Run(itm.name, func(t *testing.T) {
			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("existing", "value"))
			c := &Client{domain: "example.com", opts: &Opts{}}
			calls := 0
			if itm.callback {
				c.opts.GetRefreshToken = func(arg context.Context, domain string) (string, error) {
					assert.Equal(t, ctx, arg)
					assert.Equal(t, "example.com", domain)
					calls++
					return itm.token, itm.tokenErr
				}
			}
			wantErr := status.Error(codes.PermissionDenied, "denied")
			check := func(arg context.Context, method string, opts []grpc.CallOption) {
				assert.Equal(t, "/test/Method", method)
				assert.Len(t, opts, 1)
				md, _ := metadata.FromOutgoingContext(arg)
				assert.Equal(t, []string{"value"}, md.Get("existing"))
				if itm.token != "" && itm.tokenErr == nil {
					assert.Equal(t, []string{itm.token}, md.Get("x-octelium-refresh-token"))
				} else {
					assert.Empty(t, md.Get("x-octelium-refresh-token"))
				}
			}
			err := c.unaryClientInterceptor()(ctx, "/test/Method", "request", "response", nil,
				func(arg context.Context, method string, req, reply any, cc *grpc.ClientConn, opts ...grpc.CallOption) error {
					check(arg, method, opts)
					assert.Equal(t, "request", req)
					assert.Equal(t, "response", reply)
					return wantErr
				}, grpc.WaitForReady(true))
			assert.ErrorIs(t, err, wantErr)
			stream, err := c.streamClientInterceptor()(ctx, &grpc.StreamDesc{}, nil, "/test/Method",
				func(arg context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
					check(arg, method, opts)
					return nil, wantErr
				}, grpc.WaitForReady(true))
			assert.Nil(t, stream)
			assert.ErrorIs(t, err, wantErr)
			if itm.callback {
				assert.Equal(t, 2, calls)
			}
			md, _ := metadata.FromOutgoingContext(ctx)
			assert.Empty(t, md.Get("x-octelium-refresh-token"))
		})
	}
}

func TestAuthClientTLSGRPC(t *testing.T) {
	t.Setenv("OCTELIUM_INSECURE_TLS", "true")
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	previous := resolver.Get("dns")
	r := manual.NewBuilderWithScheme("dns")
	r.InitialState(resolver.State{Addresses: []resolver.Address{{Addr: lis.Addr().String()}}})
	resolver.Register(r)
	t.Cleanup(func() { resolver.Register(previous) })
	received := make(chan metadata.MD, 2)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			received <- md
			return &authv1.LogoutResponse{}, nil
		}))
	authv1.RegisterMainServiceServer(srv, &authv1.UnimplementedMainServiceServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := NewClient(ctx, "example.invalid", &Opts{
		GetRefreshToken: func(ctx context.Context, domain string) (string, error) { return "refresh", nil },
		UserAgent:       "test-client/1.0",
	})
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	_, err = c.C().Logout(ctx, &authv1.LogoutRequest{})
	require.NoError(t, err)
	md := <-received
	assert.Equal(t, []string{"refresh"}, md.Get("x-octelium-refresh-token"))
	assert.Contains(t, md.Get("user-agent")[0], "test-client/1.0")
	assert.NoError(t, c.Close())
	assert.Equal(t, connectivity.Shutdown, c.grpcConn.GetState())
	c, err = NewClient(ctx, "example.invalid", nil)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	_, err = c.C().Logout(ctx, &authv1.LogoutRequest{})
	require.NoError(t, err)
	assert.Empty(t, (<-received).Get("x-octelium-refresh-token"))
	assert.NoError(t, (&Client{}).Close())
	assert.Equal(t, "octelium-api.example.com:443", GetAPIServerAddr("example.com"))
}
