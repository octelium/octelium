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

package octelium

import (
	"context"
	"fmt"
	"net"

	"github.com/octelium/octelium/apis/main/authv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	metadataKeyAuth         = "x-octelium-auth"
	metadataKeyRefreshToken = "x-octelium-refresh-token"
)

func (c *Client) baseDialOptions() []grpc.DialOption {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(c.grpcTransportCredentials()),
		grpc.WithUserAgent(c.cfg.userAgent),
	}

	if c.cfg.grpcServiceConfig != "" {
		opts = append(opts, grpc.WithDefaultServiceConfig(c.cfg.grpcServiceConfig))
	}
	if c.cfg.grpcKeepalive != nil {
		opts = append(opts, grpc.WithKeepaliveParams(*c.cfg.grpcKeepalive))
	}

	return append(opts, c.cfg.grpcDialOptions...)
}

func (c *Client) authClient() (authv1.MainServiceClient, error) {
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}

	c.authMu.Lock()
	defer c.authMu.Unlock()

	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	if c.authC != nil {
		return c.authC, nil
	}

	opts := c.baseDialOptions()
	opts = append(opts,
		grpc.WithChainUnaryInterceptor(c.refreshTokenUnaryInterceptor()),
		grpc.WithChainStreamInterceptor(c.refreshTokenStreamInterceptor()),
	)

	conn, err := grpc.NewClient(c.cfg.apiEndpoint, opts...)
	if err != nil {
		return nil, err
	}

	c.authConn = conn
	c.authC = authv1.NewMainServiceClient(conn)
	return c.authC, nil
}

// Conn returns a shared authenticated gRPC connection. The Client owns it and
// callers must not close it.
func (c *Client) Conn(ctx context.Context) (*grpc.ClientConn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("octelium: nil context")
	}
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}

	c.apiMu.Lock()
	defer c.apiMu.Unlock()

	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	if c.apiConn != nil {
		return c.apiConn, nil
	}

	conn, err := c.newAPIConn()
	if err != nil {
		return nil, err
	}
	c.apiConn = conn
	return conn, nil
}

// NewConn creates a caller-owned authenticated gRPC connection.
func (c *Client) NewConn(ctx context.Context, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	if ctx == nil {
		return nil, fmt.Errorf("octelium: nil context")
	}
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}

	base := c.apiDialOptions()
	base = append(base, opts...)
	return grpc.NewClient(c.cfg.apiEndpoint, base...)
}

func (c *Client) newAPIConn() (*grpc.ClientConn, error) {
	return grpc.NewClient(c.cfg.apiEndpoint, c.apiDialOptions()...)
}

func (c *Client) apiDialOptions() []grpc.DialOption {
	opts := c.baseDialOptions()
	opts = append(opts,
		grpc.WithChainUnaryInterceptor(c.AuthUnaryClientInterceptor()),
		grpc.WithChainStreamInterceptor(c.AuthStreamClientInterceptor()),
	)
	return opts
}

// AuthUnaryClientInterceptor attaches the access token to unary calls. It does
// not retry failed calls; replay policy belongs to the caller or a
// method-specific gRPC service config.
func (c *Client) AuthUnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req any,
		reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		token, err := c.AccessToken(ctx)
		if err != nil {
			return err
		}

		ctx = setOutgoingMetadata(ctx, metadataKeyAuth, token)
		err = invoker(ctx, method, req, reply, cc, opts...)
		if status.Code(err) == codes.Unauthenticated {
			c.InvalidateAccessToken()
		}
		return err
	}
}

// AuthStreamClientInterceptor attaches the access token when a stream is
// created. Existing streams retain the authorization established at creation.
func (c *Client) AuthStreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		token, err := c.AccessToken(ctx)
		if err != nil {
			return nil, err
		}

		ctx = setOutgoingMetadata(ctx, metadataKeyAuth, token)
		stream, err := streamer(ctx, desc, cc, method, opts...)
		if status.Code(err) == codes.Unauthenticated {
			c.InvalidateAccessToken()
		}
		return stream, err
	}
}

func (c *Client) refreshTokenUnaryInterceptor() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req any,
		reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if token, ok := c.tokens.refreshToken(); ok {
			ctx = setOutgoingMetadata(ctx, metadataKeyRefreshToken, token)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func (c *Client) refreshTokenStreamInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		if token, ok := c.tokens.refreshToken(); ok {
			ctx = setOutgoingMetadata(ctx, metadataKeyRefreshToken, token)
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}

func setOutgoingMetadata(ctx context.Context, key, value string) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set(key, value)
	return metadata.NewOutgoingContext(ctx, md)
}

// GetAPIServerAddr returns the default Cluster API host and port.
func GetAPIServerAddr(domain string) string {
	return net.JoinHostPort("octelium-api."+domain, "443")
}
