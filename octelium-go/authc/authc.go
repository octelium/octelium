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
	"fmt"
	"net"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

type Opts struct {
	GetRefreshToken func(ctx context.Context, domain string) (string, error)
	UserAgent       string
}

type Client struct {
	c      authv1.MainServiceClient
	domain string
	opts   *Opts
}

func NewClient(ctx context.Context, domain string, opts *Opts) (*Client, error) {
	var err error

	if opts == nil {
		opts = &Opts{}
	}

	ret := &Client{
		domain: domain,
		opts:   opts,
	}

	grpcConn, err := ret.doGetGRPCClientConn(ctx, domain)
	if err != nil {
		return nil, err
	}

	ret.c = authv1.NewMainServiceClient(grpcConn)

	return ret, nil
}

func getTLSConfig() (*tls.Config, error) {

	ret := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if ldflags.IsDev() || utils.IsInsecureTLS() {
		ret.InsecureSkipVerify = true
	}

	return ret, nil
}

func (c *Client) doGetGRPCClientConn(ctx context.Context, domain string) (*grpc.ClientConn, error) {

	tlsConfig, err := getTLSConfig()
	if err != nil {
		return nil, err
	}

	retryCodes := []codes.Code{
		codes.Unavailable,
		codes.ResourceExhausted,
		codes.Unknown,
		codes.Aborted,
		codes.DataLoss,
		codes.Internal,
		codes.DeadlineExceeded,
	}

	unaryMiddlewares := []grpc.UnaryClientInterceptor{
		grpc_retry.UnaryClientInterceptor(
			grpc_retry.WithMax(16),
			grpc_retry.WithBackoff(grpc_retry.BackoffLinear(1000*time.Millisecond)),
			grpc_retry.WithCodes(retryCodes...)),
	}

	streamMiddlewares := []grpc.StreamClientInterceptor{}

	unaryMiddlewares = append(unaryMiddlewares,
		c.unaryClientInterceptor(),
	)

	streamMiddlewares = append(streamMiddlewares,
		c.streamClientInterceptor(),
	)

	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    45 * time.Second,
			Timeout: 15 * time.Second,
		}),

		grpc.WithUnaryInterceptor(grpc_middleware.ChainUnaryClient(unaryMiddlewares...)),
		grpc.WithStreamInterceptor(grpc_middleware.ChainStreamClient(streamMiddlewares...)),
	}

	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if c.opts.UserAgent != "" {
		opts = append(opts, grpc.WithUserAgent(c.opts.UserAgent))
	}

	return grpc.NewClient(GetAPIServerAddr(domain), opts...)
}

func (c *Client) unaryClientInterceptor() grpc.UnaryClientInterceptor {

	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {

		if c.opts.GetRefreshToken != nil {
			if refreshToken, err := c.opts.GetRefreshToken(ctx, c.domain); err == nil && refreshToken != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-refresh-token", refreshToken)
			}
		}

		err := invoker(ctx, method, req, reply, cc, opts...)

		return err
	}
}

func (c *Client) streamClientInterceptor() grpc.StreamClientInterceptor {

	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {

		if c.opts.GetRefreshToken != nil {
			if refreshToken, err := c.opts.GetRefreshToken(ctx, c.domain); err == nil && refreshToken != "" {
				ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-refresh-token", refreshToken)
			}
		}

		clientStream, err := streamer(ctx, desc, cc, method, opts...)
		return clientStream, err
	}
}

func (c *Client) C() authv1.MainServiceClient {
	return c.c
}

func GetAPIServerAddr(domain string) string {
	return net.JoinHostPort(fmt.Sprintf("octelium-api.%s", domain), "443")
}
