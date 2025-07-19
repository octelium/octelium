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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/octelium-go/authc"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

type Client struct {
	cc *ClientConfig

	mu sync.Mutex

	isClosed bool

	c *authc.Client

	sessToken sessToken
}

type grpcC struct {
	c *Client
}
type httpC struct {
	c *Client
}

type sessToken struct {
	t     *authv1.SessionToken
	setAt time.Time
	sync.RWMutex
}

func (s *sessToken) getAccessToken() (string, error) {
	s.RLock()
	defer s.RUnlock()

	if s.t == nil {
		return "", errors.Errorf("Could not find access token")
	}
	return s.t.AccessToken, nil
}

// HTTP implements HTTP-related functions
type HTTP interface {
	// Client returns an HTTP client with a middleware that automatically sets the access token
	// in the Authorization header for every request
	Client() *http.Client
	// OAuth2TokenSource returns an oauth2.TokenSource instance
	OAuth2TokenSource(ctx context.Context) oauth2.TokenSource
}

// GRPC implements gRPC-related functions
type GRPC interface {
	// GetConn creates a new gRPC connection with the necessary auth middlewares needed to
	// access the different Cluster APIs.
	GetConn(ctx context.Context, opts ...grpc.DialOption) (grpc.ClientConnInterface, error)

	// AuthUnaryClientInterceptor returns an grpc.UnaryClientInterceptor middleware that automatically
	// sets the access token on every unary gRPC call
	AuthUnaryClientInterceptor() grpc.UnaryClientInterceptor

	// AuthStreamClientInterceptor returns an grpc.StreamClientInterceptor middleware that automatically
	// sets the access token on every stream gRPC call
	AuthStreamClientInterceptor() grpc.StreamClientInterceptor
}

// ClientConfig is the Octelium client configuration
type ClientConfig struct {
	// Domain is the Cluster domain (e.g. `example.com`, `octelium.example.com`, etc...).
	Domain string
	// AuthenticationToken is the authentication Token used to obtain a valid Session in order to interact with the Cluster. This field is required.
	AuthenticationToken string
	// Scopes is the optional list of Scopes to further limit the access permissions. Read the docs to understand more about Scopes.
	Scopes []string
	// AuthenticateOnCreation disables the default behavior of doing the initial authentication lazily whenever first needed.
	AuthenticateOnCreation bool
}

// NewClient creates a new Octelium client
func NewClient(ctx context.Context, cc *ClientConfig) (*Client, error) {
	var err error
	if cc == nil {
		cc = &ClientConfig{}
	}

	if cc.Domain == "" {
		cc.Domain = os.Getenv("OCTELIUM_DOMAIN")
	}

	if cc.AuthenticationToken == "" {
		cc.AuthenticationToken = os.Getenv("OCTELIUM_AUTH_TOKEN")
	}

	if cc.Domain == "" {
		return nil, errors.Errorf("Empty Domain")
	}

	if cc.AuthenticationToken == "" {
		return nil, errors.Errorf("Empty authentication token")
	}

	ret := &Client{
		cc: cc,
	}

	ret.c, err = authc.NewClient(ctx, cc.Domain, &authc.Opts{
		GetRefreshToken: func(ctx context.Context, domain string) (string, error) {
			ret.sessToken.RLock()
			defer ret.sessToken.RUnlock()

			if ret.sessToken.t != nil && ret.sessToken.t.RefreshToken != "" {
				return ret.sessToken.t.RefreshToken, nil
			}
			return "", errors.Errorf("No refresh token found")
		},
		UserAgent: "octelium-sdk",
	})
	if err != nil {
		return nil, err
	}

	if cc.AuthenticateOnCreation {
		if _, err := ret.doGetAccessToken(ctx); err != nil {
			return nil, err
		}
	}

	return ret, nil
}

// GetAccessToken returns an access token
func (c *Client) GetAccessToken(ctx context.Context) (string, error) {
	return c.doGetAccessToken(ctx)
}

func (c *sessToken) getExpiresAt() time.Time {
	c.RLock()
	defer c.RUnlock()

	if c.t == nil {
		return time.Time{}
	}

	return c.setAt.
		Add(time.Second * time.Duration(c.t.ExpiresIn))
}

func (c *Client) GRPC() GRPC {
	return &grpcC{
		c: c,
	}
}

func (c *Client) HTTP() HTTP {
	return &httpC{
		c: c,
	}
}

type oauth2TknSource struct {
	c *Client
}

func (c *httpC) OAuth2TokenSource(_ context.Context) oauth2.TokenSource {
	return &oauth2TknSource{
		c: c.c,
	}
}

func (i *oauth2TknSource) Token() (*oauth2.Token, error) {

	c := i.c

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	accessToken, err := c.doGetAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		Expiry:      c.sessToken.getExpiresAt(),
	}, nil
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

func (i *grpcC) GetConn(ctx context.Context, opts ...grpc.DialOption) (grpc.ClientConnInterface, error) {
	c := i.c
	if _, err := c.doGetAccessToken(ctx); err != nil {
		return nil, err
	}

	return c.getGRPCClient(ctx, opts...)
}

func (s *Client) getGRPCClient(ctx context.Context, opts ...grpc.DialOption) (grpc.ClientConnInterface, error) {

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
	}

	unaryMiddlewares := []grpc.UnaryClientInterceptor{
		grpc_retry.UnaryClientInterceptor(grpc_retry.WithMax(100), grpc_retry.WithCodes(retryCodes...)),
		s.unaryClientInterceptor(),
	}

	streamMiddlewares := []grpc.StreamClientInterceptor{
		grpc_retry.StreamClientInterceptor(grpc_retry.WithMax(100), grpc_retry.WithCodes(retryCodes...)),
		s.streamClientInterceptor(),
	}

	cOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithUnaryInterceptor(grpc_middleware.ChainUnaryClient(unaryMiddlewares...)),
		grpc.WithStreamInterceptor(grpc_middleware.ChainStreamClient(streamMiddlewares...)),
	}
	cOpts = append(cOpts, opts...)

	return grpc.NewClient(authc.GetAPIServerAddr(s.cc.Domain), cOpts...)

}

// Close closes the Client and logs out from the Cluster.
func (c *Client) Close() error {

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed {
		return nil
	}
	c.isClosed = true
	ctx, cancelFn := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelFn()
	if err := c.doLogout(ctx); err != nil {
		return err
	}

	return nil
}

func (i *grpcC) AuthUnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return i.c.unaryClientInterceptor()
}

func (c *Client) unaryClientInterceptor() grpc.UnaryClientInterceptor {

	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {

		token, err := c.doGetAccessToken(ctx)
		if err != nil {
			return err
		}
		ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-auth", token)

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func (i *grpcC) AuthStreamClientInterceptor() grpc.StreamClientInterceptor {
	return i.c.streamClientInterceptor()
}

func (c *Client) streamClientInterceptor() grpc.StreamClientInterceptor {

	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		token, err := c.doGetAccessToken(ctx)
		if err != nil {
			return nil, err
		}
		ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-auth", token)

		clientStream, err := streamer(ctx, desc, cc, method, opts...)
		return clientStream, err
	}
}

func (c *Client) doGetAccessToken(ctx context.Context) (string, error) {
	if accessToken := os.Getenv("OCTELIUM_ACCESS_TOKEN"); accessToken != "" {
		return accessToken, nil
	}
	if !c.needsNewAccessToken() {
		return c.sessToken.getAccessToken()
	}

	if err := c.setAccessTokenResponse(ctx); err != nil {
		return "", err
	}

	return c.sessToken.getAccessToken()
}

func (c *Client) setAccessTokenResponse(ctx context.Context) error {

	var resp *authv1.SessionToken
	var err error
	if c.sessToken.t == nil {
		resp, err = c.c.C().AuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: c.cc.AuthenticationToken,
			Scopes:              c.cc.Scopes,
		})
		if err != nil {
			return err
		}

	} else {
		resp, err = c.c.C().AuthenticateWithRefreshToken(ctx, &authv1.AuthenticateWithRefreshTokenRequest{})
		if err != nil {
			if grpcerr.AlreadyExists(err) {
				return nil
			}
			return err
		}
	}

	c.sessToken.Lock()
	c.sessToken.t = resp
	c.sessToken.setAt = time.Now()
	c.sessToken.Unlock()

	return nil
}

func (c *Client) needsNewAccessToken() bool {

	if _, err := c.sessToken.getAccessToken(); err != nil {
		return true
	}

	return time.Now().After(c.sessToken.getExpiresAt())
}

func (c *Client) doLogout(ctx context.Context) error {
	if _, err := c.sessToken.getAccessToken(); err != nil {
		return nil
	}

	_, err := c.c.C().Logout(ctx, &authv1.LogoutRequest{})
	return err
}

type roundTripper struct {
	c *Client
}

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	accessToken, err := r.c.doGetAccessToken(req.Context())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	return createTransport().RoundTrip(req)
}

func createTransport() *http.Transport {
	dialer := &net.Dialer{
		KeepAlive: 30 * time.Second,
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: ldflags.IsDev() || utils.IsInsecureTLS(),
		},
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       dialer.DialContext,
		ForceAttemptHTTP2: true,
	}
}

func (c *httpC) Client() *http.Client {
	return &http.Client{
		Transport: &roundTripper{
			c: c.c,
		},
	}
}
