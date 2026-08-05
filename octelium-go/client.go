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
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"golang.org/x/net/idna"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpccredentials "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// Client is an authenticated Octelium Cluster client. It is safe for
// concurrent use.
type Client struct {
	cfg config

	tokens *tokenManager

	stateMu sync.RWMutex
	closed  bool

	authMu   sync.Mutex
	authConn *grpc.ClientConn
	authC    authv1.MainServiceClient

	apiMu   sync.Mutex
	apiConn *grpc.ClientConn

	httpTransport http.RoundTripper
}

// New creates a Client. The caller owns the Client and must Close it.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	if ctx == nil {
		return nil, fmt.Errorf("octelium: nil context")
	}

	cfg := config{
		useEnvironment:        true,
		userAgent:             defaultUserAgent,
		logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
		authenticationTimeout: defaultAuthenticationTimeout,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	if cfg.domain == "" {
		cfg.domain = os.Getenv("OCTELIUM_DOMAIN")
	}

	domain, err := normalizeDomain(cfg.domain)
	if err != nil {
		return nil, err
	}
	cfg.domain = domain

	for i, host := range cfg.authorizedHTTPHosts {
		normalized, err := normalizeHTTPHost(host)
		if err != nil {
			return nil, fmt.Errorf("octelium: invalid authorized HTTP host %q: %w", host, err)
		}
		cfg.authorizedHTTPHosts[i] = normalized
	}

	if cfg.authenticator != nil && cfg.tokenProvider != nil {
		return nil, fmt.Errorf("octelium: WithAuthenticator and WithAccessTokenProvider are mutually exclusive")
	}

	if cfg.authenticator == nil && cfg.tokenProvider == nil {
		if !cfg.useEnvironment {
			return nil, ErrNoCredentials
		}

		identity, err := identityFromEnvironment()
		if err != nil {
			return nil, err
		}
		cfg.authenticator = identity.authenticator
		cfg.tokenProvider = identity.provider
	}

	if cfg.rootCAs != nil && cfg.insecureSkipVerify {
		return nil, fmt.Errorf("octelium: WithRootCAs and WithInsecureSkipVerify are mutually exclusive")
	}
	if cfg.grpcCredentials != nil && (cfg.rootCAs != nil || cfg.insecureSkipVerify) {
		return nil, fmt.Errorf("octelium: custom gRPC credentials are mutually exclusive with SDK TLS options")
	}

	defaultServerName := "octelium-api." + cfg.domain
	if cfg.tlsServerName == "" {
		cfg.tlsServerName = os.Getenv("OCTELIUM_TLS_SERVER_NAME")
	}
	if cfg.tlsServerName == "" {
		cfg.tlsServerName = defaultServerName
	}
	if cfg.apiEndpoint == "" {
		cfg.apiEndpoint = os.Getenv("OCTELIUM_API_ENDPOINT")
	}
	if cfg.apiEndpoint == "" {
		cfg.apiEndpoint = "dns:///" + net.JoinHostPort(defaultServerName, "443")
	}

	ret := &Client{
		cfg:    cfg,
		tokens: newTokenManager(),
	}

	if cfg.httpTransport != nil {
		ret.httpTransport = cfg.httpTransport
	} else {
		ret.httpTransport = ret.newHTTPTransport()
		ret.cfg.ownsHTTPTransport = true
	}

	if cfg.authenticateOnCreate {
		if _, err := ret.AccessToken(ctx); err != nil {
			_ = ret.Close()
			return nil, err
		}
	}

	return ret, nil
}

// NewClient is an alias for New.
func NewClient(ctx context.Context, opts ...Option) (*Client, error) {
	return New(ctx, opts...)
}

// Domain returns the normalized Cluster domain.
func (c *Client) Domain() string {
	return c.cfg.domain
}

// APIEndpoint returns the configured gRPC target.
func (c *Client) APIEndpoint() string {
	return c.cfg.apiEndpoint
}

// AccessToken returns a valid bearer token, authenticating or refreshing as
// needed. Concurrent callers share one in-flight token operation.
func (c *Client) AccessToken(ctx context.Context) (string, error) {
	tkn, err := c.Token(ctx)
	if err != nil {
		return "", err
	}
	return tkn.Value, nil
}

// Token returns a valid bearer token and its known expiration time.
func (c *Client) Token(ctx context.Context) (AccessToken, error) {
	if ctx == nil {
		return AccessToken{}, fmt.Errorf("octelium: nil context")
	}
	if err := c.ensureOpen(); err != nil {
		return AccessToken{}, err
	}

	if tkn, ok := c.tokens.current(time.Now()); ok {
		return tkn, nil
	}

	c.tokens.refreshMu.Lock()
	defer c.tokens.refreshMu.Unlock()

	if err := c.ensureOpen(); err != nil {
		return AccessToken{}, err
	}
	if tkn, ok := c.tokens.current(time.Now()); ok {
		return tkn, nil
	}

	if c.cfg.tokenProvider != nil {
		return c.obtainExternalToken(ctx)
	}

	return c.obtainManagedToken(ctx)
}

func (c *Client) obtainExternalToken(ctx context.Context) (AccessToken, error) {
	authCtx, cancel := c.authenticationContext(ctx)
	defer cancel()

	tkn, err := c.cfg.tokenProvider.Token(authCtx)
	if err != nil {
		if current, ok := c.tokens.usable(time.Now()); ok {
			c.cfg.logger.Warn("Could not proactively replace the access token; using the still-valid token", "error", err)
			return current, nil
		}
		return AccessToken{}, &AuthenticationError{Err: err}
	}
	tkn.Value = strings.TrimSpace(tkn.Value)
	if tkn.Value == "" {
		return AccessToken{}, &AuthenticationError{Err: fmt.Errorf("access token provider returned an empty token")}
	}
	if !tkn.Expiry.IsZero() && !time.Now().Before(tkn.Expiry) {
		return AccessToken{}, &AuthenticationError{Err: fmt.Errorf("access token provider returned an expired token")}
	}

	now := time.Now()
	c.tokens.setExternal(tkn, now, defaultRefreshBefore)
	if err := c.ensureOpen(); err != nil {
		return AccessToken{}, err
	}
	ret, ok := c.tokens.current(now)
	if !ok {
		return AccessToken{}, &AuthenticationError{Err: fmt.Errorf("access token became stale immediately")}
	}
	return ret, nil
}

func (c *Client) obtainManagedToken(ctx context.Context) (AccessToken, error) {
	snapshot := c.tokens.snapshot()

	if snapshot.refreshToken != "" {
		tkn, err := c.refreshSession(ctx, snapshot.refreshToken)
		if err == nil {
			return tkn, nil
		}

		if status.Code(err) != codes.Unauthenticated {
			if current, ok := c.tokens.usable(time.Now()); ok {
				c.cfg.logger.Warn("Could not proactively refresh the Session; using the still-valid access token", "error", err)
				return current, nil
			}
			return AccessToken{}, &RefreshError{Err: err}
		}

		c.tokens.clear()
		if !canReauthenticate(c.cfg.authenticator) {
			return AccessToken{}, ErrSessionExpired
		}
	}

	if c.tokens.hasEverAuthenticated() && !canReauthenticate(c.cfg.authenticator) {
		return AccessToken{}, ErrSessionExpired
	}

	return c.authenticate(ctx)
}

func (c *Client) refreshSession(ctx context.Context, previousRefreshToken string) (AccessToken, error) {
	client, err := c.authClient()
	if err != nil {
		return AccessToken{}, err
	}

	authCtx, cancel := c.authenticationContext(ctx)
	defer cancel()

	resp, err := client.AuthenticateWithRefreshToken(authCtx, &authv1.AuthenticateWithRefreshTokenRequest{})
	if err != nil {
		return AccessToken{}, err
	}
	if err := validateSessionToken(resp); err != nil {
		return AccessToken{}, err
	}

	now := time.Now()
	c.tokens.setSession(resp, now, defaultRefreshBefore, previousRefreshToken)
	if err := c.ensureOpen(); err != nil {
		return AccessToken{}, err
	}
	ret, ok := c.tokens.current(now)
	if !ok {
		return AccessToken{}, fmt.Errorf("octelium: refreshed access token became stale immediately")
	}
	return ret, nil
}

func (c *Client) authenticate(ctx context.Context) (AccessToken, error) {
	if c.cfg.authenticator == nil {
		return AccessToken{}, ErrNoCredentials
	}

	client, err := c.authClient()
	if err != nil {
		return AccessToken{}, &AuthenticationError{Err: err}
	}

	authCtx, cancel := c.authenticationContext(ctx)
	defer cancel()

	resp, err := c.cfg.authenticator.Authenticate(authCtx, client, append([]string(nil), c.cfg.scopes...))
	if err != nil {
		return AccessToken{}, &AuthenticationError{Err: err}
	}
	if err := validateSessionToken(resp); err != nil {
		return AccessToken{}, &AuthenticationError{Err: err}
	}

	now := time.Now()
	c.tokens.setSession(resp, now, defaultRefreshBefore, "")
	if err := c.ensureOpen(); err != nil {
		return AccessToken{}, err
	}
	ret, ok := c.tokens.current(now)
	if !ok {
		return AccessToken{}, &AuthenticationError{Err: fmt.Errorf("access token became stale immediately")}
	}
	return ret, nil
}

func validateSessionToken(tkn *authv1.SessionToken) error {
	if tkn == nil {
		return fmt.Errorf("Cluster returned a nil Session token")
	}
	if strings.TrimSpace(tkn.AccessToken) == "" {
		return fmt.Errorf("Cluster returned an empty access token")
	}
	return nil
}

// InvalidateAccessToken causes the next operation to obtain a new access token
// without discarding a managed Session's refresh token.
func (c *Client) InvalidateAccessToken() {
	c.tokens.invalidateAccessToken()
}

// Logout terminates the managed Cluster Session. It does not apply when the
// Client uses an externally managed access token.
func (c *Client) Logout(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("octelium: nil context")
	}
	if c.cfg.tokenProvider != nil {
		return ErrNoManagedSession
	}
	if err := c.ensureOpen(); err != nil {
		return err
	}

	c.tokens.refreshMu.Lock()
	defer c.tokens.refreshMu.Unlock()

	if err := c.ensureOpen(); err != nil {
		return err
	}
	if _, ok := c.tokens.refreshToken(); !ok {
		c.tokens.clear()
		return nil
	}

	client, err := c.authClient()
	if err != nil {
		return err
	}

	authCtx, cancel := c.authenticationContext(ctx)
	defer cancel()

	_, err = client.Logout(authCtx, &authv1.LogoutRequest{})
	if err == nil || status.Code(err) == codes.Unauthenticated {
		c.tokens.clear()
		return nil
	}

	return err
}

// ForgetSession clears local token state without contacting the Cluster.
func (c *Client) ForgetSession() {
	c.tokens.refreshMu.Lock()
	defer c.tokens.refreshMu.Unlock()
	c.tokens.clear()
}

// Close releases connections and owned transports. It does not log out.
func (c *Client) Close() error {
	c.stateMu.Lock()
	if c.closed {
		c.stateMu.Unlock()
		return nil
	}
	c.closed = true
	c.stateMu.Unlock()

	c.tokens.refreshMu.Lock()
	defer c.tokens.refreshMu.Unlock()

	var firstErr error

	c.apiMu.Lock()
	if c.apiConn != nil {
		if err := c.apiConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.apiConn = nil
	}
	c.apiMu.Unlock()

	c.authMu.Lock()
	if c.authConn != nil {
		if err := c.authConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		c.authConn = nil
		c.authC = nil
	}
	c.authMu.Unlock()

	if c.cfg.ownsHTTPTransport {
		if closer, ok := c.httpTransport.(io.Closer); ok {
			if err := closer.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		} else if closer, ok := c.httpTransport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}

	return firstErr
}

func (c *Client) ensureOpen() error {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	if c.closed {
		return ErrClientClosed
	}
	return nil
}

func (c *Client) authenticationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.cfg.authenticationTimeout <= 0 {
		return ctx, func() {}
	}

	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= c.cfg.authenticationTimeout {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, c.cfg.authenticationTimeout)
}

func (c *Client) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            c.cfg.rootCAs,
		ServerName:         serverName,
		InsecureSkipVerify: c.cfg.insecureSkipVerify,
	}
}

func (c *Client) grpcTransportCredentials() grpccredentials.TransportCredentials {
	if c.cfg.grpcCredentials != nil {
		return c.cfg.grpcCredentials
	}
	return grpccredentials.NewTLS(c.tlsConfig(c.cfg.tlsServerName))
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return "", fmt.Errorf("octelium: no Cluster domain was provided")
	}
	if strings.Contains(domain, "://") || strings.ContainsAny(domain, "/?#@") {
		return "", fmt.Errorf("octelium: invalid Cluster domain %q", domain)
	}
	if strings.Contains(domain, ":") {
		return "", fmt.Errorf("octelium: Cluster domain must not contain a port")
	}

	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("octelium: invalid Cluster domain %q: %w", domain, err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", fmt.Errorf("octelium: Cluster domain is too long")
	}
	return ascii, nil
}
