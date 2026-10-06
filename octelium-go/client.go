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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
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

	stateMu     sync.RWMutex
	closed      bool
	closeDone   chan struct{}
	closeErr    error
	lifetimeCtx context.Context
	cancel      context.CancelFunc

	operationMu sync.Mutex
	operation   *tokenOperation
	retryAt     time.Time
	retryDelay  time.Duration
	retryErr    error

	authMu   sync.Mutex
	authConn *grpc.ClientConn
	authC    authv1.MainServiceClient

	apiMu   sync.Mutex
	apiConn *grpc.ClientConn

	httpTransport http.RoundTripper
}

type tokenOperation struct {
	done    chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	isToken bool
	token   tokenValue
	err     error
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

	lifetimeCtx, cancel := context.WithCancel(context.Background())
	ret := &Client{
		cfg:         cfg,
		tokens:      newTokenManager(),
		lifetimeCtx: lifetimeCtx,
		cancel:      cancel,
		closeDone:   make(chan struct{}),
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
	tkn, err := c.token(ctx)
	return tkn.AccessToken, err
}

func (c *Client) token(ctx context.Context) (tokenValue, error) {
	if ctx == nil {
		return tokenValue{}, fmt.Errorf("octelium: nil context")
	}
	for {
		if err := ctx.Err(); err != nil {
			return tokenValue{}, err
		}
		c.operationMu.Lock()
		if err := c.ensureOpen(); err != nil {
			c.operationMu.Unlock()
			return tokenValue{}, err
		}
		if err := ctx.Err(); err != nil {
			c.operationMu.Unlock()
			return tokenValue{}, err
		}
		now := time.Now()
		if tkn, ok := c.tokens.current(now); ok {
			c.operationMu.Unlock()
			return tkn, nil
		}
		op := c.operation
		if op == nil {
			if now.Before(c.retryAt) {
				tkn, ok := c.tokens.usable(now)
				err := c.retryErr
				c.operationMu.Unlock()
				if ok {
					return tkn, nil
				}
				return tokenValue{}, err
			}
			opCtx, cancel := c.operationContext(ctx)
			op = &tokenOperation{done: make(chan struct{}), ctx: opCtx, cancel: cancel, isToken: true}
			c.operation = op
			go c.runTokenOperation(op)
		}
		c.operationMu.Unlock()

		if err := c.waitOperation(ctx, op); err != nil {
			if op.isToken && errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				if current, ok := c.tokens.usable(time.Now()); ok {
					return current, nil
				}
			}
			return tokenValue{}, err
		}
		if op.isToken {
			return op.token, op.err
		}
	}
}

func (c *Client) waitOperation(ctx context.Context, op *tokenOperation) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.lifetimeCtx.Done():
		return ErrClientClosed
	case <-op.ctx.Done():
		select {
		case <-op.done:
			if err := ctx.Err(); err != nil {
				return err
			}
			return c.ensureOpen()
		default:
		}
		if err := c.ensureOpen(); err != nil {
			return err
		}
		return op.ctx.Err()
	case <-op.done:
		if err := ctx.Err(); err != nil {
			return err
		}
		return c.ensureOpen()
	}
}

func (c *Client) runTokenOperation(op *tokenOperation) {
	defer op.cancel()

	var tkn tokenValue
	var err error
	if c.cfg.tokenProvider != nil {
		tkn, err = c.obtainExternalToken(op.ctx)
	} else {
		tkn, err = c.obtainManagedToken(op.ctx)
	}

	c.operationMu.Lock()
	var fallbackErr error
	if contextErr := op.ctx.Err(); contextErr != nil {
		err = contextErr
	}
	closedErr := c.ensureOpen()
	if closedErr != nil {
		err = closedErr
	}
	if err != nil {
		tkn = tokenValue{}
		if op.ctx.Err() != context.Canceled && closedErr == nil {
			if c.retryDelay == 0 {
				c.retryDelay = time.Second
			} else {
				c.retryDelay = min(2*c.retryDelay, 30*time.Second)
			}
			c.retryAt = time.Now().Add(c.retryDelay/2 + time.Duration(rand.Int64N(int64(c.retryDelay/2))))
			c.retryErr = err
			if current, ok := c.tokens.usable(time.Now()); ok {
				fallbackErr = err
				tkn, err = current, nil
			}
		}
	} else {
		c.resetRetry()
	}
	op.token, op.err = tkn, err
	c.operation = nil
	close(op.done)
	c.operationMu.Unlock()
	if fallbackErr != nil {
		c.cfg.logger.Warn("Could not proactively replace the access token; using the still-valid token", "error", fallbackErr)
	}
}

func (c *Client) obtainExternalToken(ctx context.Context) (tokenValue, error) {
	tkn, err := c.cfg.tokenProvider.Token(ctx)
	if err != nil {
		return tokenValue{}, &AuthenticationError{Err: err}
	}
	tkn.Value = strings.TrimSpace(tkn.Value)
	if tkn.Value == "" {
		return tokenValue{}, &AuthenticationError{Err: fmt.Errorf("access token provider returned an empty token")}
	}

	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return tokenValue{}, err
	}
	if err := ctx.Err(); err != nil {
		return tokenValue{}, err
	}
	now := time.Now()
	if !tkn.Expiry.IsZero() && !now.Before(tkn.Expiry) {
		return tokenValue{}, &AuthenticationError{Err: fmt.Errorf("access token provider returned an expired token")}
	}
	c.tokens.setExternal(tkn, now, defaultRefreshBefore)
	ret, ok := c.tokens.usable(time.Now())
	if !ok {
		return tokenValue{}, &AuthenticationError{Err: fmt.Errorf("access token became expired immediately")}
	}
	return ret, nil
}

func (c *Client) obtainManagedToken(ctx context.Context) (tokenValue, error) {
	snapshot := c.tokens.snapshot()
	if snapshot.refreshToken != "" {
		if !snapshot.refreshExpiresAt.IsZero() && !time.Now().Before(snapshot.refreshExpiresAt) {
			c.tokens.clear()
		} else {
			tkn, err := c.refreshSession(ctx)
			if err == nil {
				return tkn, nil
			}
			if status.Code(err) != codes.Unauthenticated {
				return tokenValue{}, &RefreshError{Err: err}
			}
			c.tokens.clear()
		}
		if !canReauthenticate(c.cfg.authenticator) {
			return tokenValue{}, ErrSessionExpired
		}
	}
	if c.tokens.hasAttemptedAuthentication() && !canReauthenticate(c.cfg.authenticator) {
		return tokenValue{}, ErrSessionExpired
	}
	return c.authenticate(ctx)
}

func (c *Client) refreshSession(ctx context.Context) (tokenValue, error) {
	client, err := c.authClient()
	if err != nil {
		return tokenValue{}, err
	}
	started := time.Now()
	resp, err := client.AuthenticateWithRefreshToken(ctx, &authv1.AuthenticateWithRefreshTokenRequest{})
	if err != nil {
		return tokenValue{}, err
	}
	return c.installSession(ctx, resp, started)
}

func (c *Client) authenticate(ctx context.Context) (tokenValue, error) {
	if c.cfg.authenticator == nil {
		return tokenValue{}, ErrNoCredentials
	}
	client, err := c.authClient()
	if err != nil {
		return tokenValue{}, &AuthenticationError{Err: err}
	}
	if err := ctx.Err(); err != nil {
		return tokenValue{}, err
	}
	c.tokens.markAuthenticationAttempt()
	started := time.Now()
	resp, err := c.cfg.authenticator.Authenticate(ctx, client, append([]string(nil), c.cfg.scopes...))
	if err != nil {
		return tokenValue{}, &AuthenticationError{Err: err}
	}
	tkn, err := c.installSession(ctx, resp, started)
	if err != nil {
		return tokenValue{}, &AuthenticationError{Err: err}
	}
	return tkn, nil
}

func (c *Client) installSession(ctx context.Context, resp *authv1.SessionToken, started time.Time) (tokenValue, error) {
	if err := validateSessionToken(resp); err != nil {
		return tokenValue{}, err
	}
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if err := c.ensureOpen(); err != nil {
		return tokenValue{}, err
	}
	if err := ctx.Err(); err != nil {
		return tokenValue{}, err
	}
	if !time.Now().Before(started.Add(time.Duration(resp.ExpiresIn) * time.Second)) {
		return tokenValue{}, fmt.Errorf("octelium: Session access token expired during authentication")
	}
	c.tokens.setSession(resp, started, defaultRefreshBefore)
	ret, ok := c.tokens.usable(time.Now())
	if !ok {
		return tokenValue{}, fmt.Errorf("octelium: Session access token became expired immediately")
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
	if strings.TrimSpace(tkn.RefreshToken) == "" {
		return fmt.Errorf("Cluster returned an empty refresh token")
	}
	maxSeconds := int64(math.MaxInt64) / int64(time.Second)
	if tkn.ExpiresIn <= 0 || tkn.ExpiresIn > maxSeconds {
		return fmt.Errorf("Cluster returned an invalid access token lifetime")
	}
	if tkn.RefreshTokenExpiresIn <= 0 || tkn.RefreshTokenExpiresIn > maxSeconds || tkn.RefreshTokenExpiresIn < tkn.ExpiresIn {
		return fmt.Errorf("Cluster returned an invalid refresh token lifetime")
	}
	return nil
}

// InvalidateAccessToken causes the next operation to obtain a new access token
// without discarding a managed Session's refresh token.
func (c *Client) InvalidateAccessToken() {
	c.invalidateAccessToken(0)
}

func (c *Client) invalidateAccessToken(generation uint64) {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if c.tokens.invalidateAccessToken(generation) {
		c.resetRetry()
	}
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
	authCtx, cancel := c.authenticationContext(ctx)
	defer cancel()
	for {
		if err := authCtx.Err(); err != nil {
			return err
		}
		c.operationMu.Lock()
		if err := c.ensureOpen(); err != nil {
			c.operationMu.Unlock()
			return err
		}
		if op := c.operation; op != nil {
			c.operationMu.Unlock()
			if err := c.waitOperation(authCtx, op); err != nil {
				return err
			}
			if !op.isToken {
				return op.err
			}
			continue
		}
		if _, ok := c.tokens.refreshToken(); !ok {
			c.tokens.clear()
			c.resetRetry()
			c.operationMu.Unlock()
			return nil
		}
		opCtx, opCancel := c.requestContext(authCtx)
		op := &tokenOperation{done: make(chan struct{}), ctx: opCtx, cancel: opCancel}
		c.operation = op
		c.operationMu.Unlock()
		defer opCancel()

		client, err := c.authClient()
		if err == nil {
			_, err = client.Logout(opCtx, &authv1.LogoutRequest{})
		}
		c.operationMu.Lock()
		if err == nil || status.Code(err) == codes.Unauthenticated {
			c.tokens.clear()
			c.resetRetry()
			err = nil
		}
		op.err = err
		c.operation = nil
		close(op.done)
		c.operationMu.Unlock()
		return err
	}
}

// ForgetSession clears local token state without contacting the Cluster.
func (c *Client) ForgetSession() {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if c.operation != nil {
		c.operation.cancel()
	}
	c.tokens.clear()
	c.resetRetry()
}

func (c *Client) resetRetry() {
	c.retryAt = time.Time{}
	c.retryDelay = 0
	c.retryErr = nil
}

// Close releases connections and owned transports. It does not log out.
func (c *Client) Close() error {
	c.stateMu.Lock()
	if c.closed {
		done := c.closeDone
		c.stateMu.Unlock()
		<-done
		c.stateMu.RLock()
		defer c.stateMu.RUnlock()
		return c.closeErr
	}
	c.closed = true
	c.stateMu.Unlock()
	c.cancel()

	c.operationMu.Lock()
	if c.operation != nil {
		c.operation.cancel()
	}
	c.tokens.clear()
	c.resetRetry()
	c.operationMu.Unlock()

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

	c.stateMu.Lock()
	c.closeErr = firstErr
	close(c.closeDone)
	c.stateMu.Unlock()
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

func (c *Client) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ret, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.lifetimeCtx, cancel)
	return ret, func() {
		stop()
		cancel()
	}
}

func (c *Client) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ret, cancel := c.requestContext(context.WithoutCancel(ctx))
	ret, timeoutCancel := c.authenticationContext(ret)
	return ret, func() {
		timeoutCancel()
		cancel()
	}
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
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
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
