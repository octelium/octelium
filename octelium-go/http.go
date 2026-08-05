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
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/oauth2"
)

const (
	defaultHTTPDialTimeout      = 20 * time.Second
	defaultHTTPKeepAlive        = 30 * time.Second
	defaultHTTPIdleConnTimeout  = 90 * time.Second
	defaultHTTPMaxIdleConns     = 128
	defaultHTTPMaxIdlePerHost   = 32
	defaultHTTPHandshakeTimeout = 10 * time.Second
)

func (c *Client) newHTTPTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   defaultHTTPDialTimeout,
		KeepAlive: defaultHTTPKeepAlive,
	}

	return &http.Transport{
		TLSClientConfig:     c.tlsConfig(""),
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: defaultHTTPHandshakeTimeout,
		IdleConnTimeout:     defaultHTTPIdleConnTimeout,
		MaxIdleConns:        defaultHTTPMaxIdleConns,
		MaxIdleConnsPerHost: defaultHTTPMaxIdlePerHost,
	}
}

// HTTPClient returns an HTTP client that attaches the access token only to
// destinations accepted by the configured authorization policy. Each call
// returns a distinct http.Client sharing the Client's connection pool.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{Transport: c.HTTPTransport()}
}

// HTTPTransport returns an authenticated RoundTripper suitable for embedding
// in a custom http.Client.
func (c *Client) HTTPTransport() http.RoundTripper {
	return &authRoundTripper{
		client: c,
		base:   c.httpTransport,
	}
}

// TokenSource returns a concurrency-safe oauth2.TokenSource. Authentication
// calls use a background context bounded by the configured authentication
// timeout.
func (c *Client) TokenSource() oauth2.TokenSource {
	return &oauth2TokenSource{client: c}
}

// TokenSourceContext returns an oauth2.TokenSource using the supplied context.
// The context must remain valid for the lifetime of the TokenSource.
func (c *Client) TokenSourceContext(ctx context.Context) oauth2.TokenSource {
	return &oauth2TokenSource{client: c, ctx: ctx}
}

type authRoundTripper struct {
	client *Client
	base   http.RoundTripper
}

func (r *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("octelium: invalid HTTP request")
	}
	if r == nil || r.client == nil || r.base == nil {
		return nil, fmt.Errorf("octelium: invalid authenticated HTTP transport")
	}

	if err := r.client.authorizeHTTPRequest(req); err != nil {
		return nil, &HTTPAuthorizationError{URL: req.URL.Redacted(), Err: err}
	}

	accessToken, err := r.client.AccessToken(req.Context())
	if err != nil {
		return nil, err
	}

	// RoundTripper implementations must not mutate the caller's request. Clone
	// also deep-copies the Header map while retaining the streaming Body.
	out := req.Clone(req.Context())
	out.Header.Set("Authorization", "Bearer "+accessToken)
	if out.Header.Get("User-Agent") == "" {
		out.Header.Set("User-Agent", r.client.cfg.userAgent)
	}

	return r.base.RoundTrip(out)
}

func (c *Client) authorizeHTTPRequest(req *http.Request) error {
	if c.cfg.httpAuthPolicy != nil {
		return c.cfg.httpAuthPolicy(req)
	}

	if req.URL.User != nil {
		return fmt.Errorf("URL userinfo is not allowed")
	}

	scheme := strings.ToLower(req.URL.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !c.cfg.allowInsecureHTTP {
			return fmt.Errorf("plain HTTP is disabled")
		}
	default:
		return fmt.Errorf("unsupported URL scheme %q", req.URL.Scheme)
	}

	host, err := normalizeHTTPHost(req.URL.Hostname())
	if err != nil {
		return err
	}

	if host == c.cfg.domain || strings.HasSuffix(host, "."+c.cfg.domain) {
		return nil
	}

	for _, allowed := range c.cfg.authorizedHTTPHosts {
		if host == allowed {
			return nil
		}
	}

	return fmt.Errorf("host %q is outside the Cluster domain", host)
}

func normalizeHTTPHost(host string) (string, error) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", fmt.Errorf("empty HTTP host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return strings.ToLower(host), nil
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", err
	}
	return strings.ToLower(ascii), nil
}

type oauth2TokenSource struct {
	client *Client
	ctx    context.Context
}

func (s *oauth2TokenSource) Token() (*oauth2.Token, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("octelium: invalid OAuth2 token source")
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	tkn, err := s.client.Token(ctx)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken: tkn.Value,
		TokenType:   "Bearer",
		Expiry:      tkn.Expiry,
	}, nil
}
