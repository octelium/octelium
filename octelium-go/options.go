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
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/grpc"
	grpccredentials "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	defaultUserAgent             = "octelium-go"
	defaultAuthenticationTimeout = 20 * time.Second

	// defaultRefreshBefore is how long before expiration a token is replaced.
	// newTokenSnapshot caps it at 20% of a short token's lifetime, so the
	// effective leeway is always the smaller of the two.
	defaultRefreshBefore = 30 * time.Second
)

// HTTPAuthorizationPolicy decides whether an HTTP request may receive the
// Octelium access token. Returning an error rejects the request before any
// network operation occurs.
type HTTPAuthorizationPolicy func(*http.Request) error

type config struct {
	domain        string
	apiEndpoint   string
	tlsServerName string
	scopes        []string

	authenticator Authenticator
	tokenProvider AccessTokenProvider

	useEnvironment bool

	userAgent string
	logger    *slog.Logger

	rootCAs            *x509.CertPool
	insecureSkipVerify bool
	grpcCredentials    grpccredentials.TransportCredentials

	httpTransport       http.RoundTripper
	ownsHTTPTransport   bool
	httpAuthPolicy      HTTPAuthorizationPolicy
	authorizedHTTPHosts []string
	allowInsecureHTTP   bool

	grpcDialOptions   []grpc.DialOption
	grpcServiceConfig string
	grpcKeepalive     *keepalive.ClientParameters

	authenticationTimeout time.Duration
	authenticateOnCreate  bool
}

// Option configures a Client.
type Option func(*config) error

// WithDomain sets the Cluster domain, for example example.com or
// octelium.example.com.
func WithDomain(domain string) Option {
	return func(c *config) error {
		c.domain = domain
		return nil
	}
}

// WithAPIEndpoint overrides the gRPC target. It accepts any target supported by
// grpc.NewClient, such as dns:///host:443 or passthrough:///bufnet.
func WithAPIEndpoint(target string) Option {
	return func(c *config) error {
		if target == "" {
			return fmt.Errorf("octelium: empty API endpoint")
		}
		c.apiEndpoint = target
		return nil
	}
}

// WithTLSServerName overrides the name verified in the Cluster certificate.
// This is useful when WithAPIEndpoint points at an IP, port forward or local
// proxy while the certificate remains valid for octelium-api.<domain>.
func WithTLSServerName(name string) Option {
	return func(c *config) error {
		if name == "" {
			return fmt.Errorf("octelium: empty TLS server name")
		}
		c.tlsServerName = name
		return nil
	}
}

// WithScopes limits the access permissions of the resulting Session.
func WithScopes(scopes ...string) Option {
	return func(c *config) error {
		c.scopes = append([]string(nil), scopes...)
		return nil
	}
}

// WithAuthenticator configures a Cluster Session authentication method.
func WithAuthenticator(authenticator Authenticator) Option {
	return func(c *config) error {
		if authenticator == nil {
			return fmt.Errorf("octelium: nil authenticator")
		}
		c.authenticator = authenticator
		return nil
	}
}

// WithAccessTokenProvider configures externally managed access tokens. It is
// mutually exclusive with WithAuthenticator.
func WithAccessTokenProvider(provider AccessTokenProvider) Option {
	return func(c *config) error {
		if provider == nil {
			return fmt.Errorf("octelium: nil access token provider")
		}
		c.tokenProvider = provider
		return nil
	}
}

// WithAccessToken configures one externally managed access token.
func WithAccessToken(token string) Option {
	return WithAccessTokenProvider(StaticAccessToken(token))
}

// WithoutEnvironmentCredentials disables the default environment credential
// chain.
func WithoutEnvironmentCredentials() Option {
	return func(c *config) error {
		c.useEnvironment = false
		return nil
	}
}

// WithUserAgent overrides the user agent sent to the Cluster.
func WithUserAgent(userAgent string) Option {
	return func(c *config) error {
		if userAgent == "" {
			return fmt.Errorf("octelium: empty user agent")
		}
		c.userAgent = userAgent
		return nil
	}
}

// WithLogger installs a structured logger. The Client is silent by default.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) error {
		if logger == nil {
			return fmt.Errorf("octelium: nil logger")
		}
		c.logger = logger
		return nil
	}
}

// WithRootCAs verifies the Cluster certificate against the supplied pool.
func WithRootCAs(pool *x509.CertPool) Option {
	return func(c *config) error {
		if pool == nil {
			return fmt.Errorf("octelium: nil certificate pool")
		}
		c.rootCAs = pool.Clone()
		return nil
	}
}

// WithInsecureSkipVerify disables certificate verification. It should be used
// only for local development.
func WithInsecureSkipVerify() Option {
	return func(c *config) error {
		c.insecureSkipVerify = true
		return nil
	}
}

// WithGRPCTransportCredentials replaces the default TLS credentials. This is
// primarily useful for tests and non-TCP transports.
func WithGRPCTransportCredentials(creds grpccredentials.TransportCredentials) Option {
	return func(c *config) error {
		if creds == nil {
			return fmt.Errorf("octelium: nil gRPC transport credentials")
		}
		c.grpcCredentials = creds
		return nil
	}
}

// WithHTTPTransport installs a caller-owned transport. Close does not close it.
func WithHTTPTransport(transport http.RoundTripper) Option {
	return func(c *config) error {
		if transport == nil {
			return fmt.Errorf("octelium: nil HTTP transport")
		}
		c.httpTransport = transport
		return nil
	}
}

// WithAuthorizedHTTPHosts permits the listed exact hostnames to receive the
// access token in addition to the Cluster domain and its subdomains.
func WithAuthorizedHTTPHosts(hosts ...string) Option {
	return func(c *config) error {
		c.authorizedHTTPHosts = append(c.authorizedHTTPHosts, hosts...)
		return nil
	}
}

// WithHTTPAuthorizationPolicy replaces the default destination policy.
func WithHTTPAuthorizationPolicy(policy HTTPAuthorizationPolicy) Option {
	return func(c *config) error {
		if policy == nil {
			return fmt.Errorf("octelium: nil HTTP authorization policy")
		}
		c.httpAuthPolicy = policy
		return nil
	}
}

// WithAllowInsecureHTTP permits bearer tokens over plain HTTP to destinations
// accepted by the authorization policy. It should normally be limited to local
// development environments.
func WithAllowInsecureHTTP() Option {
	return func(c *config) error {
		c.allowInsecureHTTP = true
		return nil
	}
}

// WithGRPCDialOptions appends advanced options to both gRPC connections.
func WithGRPCDialOptions(opts ...grpc.DialOption) Option {
	return func(c *config) error {
		c.grpcDialOptions = append(c.grpcDialOptions, opts...)
		return nil
	}
}

// WithGRPCDefaultServiceConfig installs an explicit service config. The SDK
// deliberately has no broad retry policy by default because Cluster APIs
// include non-idempotent operations.
func WithGRPCDefaultServiceConfig(serviceConfig string) Option {
	return func(c *config) error {
		if serviceConfig == "" {
			return fmt.Errorf("octelium: empty gRPC service config")
		}
		c.grpcServiceConfig = serviceConfig
		return nil
	}
}

// WithGRPCKeepalive configures client HTTP/2 PING behavior. It is unset by
// default to avoid violating an upstream server's minimum PING interval.
func WithGRPCKeepalive(params keepalive.ClientParameters) Option {
	return func(c *config) error {
		c.grpcKeepalive = &params
		return nil
	}
}

// WithAuthenticationTimeout bounds authentication and refresh calls when the
// caller's context has no earlier deadline. Zero disables the SDK timeout.
func WithAuthenticationTimeout(timeout time.Duration) Option {
	return func(c *config) error {
		if timeout < 0 {
			return fmt.Errorf("octelium: negative authentication timeout")
		}
		c.authenticationTimeout = timeout
		return nil
	}
}

// WithAuthenticateOnCreate validates credentials during New.
func WithAuthenticateOnCreate() Option {
	return func(c *config) error {
		c.authenticateOnCreate = true
		return nil
	}
}
