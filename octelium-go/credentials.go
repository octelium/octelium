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
	"os"
	"strings"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"golang.org/x/oauth2"
)

// Authenticator creates a Cluster Session. It is intentionally exported so
// applications can add authentication methods introduced after this SDK
// release without waiting for a new octelium-go version.
type Authenticator interface {
	Authenticate(ctx context.Context, client authv1.MainServiceClient, scopes []string) (*authv1.SessionToken, error)
}

// Reauthenticator is implemented by authenticators that can safely create a
// replacement Session after a refresh token has become invalid.
//
// One-time authentication tokens deliberately do not implement this behavior.
type Reauthenticator interface {
	Authenticator
	CanReauthenticate() bool
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(context.Context, authv1.MainServiceClient, []string) (*authv1.SessionToken, error)

func (f AuthenticatorFunc) Authenticate(
	ctx context.Context,
	client authv1.MainServiceClient,
	scopes []string,
) (*authv1.SessionToken, error) {
	if f == nil {
		return nil, fmt.Errorf("octelium: nil authenticator function")
	}
	return f(ctx, client, scopes)
}

type authenticationTokenAuthenticator struct {
	token string
}

// AuthenticationToken exchanges a Credential authentication token for a
// Cluster Session. Authentication tokens are treated as one-time credentials
// and are never reused automatically after the Session expires.
func AuthenticationToken(token string) Authenticator {
	return &authenticationTokenAuthenticator{token: strings.TrimSpace(token)}
}

func (a *authenticationTokenAuthenticator) Authenticate(
	ctx context.Context,
	client authv1.MainServiceClient,
	scopes []string,
) (*authv1.SessionToken, error) {
	if a == nil || a.token == "" {
		return nil, fmt.Errorf("octelium: empty authentication token")
	}

	return client.AuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
		AuthenticationToken: a.token,
		Scopes:              append([]string(nil), scopes...),
	})
}

func (*authenticationTokenAuthenticator) CanReauthenticate() bool {
	return false
}

type assertionAuthenticator struct {
	provider func(context.Context) (string, error)
	reusable bool
}

// Assertion authenticates with a freshly obtained signed assertion. The
// provider is called for every authentication attempt, so this authenticator
// can replace an expired Session.
func Assertion(provider func(context.Context) (string, error)) Authenticator {
	return &assertionAuthenticator{
		provider: provider,
		reusable: true,
	}
}

// OIDCAssertion is an alias for Assertion.
func OIDCAssertion(provider func(context.Context) (string, error)) Authenticator {
	return Assertion(provider)
}

// OIDCAssertionFromFile is an alias for AssertionFromFile.
func OIDCAssertionFromFile(path string) Authenticator {
	return AssertionFromFile(path)
}

// StaticAssertion authenticates with one fixed assertion. It is not reused
// automatically because assertions are commonly short lived or replay
// protected.
func StaticAssertion(assertion string) Authenticator {
	value := strings.TrimSpace(assertion)
	return &assertionAuthenticator{
		provider: func(context.Context) (string, error) {
			return value, nil
		},
	}
}

// AssertionFromFile reads the assertion on every authentication. This is
// suitable for Kubernetes projected ServiceAccount tokens and similar files
// that are atomically rotated by the surrounding platform.
func AssertionFromFile(path string) Authenticator {
	return &assertionAuthenticator{
		reusable: true,
		provider: func(context.Context) (string, error) {
			b, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(b)), nil
		},
	}
}

func (a *assertionAuthenticator) Authenticate(
	ctx context.Context,
	client authv1.MainServiceClient,
	scopes []string,
) (*authv1.SessionToken, error) {
	if a == nil || a.provider == nil {
		return nil, fmt.Errorf("octelium: no assertion provider was configured")
	}

	assertion, err := a.provider(ctx)
	if err != nil {
		return nil, err
	}
	assertion = strings.TrimSpace(assertion)
	if assertion == "" {
		return nil, fmt.Errorf("octelium: empty assertion")
	}

	return client.AuthenticateWithAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
		Assertion: assertion,
		Scopes:    append([]string(nil), scopes...),
	})
}

func (a *assertionAuthenticator) CanReauthenticate() bool {
	return a != nil && a.reusable
}

// AccessToken contains a bearer token supplied by an external identity system.
type AccessToken struct {
	Value  string
	Expiry time.Time
}

// AccessTokenProvider supplies externally managed Octelium access tokens. It
// must be safe for concurrent use.
type AccessTokenProvider interface {
	Token(ctx context.Context) (AccessToken, error)
}

// AccessTokenProviderFunc adapts a function to AccessTokenProvider.
type AccessTokenProviderFunc func(context.Context) (AccessToken, error)

func (f AccessTokenProviderFunc) Token(ctx context.Context) (AccessToken, error) {
	if f == nil {
		return AccessToken{}, fmt.Errorf("octelium: nil access token provider")
	}
	return f(ctx)
}

type staticAccessTokenProvider struct {
	token AccessToken
}

// StaticAccessToken returns a provider for an externally managed token with no
// known expiration time.
func StaticAccessToken(token string) AccessTokenProvider {
	return &staticAccessTokenProvider{token: AccessToken{Value: strings.TrimSpace(token)}}
}

func (p *staticAccessTokenProvider) Token(context.Context) (AccessToken, error) {
	if p == nil || p.token.Value == "" {
		return AccessToken{}, fmt.Errorf("octelium: empty access token")
	}
	return p.token, nil
}

type oauth2AccessTokenProvider struct {
	source oauth2.TokenSource
}

// OAuth2AccessTokenProvider adapts an oauth2.TokenSource, including client
// credentials, workload identity and other OAuth2 flows, to this SDK.
func OAuth2AccessTokenProvider(source oauth2.TokenSource) AccessTokenProvider {
	return &oauth2AccessTokenProvider{source: source}
}

func (p *oauth2AccessTokenProvider) Token(context.Context) (AccessToken, error) {
	if p == nil || p.source == nil {
		return AccessToken{}, fmt.Errorf("octelium: nil OAuth2 token source")
	}

	tkn, err := p.source.Token()
	if err != nil {
		return AccessToken{}, err
	}
	if tkn == nil {
		return AccessToken{}, fmt.Errorf("octelium: OAuth2 token source returned nil")
	}

	return AccessToken{
		Value:  strings.TrimSpace(tkn.AccessToken),
		Expiry: tkn.Expiry,
	}, nil
}

func canReauthenticate(authenticator Authenticator) bool {
	v, ok := authenticator.(Reauthenticator)
	return ok && v.CanReauthenticate()
}
