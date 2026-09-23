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

package authenticator

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/common/clientlogin"
	"github.com/octelium/octelium/pkg/common/opkce"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/pkg/errors"
)

type AppAuthenticatorOpts struct {
	Domain string
	Scopes []string
}

type AppAuthenticator struct {
	domain        string
	scopes        []string
	loginURL      string
	codeVerifier  []byte
	codeChallenge []byte

	mu          sync.Mutex
	isCompleted bool
	respCh      chan *authv1.ClientLoginResponse
}

func NewAppAuthenticator(opts *AppAuthenticatorOpts) (*AppAuthenticator, error) {
	if opts == nil || opts.Domain == "" {
		return nil, errors.Errorf("The Cluster domain is not set")
	}

	codeVerifier, err := opkce.NewVerifier()
	if err != nil {
		return nil, err
	}

	return &AppAuthenticator{
		domain:        opts.Domain,
		scopes:        opts.Scopes,
		loginURL:      fmt.Sprintf("https://%s/login", opts.Domain),
		codeVerifier:  codeVerifier,
		codeChallenge: opkce.GetChallenge(codeVerifier),
		respCh:        make(chan *authv1.ClientLoginResponse, 1),
	}, nil
}

func (s *AppAuthenticator) GetLoginURL() string {
	u, _ := url.Parse(s.loginURL)

	q := u.Query()

	req := &authv1.ClientLoginRequest{
		ApiVersion:    authv1.ClientLoginRequest_V1,
		CodeChallenge: s.codeChallenge,
		CallbackType:  authv1.ClientLoginRequest_APP,
	}

	reqBytes, _ := pbutils.Marshal(req)

	q.Set("octelium_req", base64.RawURLEncoding.EncodeToString(reqBytes))

	u.RawQuery = q.Encode()

	return u.String()
}

func (s *AppAuthenticator) GetLoginResponse(callbackURL string) (*authv1.ClientLoginResponse, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return nil, err
	}

	if u.Scheme != clientlogin.AppCallbackScheme || u.Host != "" || u.User != nil ||
		u.Opaque != "" || u.Path != clientlogin.AppCallbackPath {
		return nil, errors.Errorf("Invalid callback URL")
	}

	respBytes, err := base64.RawURLEncoding.DecodeString(u.Query().Get("octelium_response"))
	if err != nil {
		return nil, err
	}

	resp := &authv1.ClientLoginResponse{}
	if err := pbutils.Unmarshal(respBytes, resp); err != nil {
		return nil, err
	}

	if resp.AuthenticationToken == "" {
		return nil, errors.Errorf("No authentication token is set")
	}

	if !utils.SecureBytesEqual(resp.CodeChallenge, s.codeChallenge) {
		return nil, errors.Errorf("The callback does not belong to this authentication")
	}

	return resp, nil
}

func (s *AppAuthenticator) Complete(resp *authv1.ClientLoginResponse) error {
	if resp == nil {
		return errors.Errorf("Nil login response")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isCompleted {
		return errors.Errorf("The authentication is already completed")
	}

	s.isCompleted = true
	s.respCh <- resp

	return nil
}

func (s *AppAuthenticator) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(WebAuthenticationTimeout):
		return ErrWebAuthenticationTimedOut
	case resp := <-s.respCh:
		return s.doAuthenticate(ctx, resp)
	}
}

func (s *AppAuthenticator) doAuthenticate(ctx context.Context, resp *authv1.ClientLoginResponse) error {
	if isAuthProxyMode() || isStaticAccessToken() {
		return nil
	}

	authC, err := newAuthenticator(ctx, &AuthenticateOpts{
		Domain:       s.domain,
		AuthToken:    resp.AuthenticationToken,
		CodeVerifier: s.codeVerifier,
		Scopes:       s.scopes,
	})
	if err != nil {
		return err
	}

	authC.isRefresh = false
	authC.isAuthentication = true

	return authC.run(ctx)
}
