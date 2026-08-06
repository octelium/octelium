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
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/common/opkce"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const callbackSuffixLen = 8

type webAuthenticator struct {
	server              *http.Server
	listeners           []net.Listener
	ch                  chan bool
	port                int
	successCallbackPath string
	domain              string
	domainRoot          string
	callbackSuffix      string
	scopes              []string
	loginURL            string
	codeVerifier        []byte
	codeChallenge       []byte
	err                 error
	closeOnce           sync.Once
}

func newWebAuthenticator(domain string, scopes []string) (*webAuthenticator, error) {

	suffix := utilrand.GetRandomString(callbackSuffixLen)

	zap.L().Debug("Creating new webAuthenticator", zap.String("pathSuffix", suffix))

	codeVerifier, err := opkce.NewVerifier()
	if err != nil {
		return nil, err
	}

	return &webAuthenticator{
		domain:              domain,
		domainRoot:          fmt.Sprintf("https://%s", domain),
		ch:                  make(chan bool),
		successCallbackPath: fmt.Sprintf("/callback/success/%s", suffix),
		callbackSuffix:      suffix,
		loginURL:            fmt.Sprintf("https://%s/login", domain),
		scopes:              scopes,
		codeVerifier:        codeVerifier,
		codeChallenge:       opkce.GetChallenge(codeVerifier),
	}, nil
}

func (s *webAuthenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	zap.L().Debug("Received request at auth federation server")

	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	resp, err := s.getLoginResponse(r)
	if err != nil {
		zap.L().Debug("Ignoring an invalid callback request", zap.Error(err))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err = s.doAuthenticate(r.Context(), resp)

	defer s.closeOnce.Do(func() {
		s.err = err
		close(s.ch)
	})

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, s.domainRoot, http.StatusFound)
}

func (s *webAuthenticator) getLoginResponse(r *http.Request) (*authv1.ClientLoginResponse, error) {
	respBytes, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("octelium_response"))
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

	return resp, nil
}

func (s *webAuthenticator) doAuthenticate(ctx context.Context, resp *authv1.ClientLoginResponse) error {
	if len(resp.CodeChallenge) == 0 {
		cliutils.LineWarn(
			"This Cluster does not support verified client logins. Please ask your Cluster administrators to upgrade it.\n")
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

	return authC.run(ctx)
}

func (s *webAuthenticator) getLoginURL() string {
	u, _ := url.Parse(s.loginURL)

	q := u.Query()

	req := &authv1.ClientLoginRequest{
		ApiVersion:     authv1.ClientLoginRequest_V1,
		CallbackPort:   uint32(s.port),
		CallbackSuffix: s.callbackSuffix,
		CodeChallenge:  s.codeChallenge,
	}

	reqBytes, _ := pbutils.Marshal(req)

	q.Set("octelium_req", base64.RawURLEncoding.EncodeToString(reqBytes))

	u.RawQuery = q.Encode()

	return u.String()
}

func (s *webAuthenticator) listen() error {
	const maxAttempts = 5

	for range maxAttempts {
		l4, err4 := net.Listen("tcp4", "127.0.0.1:0")
		if err4 != nil {
			l6, err6 := net.Listen("tcp6", "[::1]:0")
			if err6 != nil {
				return errors.Errorf(
					"could not bind to a local port for authentication callback: %+v", err6)
			}

			s.listeners = []net.Listener{l6}
			s.port = l6.Addr().(*net.TCPAddr).Port
			return nil
		}

		port := l4.Addr().(*net.TCPAddr).Port

		l6, err6 := net.Listen("tcp6", net.JoinHostPort("::1", fmt.Sprintf("%d", port)))
		if err6 != nil {
			zap.L().Debug("Could not bind the IPv6 loopback. Retrying with another port",
				zap.Int("port", port), zap.Error(err6))
			l4.Close()
			continue
		}

		s.listeners = []net.Listener{l4, l6}
		s.port = port
		return nil
	}

	return errors.Errorf("could not bind to a local port for authentication callback")
}

func (s *webAuthenticator) run(_ context.Context) error {

	if err := s.listen(); err != nil {
		return err
	}

	mux := http.NewServeMux()

	mux.Handle(s.successCallbackPath, s)

	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			zap.L().Debug("Error shutting down web authentication server", zap.Error(err))
		}
	}()

	serverErrCh := make(chan error, 1)
	for _, lis := range s.listeners {
		go func(lis net.Listener) {
			if err := s.server.Serve(lis); err != nil && err != http.ErrServerClosed {
				serverErrCh <- err
			}
		}(lis)
	}

	select {
	case <-time.After(100 * time.Millisecond):
	case err := <-serverErrCh:
		return errors.Errorf("Could not start auth callback server: %+v", err)
	}

	cmd, err := cliutils.OpenFileByDefaultAppCmd(s.getLoginURL())
	if err != nil {
		return err
	}

	go func() {
		zap.L().Debug("running the browser to authenticate user")
		if err := cmd.Run(); err != nil {
			zap.L().Warn("Could not run browser command", zap.Error(err))
		}
	}()

	cliutils.LineNotify("Please authenticate yourself using Octelium web Portal\n")
	cliutils.LineInfo("Waiting for you to approve the login in your browser. Press Ctrl-C to cancel.\n")

	select {
	case <-time.After(5 * time.Minute):
		return errors.Errorf(
			"You have not authenticated yourself after 5 minutes. Please authenticate yourself again.")
	case <-s.ch:
		return s.err
	}
}
