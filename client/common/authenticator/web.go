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
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type webAuthenticator struct {
	server              *http.Server
	listener            net.Listener
	ch                  chan bool
	port                int
	addr                string
	successCallbackPath string
	domain              string
	domainRoot          string
	callbackSuffix      string
	scopes              []string
	loginURL            string
	closeOnce           sync.Once
}

func newWebAuthenticator(domain string, scopes []string) (*webAuthenticator, error) {

	suffix := utilrand.GetRandomString(5)

	zap.L().Debug("Creating new webAuthenticator", zap.String("pathSuffix", suffix))

	return &webAuthenticator{
		domain:              domain,
		domainRoot:          fmt.Sprintf("https://%s", domain),
		ch:                  make(chan bool),
		addr:                "localhost",
		successCallbackPath: fmt.Sprintf("/callback/success/%s", suffix),
		callbackSuffix:      suffix,
		loginURL:            fmt.Sprintf("https://%s/login", domain),
		scopes:              scopes,
	}, nil
}

func (s *webAuthenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	defer s.closeOnce.Do(func() {
		close(s.ch)
	})

	zap.L().Debug("Received request at auth federation server")

	http.Redirect(w, r, s.domainRoot, http.StatusFound)

	respBytes, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("octelium_response"))
	if err != nil {
		return
	}

	resp := &authv1.ClientLoginResponse{}
	if err := pbutils.Unmarshal(respBytes, resp); err != nil {
		return
	}

	{
		authC, err := newAuthenticator(r.Context(), &AuthenticateOpts{
			Domain:    s.domain,
			AuthToken: resp.AuthenticationToken,
			Scopes:    s.scopes,
		})
		if err != nil {
			zap.L().Error("Could not create authenticator", zap.Error(err))
		}

		if err := authC.run(r.Context()); err != nil {
			cliutils.LineError("Could not authenticate: %v\n", err)
		}
	}

}

func (s *webAuthenticator) getLoginURL() string {
	u, _ := url.Parse(s.loginURL)

	q := u.Query()

	req := &authv1.ClientLoginRequest{
		ApiVersion:     authv1.ClientLoginRequest_V1,
		CallbackPort:   uint32(s.port),
		CallbackSuffix: s.callbackSuffix,
	}

	reqBytes, _ := pbutils.Marshal(req)

	q.Set("octelium_req", base64.RawURLEncoding.EncodeToString(reqBytes))

	u.RawQuery = q.Encode()

	return u.String()
}

func (s *webAuthenticator) run(_ context.Context) error {

	var err error

	s.listener, err = net.Listen("tcp", net.JoinHostPort(s.addr, "0"))
	if err != nil {
		return errors.Errorf("could not bind to a local port for authentication callback: %+v", err)
	}

	s.port = s.listener.Addr().(*net.TCPAddr).Port

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
	go func() {
		if err := s.server.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
	}()

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

	select {
	case <-time.After(10 * time.Minute):
		return errors.Errorf(
			"You have not authenticated yourself after 10 minutes. Please authenticate yourself again.")
	case <-s.ch:
		return nil
	}
}
