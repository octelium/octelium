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
	"os/exec"
	"runtime"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type webAuthenticator struct {
	ch                  chan bool
	port                int
	addr                string
	successCallbackPath string
	domain              string
	domainRoot          string
	callbackSuffix      string
	scopes              []string
	loginURL            string
}

func newWebAuthenticator(domain string, scopes []string) (*webAuthenticator, error) {

	port, err := getPort()
	if err != nil {
		return nil, err
	}

	suffix := utilrand.GetRandomString(5)

	zap.L().Debug("Creating new webAuthenticator", zap.Int("port", port), zap.String("pathSuffix", suffix))

	return &webAuthenticator{
		domain:              domain,
		domainRoot:          fmt.Sprintf("https://%s", domain),
		ch:                  make(chan bool),
		port:                port,
		addr:                "localhost",
		successCallbackPath: fmt.Sprintf("/callback/success/%s", suffix),
		callbackSuffix:      suffix,
		loginURL:            fmt.Sprintf("https://%s/login", domain),
		scopes:              scopes,
	}, nil
}

func getBrowserCmd(url string) (*exec.Cmd, error) {

	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url), nil
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url), nil
	case "darwin":
		return exec.Command("open", url), nil
	default:
		return nil, errors.Errorf("This OS is not supported currently")
	}
}

func (s *webAuthenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	defer close(s.ch)

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

func isPortAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}

	defer ln.Close()
	time.Sleep(100 * time.Millisecond)
	return true
}

func getPort() (int, error) {
	for i := 0; i < 1000; i++ {
		port := utilrand.GetRandomRangeMath(20000, 65000)
		if isPortAvailable(port) {
			return port, nil
		}
	}

	return 0, errors.Errorf("Could not find an available port!")
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

func (s *webAuthenticator) run(ctx context.Context) error {
	go func() error {
		http.Handle(s.successCallbackPath, s)
		return http.ListenAndServe(fmt.Sprintf("%s:%d", s.addr, s.port), nil)
	}()

	time.Sleep(200 * time.Millisecond)

	cmd, err := getBrowserCmd(s.getLoginURL())
	if err != nil {
		return err
	}

	// errCh := make(chan error)

	go func() {
		zap.S().Debugf("running the browser to authenticate user")
		if err := cmd.Run(); err != nil {
			zap.L().Warn("Could not run browser command", zap.Error(err))
			// errCh <- err
		}
	}()

	cliutils.LineNotify("Please authenticate yourself using Octelium web Portal\n")

	select {

	/*
		case err := <-errCh:
			if err == nil {
				return nil
			}
			return errors.Errorf("Could not run browser command: %s", err.Error())
	*/
	case <-time.After(10 * time.Minute):
		return errors.Errorf("You have not authenticated yourself after 10 minutes. Please authenticate yourself again.")
	case <-s.ch:
		return nil
	}
}
