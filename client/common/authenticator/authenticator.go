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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/cliutils"
	authn "github.com/octelium/octelium/client/common/commands/auth/authenticator"
	"github.com/octelium/octelium/octelium-go/authc"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type AuthenticateOpts struct {
	Domain    string
	AuthToken string
	Assertion *AuthenticateOptsAssertion
	IsWeb     bool
	Scopes    []string
}

type AuthenticateOptsAssertion struct {
	Arg string
}

func isAuthProxyMode() bool {
	return os.Getenv("OCTELIUM_AUTH_PROXY_SOCKET") != ""
}

func isStaticAccessToken() bool {
	return getStaticAccessToken() != ""
}

func getStaticAccessToken() string {
	return os.Getenv("OCTELIUM_ACCESS_TOKEN")
}

func Authenticate(ctx context.Context, opts *AuthenticateOpts) error {

	if isAuthProxyMode() {
		zap.L().Debug("Auth proxy mode. No need to authenticate")
		return nil
	}

	if isStaticAccessToken() {
		zap.L().Debug("static accessToken mode. No need to authenticate")
		return nil
	}

	authC, err := newAuthenticator(ctx, opts)
	if err != nil {
		return err
	}
	return authC.run(ctx)
}

func StartGetAccessToken(ctx context.Context, domain string) {

	if isAuthProxyMode() {
		zap.L().Debug("Auth proxy mode. No need to periodically fetch access token")
		return
	}

	if isStaticAccessToken() {
		zap.L().Debug("static accessToken mode. No need to periodically fetch access token")
		return
	}

	go func(ctx context.Context) {

		tickerCh := time.NewTicker(5 * time.Minute)
		defer tickerCh.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tickerCh.C:
				_, err := GetAccessToken(ctx, domain)
				if err != nil {
					zap.S().Warnf("Could not get access token: %+v", err)
				}
			}

		}
	}(ctx)
}

func GetAccessToken(ctx context.Context, domain string) (string, error) {

	if isAuthProxyMode() {
		return "", nil
	}

	if isStaticAccessToken() {
		return getStaticAccessToken(), nil
	}

	authC, err := newAuthenticator(ctx, &AuthenticateOpts{
		Domain: domain,
	})
	if err != nil {
		return "", err
	}

	return authC.doGetAccessToken(ctx)
}

type authenticator struct {
	domain    string
	skipStore bool
	opts      *AuthenticateOpts
	at        *cliconfigv1.State_Domain

	isAuthentication bool
	isRefresh        bool

	c *authc.Client
}

func newAuthenticator(ctx context.Context, opts *AuthenticateOpts) (*authenticator, error) {
	// zap.L().Debug("Creating a new CLI authenticator", zap.Any("opts", opts))
	if opts == nil {
		opts = &AuthenticateOpts{}
	}
	var err error

	if opts.Domain == "" {
		opts.Domain = os.Getenv("OCTELIUM_DOMAIN")
		if opts.Domain == "" {
			return nil, errors.Errorf("The Cluster domain is not set. Set the domain either via the --domain flag or the OCTELIUM_DOMAIN environment variable...")
		}
	}

	ret := &authenticator{
		opts:      opts,
		domain:    opts.Domain,
		skipStore: false,
	}

	if isAuthProxyMode() || isStaticAccessToken() {
		return ret, nil
	}

	ret.c, err = cliutils.NewAuthClient(ctx, opts.Domain, nil)
	if err != nil {
		return nil, err
	}

	if ret.opts != nil {
		if ret.opts.AuthToken == "" && ret.opts.Assertion == nil {
			switch {
			case os.Getenv("OCTELIUM_AUTH_TOKEN") != "":
				ret.opts.AuthToken = os.Getenv("OCTELIUM_AUTH_TOKEN")
			case os.Getenv("OCTELIUM_AUTH_ASSERTION") != "":
				ret.opts.Assertion = &AuthenticateOptsAssertion{
					Arg: os.Getenv("OCTELIUM_AUTH_ASSERTION"),
					// IdentityProvider: os.Getenv("OCTELIUM_AUTH_ASSERTION_PROVIDER"),
				}
			}
		}
	}

	if at, err := cliutils.GetDB().Get(ret.domain); err == nil {
		ret.at = at
	} else if !cliutils.GetDB().ErrorIsNotFound(err) {
		return nil, errors.Errorf("Could not fetch access token from DB: %+v", err)
	}

	if ret.at == nil {
		ret.isAuthentication = true
	} else if hasValidRefreshToken(ret.at) {
		ret.isRefresh = true
	} else {
		ret.isAuthentication = true
	}

	return ret, nil
}

func (a *authenticator) run(ctx context.Context) error {
	_, err := a.doGetAccessToken(ctx)
	return err
}

func (a *authenticator) doGetAccessToken(ctx context.Context) (string, error) {

	if isAuthProxyMode() {
		return "", nil
	}

	if isStaticAccessToken() {
		return getStaticAccessToken(), nil
	}

	switch {
	case a.isRefresh:
		if !needsNewAccessToken(a.at) {
			// zap.L().Debug("No need to fetch a new access token. The current one is still new")
			return a.at.SessionToken.AccessToken, nil
		}

		if resp, err := a.c.C().GetAvailableAuthenticator(ctx,
			&authv1.GetAvailableAuthenticatorRequest{}); err == nil && resp.MainAuthenticator != nil {
			if err := authn.DoAuthenticate(ctx,
				a.domain, a.c, umetav1.GetObjectReference(resp.MainAuthenticator)); err == nil {
				sessTkn, err := cliutils.GetDB().GetSessionToken(a.domain)
				if err != nil {
					return "", err
				}

				zap.L().Debug("Successfully authenticated with main Authenticator",
					zap.Any("authenticator", resp.MainAuthenticator))

				return sessTkn.AccessToken, nil
			} else {
				zap.L().Warn("Could not DoAuthenticate for Authenticator",
					zap.Error(err), zap.Any("authenticator", resp.MainAuthenticator))
			}
		} else if grpcerr.IsUnimplemented(err) {
			zap.L().Debug("GetAvailableAuthenticator is not implemented at the Cluster.")
		} else {
			zap.L().Warn("Could not getAvailableAuthenticator", zap.Error(err))
		}

		sessTkn, err := a.c.C().AuthenticateWithRefreshToken(ctx, &authv1.AuthenticateWithRefreshTokenRequest{})
		if err != nil {
			if grpcerr.AlreadyExists(err) {
				return a.at.SessionToken.AccessToken, nil
			}
			if grpcerr.IsUnauthenticated(err) {
				a.isRefresh = false
				a.isAuthentication = true
				return a.doGetAccessToken(ctx)
			}

			return "", err
		}
		if err := cliutils.GetDB().SetSessionToken(a.domain, sessTkn); err != nil {
			return "", err
		}

		return sessTkn.AccessToken, nil
	case a.isAuthentication:
		switch {
		case a.opts.IsWeb:
			return a.doWebAuthentication(ctx)
		case a.opts.AuthToken != "":
			sessTkn, err := a.c.C().AuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
				AuthenticationToken: a.opts.AuthToken,
				Scopes:              a.opts.Scopes,
			})
			if err != nil {
				return "", err
			}
			if err := cliutils.GetDB().SetSessionToken(a.domain, sessTkn); err != nil {
				return "", err
			}

			return sessTkn.AccessToken, nil
		case a.opts.Assertion != nil:
			assertionArgs, err := a.getAssertion(ctx)
			if err != nil {
				return "", err
			}
			sessTkn, err := a.c.C().AuthenticateWithAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
				Scopes:              a.opts.Scopes,
				Assertion:           assertionArgs.assertion,
				IdentityProviderRef: assertionArgs.identityProviderRef,
			})
			if err != nil {
				return "", err
			}
			if err := cliutils.GetDB().SetSessionToken(a.domain, sessTkn); err != nil {
				return "", err
			}

			return sessTkn.AccessToken, nil
		default:
			if !isWorkloadHost() {
				return a.doWebAuthentication(ctx)
			} else {
				return "",
					errors.Errorf(
						`
You must choose the authentication type: either with an authentication token using the --auth-token flag, or using the web Portal using the --web flag`)
			}
		}
	default:
		return "", errors.Errorf("Neither a refresh nor an authentication flow")
	}

}

func (a *authenticator) doWebAuthentication(ctx context.Context) (string, error) {
	zap.L().Debug("Starting web authentication flow")
	scopes := func() []string {
		if a.opts != nil {
			return a.opts.Scopes
		}
		return nil
	}()
	webAuthC, err := newWebAuthenticator(a.domain, scopes)
	if err != nil {
		return "", err
	}
	if err := webAuthC.run(ctx); err != nil {
		return "", err
	}

	at, err := cliutils.GetDB().GetSessionToken(a.domain)
	if err != nil {
		return "", err
	}
	return at.AccessToken, nil
}

func needsNewAccessToken(at *cliconfigv1.State_Domain) bool {
	if at == nil || at.SessionToken == nil || !at.SessionTokenSetAt.IsValid() {
		return true
	}

	if at.SessionToken.ExpiresIn == 0 {
		return false
	}

	expiresAt := at.SessionTokenSetAt.AsTime().
		Add(time.Second * time.Duration(at.SessionToken.ExpiresIn)).
		Add(getExpirationGap(at.SessionToken.ExpiresIn))

	return time.Now().After(expiresAt)
}

func hasValidRefreshToken(at *cliconfigv1.State_Domain) bool {
	if at == nil || at.SessionToken == nil || !at.SessionTokenSetAt.IsValid() {
		return false
	}

	if at.SessionToken.RefreshTokenExpiresIn == 0 {
		return false
	}

	expiresAt := at.SessionTokenSetAt.AsTime().
		Add(time.Second * time.Duration(at.SessionToken.RefreshTokenExpiresIn))

	return time.Now().Before(expiresAt)
}

func getExpirationGap(nextRenewSeconds int64) time.Duration {
	if nextRenewSeconds < 3600 {
		return time.Duration(-600 * time.Second)
	}
	return time.Duration(-1 * int64(nextRenewSeconds/2) * int64(time.Second))
}

type assertionArgs struct {
	identityProviderRef *metav1.ObjectReference
	assertion           string
}

func (a *authenticator) getAssertion(_ context.Context) (*assertionArgs, error) {
	var err error
	if a.opts.Assertion == nil || a.opts.Assertion.Arg == "" {
		return nil, errors.Errorf("No assertion argument found")
	}

	args := strings.SplitN(a.opts.Assertion.Arg, ":", 2)
	if len(args) < 2 {
		return nil, errors.Errorf("Invalid assertion argument: %s", a.opts.Assertion.Arg)
	}

	hasArgsMap := len(args) == 3
	var argsMap string
	if hasArgsMap {
		argsMap = args[2]
	}

	ret := &assertionArgs{
		identityProviderRef: func() *metav1.ObjectReference {
			if govalidator.IsUUIDv4(args[0]) {
				return &metav1.ObjectReference{
					Uid: args[0],
				}
			}
			return &metav1.ObjectReference{
				Name: args[0],
			}
		}(),
	}

	switch args[1] {
	case "k8s", "kubernetes":
		filePath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
		tknBytes, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		ret.assertion = string(tknBytes)
		return ret, nil
	case "azure":
		var audience string
		if hasArgsMap {
			audience = getArgMap(argsMap)["audience"]
		}
		ret.assertion, err = a.getAssertionAzure(audience)
		if err != nil {
			return nil, err
		}
		return ret, nil
	case "github-actions":
		var audience string
		if hasArgsMap {
			audience = getArgMap(argsMap)["audience"]
		}
		ret.assertion, err = a.getAssertionGithubActions(audience)
		if err != nil {
			return nil, err
		}
		return ret, nil
	case "jwt":
		if !hasArgsMap {
			return nil, errors.Errorf("No JWT option")
		}
		argMap := getArgMap(argsMap)
		if env, ok := argMap["env"]; ok {
			ret.assertion = os.Getenv(env)
			return ret, nil
		} else if filePath, ok := argMap["file"]; ok {
			b, err := os.ReadFile(filePath)
			if err != nil {
				return nil, err
			}
			ret.assertion = string(b)
			return ret, nil
		} else {
			return nil, errors.Errorf("Neither env nor file path is set for the jwt assertion option")
		}
	default:
		return nil, errors.Errorf("Unknown assertion type: %s", args[0])
	}

}

func getArgMap(arg string) map[string]string {
	ret := make(map[string]string)
	if arg == "" {
		return ret
	}
	items := strings.Split(arg, ",")
	for _, itm := range items {
		keys := strings.SplitN(itm, "=", 2)
		if len(keys) != 2 {
			continue
		}
		ret[keys[0]] = keys[1]
	}

	return ret
}

func (a *authenticator) getAssertionAzure(aud string) (string, error) {
	const (
		defaultMountPath     = "azure"
		defaultResourceURL   = "https://management.azure.com/"
		metadataEndpoint     = "http://169.254.169.254"
		metadataAPIVersion   = "2021-05-01"
		apiVersionQueryParam = "api-version"
		resourceQueryParam   = "resource"
		clientTimeout        = 10 * time.Second
	)

	type errorJSON struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}

	type responseJSON struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    string `json:"expires_in"`
		ExpiresOn    string `json:"expires_on"`
		NotBefore    string `json:"not_before"`
		Resource     string `json:"resource"`
		TokenType    string `json:"token_type"`
	}

	if aud == "" {
		aud = a.domain
	}

	identityEndpoint, err := url.Parse(fmt.Sprintf("%s/metadata/identity/oauth2/token", metadataEndpoint))
	if err != nil {
		return "", errors.Errorf("could not create Azure metadata URL: %+v", err)
	}

	identityParameters := identityEndpoint.Query()
	identityParameters.Add(apiVersionQueryParam, metadataAPIVersion)
	identityParameters.Add(resourceQueryParam, aud)
	// identityParameters.Add(resourceQueryParam, defaultResourceURL)
	identityEndpoint.RawQuery = identityParameters.Encode()

	req, err := http.NewRequest(http.MethodGet, identityEndpoint.String(), nil)
	if err != nil {
		return "", errors.Errorf("Could not create Azure metadata url HTTP request: %+v", err)
	}
	req.Header.Add("Metadata", "true")

	client := &http.Client{
		Timeout: clientTimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Errorf("Could not do HTTP request to Azure metadata url: %+v", err)
	}
	defer resp.Body.Close()

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		var errResp errorJSON
		err = json.Unmarshal(responseBytes, &errResp)
		if err != nil {
			return "", errors.Errorf("Could not unmarshal Azure metadata url error response: %+v", err)
		}
		return "", errors.Errorf("Could not get token from Azure metadata url: %+v: %+v",
			errResp.Error, errResp.ErrorDescription)
	}

	var r responseJSON
	err = json.Unmarshal(responseBytes, &r)
	if err != nil {
		return "", errors.Errorf("Could not unmarshal Azure metadata endpoint response: %+v", err)
	}

	return r.AccessToken, nil
}

func (a *authenticator) getAssertionGithubActions(aud string) (string, error) {
	if aud == "" {
		aud = fmt.Sprintf("https://%s", a.domain)
	}

	reqToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqToken == "" {
		return "", errors.Errorf("Could not find Github Actions request token")
	}

	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	if requestURL == "" {
		return "", errors.Errorf("Could not find Github Actions request URL")
	}

	requestURL = requestURL + "&audience=" + url.QueryEscape(aud)

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", reqToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var response struct {
		Value string `json:"value"`
	}

	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&response); err != nil {
		return "", err
	}
	return response.Value, nil
}

func isWorkloadHost() bool {

	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}

	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}

	if os.Getenv("container") == "podman" {
		return true
	}

	if os.Getenv("CI") == "true" {
		return true
	}

	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		return true
	}

	if os.Getenv("AWS_EXECUTION_ENV") != "" {
		return true
	}

	zap.L().Debug("Looks like the process is not running inside a very known workload host environment. Treating it as a HUMAN host")

	return false
}
