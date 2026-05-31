/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package oidc

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	vutils "github.com/octelium/octelium/pkg/utils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type Connector struct {
	c  *corev1.IdentityProvider
	cc *corev1.ClusterConfig

	scopes    []string
	secret    string
	celEngine *celengine.CELEngine
	issuerURL string
}

func NewConnector(ctx context.Context, opts *utils.ProviderOpts) (*Connector, error) {
	if opts == nil || opts.Provider == nil || opts.Provider.Spec == nil {
		return nil, errors.Errorf("Nil provider options")
	}

	if opts.Provider.Spec.GetOidc() == nil {
		return nil, errors.Errorf("Not an OIDC provider")
	}

	conf := opts.Provider.Spec.GetOidc()

	scopes := []string{oidc.ScopeOpenID}

	if len(conf.Scopes) > 0 {
		if slices.Contains(conf.Scopes, oidc.ScopeOpenID) {
			scopes = conf.Scopes
		} else {
			scopes = append(scopes, conf.Scopes...)
		}
	} else {
		scopes = append(scopes, "profile", "email")
	}

	ret := &Connector{
		c:  opts.Provider,
		cc: opts.ClusterConfig,

		scopes:    scopes,
		celEngine: opts.CELEngine,
		issuerURL: conf.IssuerURL,
	}

	sec, err := opts.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
		Name: conf.GetClientSecret().GetFromSecret(),
	})
	if err != nil {
		return nil, err
	}

	ret.secret = ucorev1.ToSecret(sec).GetValueStr()

	return ret, nil
}

func (c *Connector) Name() string {
	return c.c.Metadata.Name
}

func (c *Connector) Provider() *corev1.IdentityProvider {
	return c.c
}

func (c *Connector) Type() string {
	return "oidc"
}

func (c *Connector) GetLogin(r *http.Request, state string) (*utils.GetLoginResponse, error) {
	nonce := utilrand.GetRandomStringCanonical(22)
	verifier := oauth2.GenerateVerifier()

	provider, err := c.newProvider(r.Context())
	if err != nil {
		return nil, err
	}

	loginURL := c.oauth2Config(provider).AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	)

	return &utils.GetLoginResponse{
		LoginURL: loginURL,
		ReqID:    nonce,
		Verifier: verifier,
	}, nil
}

func (c *Connector) oauth2Config(provider *oidc.Provider) *oauth2.Config {
	config := c.c.Spec.GetOidc()

	return &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: c.secret,
		Endpoint:     provider.Endpoint(),
		Scopes:       c.scopes,
		RedirectURL:  utils.GetCallbackURL(c.cc.Status.Domain),
	}
}

func (c *Connector) HandleCallback(r *http.Request,
	login *utils.GetLoginResponse) (*corev1.Session_Status_Authentication_Info, error) {
	conf := c.c.Spec.GetOidc()

	if login == nil {
		return nil, errors.Errorf("Nil login state")
	}

	if login.ReqID == "" {
		return nil, errors.Errorf("Empty OIDC nonce")
	}

	if login.Verifier == "" {
		return nil, errors.Errorf("Empty OIDC PKCE verifier")
	}

	ctx := r.Context()

	provider, err := c.newProvider(ctx)
	if err != nil {
		return nil, err
	}

	oauth2Config := c.oauth2Config(provider)

	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		errDesc := q.Get("error_description")
		if errDesc != "" {
			return nil, errors.Errorf("%s", errDesc)
		}
		return nil, errors.Errorf("%s", errType)
	}

	code := q.Get("code")
	if code == "" {
		return nil, errors.Errorf("No authorization code found")
	}

	token, err := oauth2Config.Exchange(
		ctx,
		code,
		oauth2.VerifierOption(login.Verifier),
	)
	if err != nil {
		return nil, errors.Errorf("Could not get token: %v", err)
	}

	if !token.Valid() {
		return nil, errors.Errorf("Invalid token")
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: conf.ClientID,
	})

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.Errorf("Could not find id_token in token response")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, errors.Errorf("Could not verify the ID Token: %v", err)
	}

	idTokenClaims := make(map[string]any)
	if err := idToken.Claims(&idTokenClaims); err != nil {
		return nil, err
	}

	claims := make(map[string]any, len(idTokenClaims))
	for k, v := range idTokenClaims {
		claims[k] = v
	}

	if conf.UseUserInfoEndpoint {
		zap.L().Debug("Getting userInfo endpoint")

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, errors.Errorf("Could not get userInfo endpoint: %v", err)
		}

		if userInfo.Subject != "" && userInfo.Subject != idToken.Subject {
			return nil, errors.Errorf("UserInfo subject mismatch")
		}

		userInfoClaims := make(map[string]any)
		if err := userInfo.Claims(&userInfoClaims); err != nil {
			return nil, err
		}

		for k, v := range userInfoClaims {
			switch k {
			case "iss", "sub", "aud", "exp", "iat", "nbf", "nonce", "azp", "auth_time", "acr", "amr":
				continue
			default:
				claims[k] = v
			}
		}
	}

	zap.L().Debug("Got OIDC claims",
		zap.String("idp", c.c.Metadata.Name),
		zap.Int("claimCount", len(claims)))

	emailVerifiedKey := "email_verified"
	picURLClaim := "picture"
	identifierKey := "email"
	if conf.IdentifierClaim != "" {
		identifierKey = conf.IdentifierClaim
	}

	identifier, _ := claims[identifierKey].(string)
	identifier = strings.TrimSpace(identifier)

	if identifier == "" {
		return nil, errors.Errorf("OIDC identifier claim %s is missing or empty", identifierKey)
	}

	picURL, _ := claims[picURLClaim].(string)
	emailVerified := func() bool {
		switch v := claims[emailVerifiedKey].(type) {
		case bool:
			return v
		case string:
			return strings.EqualFold(v, "true")
		default:
			return false
		}
	}()
	email, _ := claims["email"].(string)
	nonce, _ := claims["nonce"].(string)

	if nonce == "" || !vutils.SecureStringEqual(nonce, login.ReqID) {
		return nil, errors.Errorf("Nonce mismatch")
	}

	if conf.CheckEmailVerified && !emailVerified {
		return nil, errors.Errorf(
			"The User email is not verified according to the provider. Please verify it and try again")
	}

	ret := &corev1.Session_Status_Authentication_Info{
		Type: corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER,
		Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
			IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
				IdentityProviderRef: umetav1.GetObjectReference(c.c),
				Type:                corev1.IdentityProvider_Status_OIDC,
				Identifier:          identifier,
				PicURL:              picURL,
				Email:               email,
			},
		},
		Aal: utils.GetAAL(ctx, &utils.GetAALReq{
			CelEngine:    c.celEngine,
			Rules:        c.c.Spec.AalRules,
			AssertionMap: claims,
		}),
	}

	return ret, nil
}

func (c *Connector) AuthenticateAssertion(ctx context.Context,
	req *authv1.AuthenticateWithAssertionRequest) (*corev1.User, *corev1.Session_Status_Authentication_Info, error) {
	return nil, nil, errors.Errorf("AuthenticateAssertion is unimplemented")
}

func (c *Connector) newProvider(ctx context.Context) (*oidc.Provider, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	issuerURL := strings.TrimSpace(c.issuerURL)
	if issuerURL == "" {
		return nil, errors.Errorf("Empty OIDC issuer URL")
	}

	p, err := oidc.NewProvider(ctx, issuerURL)
	if err == nil {
		return p, nil
	}

	alt := toggleTrailingSlash(issuerURL)
	if alt != issuerURL {
		p2, err2 := oidc.NewProvider(ctx, alt)
		if err2 == nil {
			zap.L().Debug("Initialized OIDC provider using alternate trailing-slash issuer form",
				zap.String("configuredIssuer", issuerURL),
				zap.String("effectiveIssuer", alt))
			return p2, nil
		}

		return nil, errors.Errorf("Could not initialize OIDC provider for issuer %s. %+v", issuerURL, err2)
	}

	return nil, errors.Errorf("Could not initialize OIDC provider for issuer %s. %+v", issuerURL, err)
}

func toggleTrailingSlash(s string) string {
	if strings.HasSuffix(s, "/") {
		return strings.TrimSuffix(s, "/")
	}

	return s + "/"
}
