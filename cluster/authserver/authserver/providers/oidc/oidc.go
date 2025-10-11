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

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type Connector struct {
	c         *corev1.IdentityProvider
	cc        *corev1.ClusterConfig
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	scopes    []string
	secret    string
	celEngine *celengine.CELEngine
}

func NewConnector(ctx context.Context, opts *utils.ProviderOpts) (*Connector, error) {

	if opts.Provider.Spec.GetOidc() == nil {
		return nil, errors.Errorf("Not an OIDC provider")
	}

	conf := opts.Provider.Spec.GetOidc()

	provider, err := oidc.NewProvider(ctx, conf.IssuerURL)
	if err != nil {
		return nil, errors.Errorf("failed to get provider: %v", err)
	}

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
		c:        opts.Provider,
		cc:       opts.ClusterConfig,
		provider: provider,
		verifier: provider.Verifier(
			&oidc.Config{ClientID: conf.ClientID},
		),
		scopes:    scopes,
		celEngine: opts.CELEngine,
	}

	sec, err := opts.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
		Name: opts.Provider.Spec.GetOidc().ClientSecret.GetFromSecret(),
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

func (c *Connector) LoginURL(state string) (string, string, error) {
	nonce := utilrand.GetRandomStringCanonical(8)
	return c.oauth2Config().AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce)), nonce, nil
}

func (c *Connector) oauth2Config() *oauth2.Config {
	config := c.c.Spec.GetOidc()

	return &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: c.secret,
		Endpoint:     c.provider.Endpoint(),
		Scopes:       c.scopes,
		RedirectURL:  utils.GetCallbackURL(c.cc.Status.Domain),
	}
}

func (c *Connector) HandleCallback(r *http.Request, reqID string) (*corev1.Session_Status_Authentication_Info, error) {
	oauth2Config := c.oauth2Config()

	conf := c.c.Spec.GetOidc()

	ctx := r.Context()

	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return nil, errors.Errorf("%s", q.Get("error_description"))
	}

	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	if err != nil {
		return nil, errors.Errorf("Could not get token: %v", err)
	}

	if !token.Valid() {
		return nil, errors.Errorf("Invalid token")
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.Errorf("Could not find id_token in token response")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, errors.Errorf("Could not verify the ID Token: %v", err)
	}

	claims := make(map[string]any)
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	if conf.UseUserInfoEndpoint {
		zap.L().Debug("Getting userInfo endpoint")
		userInfo, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			return nil, errors.Errorf("Could not get userInfo endpoint: %v", err)
		}

		if err := userInfo.Claims(&claims); err != nil {
			return nil, err
		}
	}

	zap.L().Debug("Got oidc claims", zap.String("idp", c.c.Metadata.Name), zap.Any("claims", claims))

	// preferredUsernameKey := "preferred_username"
	identifierKey := "email"
	emailVerifiedKey := "email_verified"
	picURLClaim := "picture"

	if conf.IdentifierClaim != "" {
		identifierKey = conf.IdentifierClaim
	}

	identifier, _ := claims[identifierKey].(string)
	picURL, _ := claims[picURLClaim].(string)
	emailVerified, _ := claims[emailVerifiedKey].(bool)
	email, _ := claims["email"].(string)
	nonce, _ := claims["nonce"].(string)

	if nonce != reqID {
		return nil, errors.Errorf("Invalid nonce: Given = %s. Correct: %s", nonce, reqID)
	}

	ret := &corev1.Session_Status_Authentication_Info{
		Type: corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER,
		Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
			IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
				IdentityProviderRef: umetav1.GetObjectReference(c.c),
				Type:                corev1.IdentityProvider_Status_OIDC,

				Identifier: identifier,
				PicURL:     picURL,
				Email:      email,
			},
		},
		Aal: utils.GetAAL(ctx, &utils.GetAALReq{
			CelEngine:    c.celEngine,
			Rules:        c.c.Spec.AalRules,
			AssertionMap: claims,
		}),
	}

	if conf.CheckEmailVerified {
		if !emailVerified {
			return nil, errors.Errorf(
				"The User email is not verified according to the provider. Please verify it and try again")
		}
	}

	return ret, nil
}

func (c *Connector) AuthenticateAssertion(ctx context.Context, req *authv1.AuthenticateWithAssertionRequest) (*corev1.User, *corev1.Session_Status_Authentication_Info, error) {
	return nil, nil, errors.Errorf("AuthenticateAssertion is unimplemented")
}
