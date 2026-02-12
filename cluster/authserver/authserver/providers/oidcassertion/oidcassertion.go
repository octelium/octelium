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

package oidcassertion

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type Connector struct {
	c  *corev1.IdentityProvider
	cc *corev1.ClusterConfig

	octeliumC octeliumc.ClientInterface
	celEngine *celengine.CELEngine
}

func NewConnector(ctx context.Context, opts *utils.ProviderOpts) (*Connector, error) {

	if opts.Provider.Spec.GetOidcIdentityToken() == nil {
		return nil, errors.Errorf("Not an OIDC idToken provider")
	}

	ret := &Connector{
		c:         opts.Provider,
		cc:        opts.ClusterConfig,
		octeliumC: opts.OcteliumC,
		celEngine: opts.CELEngine,
	}

	return ret, nil
}

func (c *Connector) Name() string {
	return c.c.Metadata.Name
}

func (c *Connector) Provider() *corev1.IdentityProvider {
	return c.c
}

func (c *Connector) Type() string {
	return "oidcIdentityToken"
}

func (c *Connector) LoginURL(state string) (string, string, error) {
	return "", "", errors.Errorf("LoginURL is not supported")
}

func (c *Connector) HandleCallback(r *http.Request, reqID string) (*corev1.Session_Status_Authentication_Info, error) {
	return nil, errors.Errorf("HandleCallback is unsupported")
}

func (c *Connector) AuthenticateAssertion(ctx context.Context, req *authv1.AuthenticateWithAssertionRequest) (*corev1.User, *corev1.Session_Status_Authentication_Info, error) {
	if req.IdentityProviderRef == nil || req.IdentityProviderRef.Name != c.Name() {
		return nil, nil, errors.Errorf("Invalid Identity Provider name")
	}
	if req.IdentityProviderRef != nil {
		if req.IdentityProviderRef.Name != "" {
			if req.IdentityProviderRef.Name != c.c.Metadata.Name {
				return nil, nil, errors.Errorf("Invalid Identity Provider name")
			}
		} else if req.IdentityProviderRef.Uid != "" {
			if req.IdentityProviderRef.Uid != c.c.Metadata.Uid {
				return nil, nil, errors.Errorf("Invalid Identity Provider UID")
			}
		}
	} else {
		iss, err := peekIssuer(req.Assertion)
		if err != nil {
			return nil, nil, err
		}

		if strings.TrimSuffix(c.GetIssuer(), "/") != strings.TrimSuffix(iss, "/") {
			return nil, nil, errors.Errorf("invalid issuer")
		}
	}

	idToken := req.Assertion
	spec := c.c.Spec.GetOidcIdentityToken()

	oidcCfg := &oidc.Config{
		SkipClientIDCheck: true,
		SupportedSigningAlgs: []string{
			oidc.RS256,
			oidc.ES256,
			oidc.ES384,
		},
	}

	var verifier *oidc.IDTokenVerifier

	switch spec.Type.(type) {
	case *corev1.IdentityProvider_Spec_OIDCIdentityToken_IssuerURL:
		provider, err := oidc.NewProvider(ctx, spec.GetIssuerURL())
		if err != nil {
			return nil, nil, err
		}

		if spec.Issuer != "" {
			oidcCfg.SkipIssuerCheck = true
		}
		verifier = provider.Verifier(oidcCfg)
	case *corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksContent:
		var jwks jose.JSONWebKeySet
		if err := json.Unmarshal([]byte(spec.GetJwksContent()), &jwks); err != nil {
			return nil, nil, errors.Errorf("Cannot unmarshal jwks content: %+v", err)
		}

		keySet := oidc.StaticKeySet{
			PublicKeys: []crypto.PublicKey{},
		}
		for _, jwk := range jwks.Keys {
			keySet.PublicKeys = append(keySet.PublicKeys, jwk.Public().Key)
		}

		oidcCfg.SkipIssuerCheck = true
		verifier = oidc.NewVerifier("", &keySet, oidcCfg)
	case *corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksURL:
		oidcCfg.SkipIssuerCheck = true
		keySet := oidc.NewRemoteKeySet(ctx, spec.GetJwksURL())
		verifier = oidc.NewVerifier("", keySet, oidcCfg)
	default:
		return nil, nil, errors.Errorf("Cannot create a verifier without having an issuer URL or a JWKS")
	}

	zap.L().Debug("Starting verifying OIDC assertion", zap.String("name", c.Name()))
	idTkn, err := verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, nil, errors.Errorf("Could not verify idToken: %+v", err)
	}
	zap.L().Debug("OIDC assertion successfully verified", zap.String("name", c.Name()))

	if oidcCfg.SkipIssuerCheck {
		if spec.Issuer == "" {
			return nil, nil, errors.Errorf("You must supply the issuer for the JWS URL and content modes")
		}
		if idTkn.Issuer != spec.Issuer {
			return nil, nil, errors.Errorf("Overridden issuer does not match")
		}
	}

	audience := spec.Audience
	if audience == "" {
		audience = fmt.Sprintf("https://%s", c.cc.Status.Domain)
	}

	if !slices.Contains(idTkn.Audience, audience) {
		return nil, nil, errors.Errorf("Audience not found in the id token")
	}

	var claims map[string]any
	if err := idTkn.Claims(&claims); err != nil {
		return nil, nil, err
	}

	usr, err := utils.GetUserFromIdentifier(ctx, &utils.GetUserFromIdentifierOpts{
		OcteliumC:            c.octeliumC,
		IdentityProviderName: c.c.Metadata.Name,
		Identifier:           idTkn.Subject,
		UserType:             corev1.User_Spec_WORKLOAD,
	})
	if err != nil {
		return nil, nil, err
	}
	zap.L().Debug("Found User from assertion",
		zap.String("name", c.Name()), zap.String("userNanem", usr.Metadata.Name))

	return usr, &corev1.Session_Status_Authentication_Info{
		Type: corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER,
		Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
			IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
				IdentityProviderRef: umetav1.GetObjectReference(c.c),
				Identifier:          idTkn.Subject,
				Type:                corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN,
			},
		},
		Aal: utils.GetAAL(ctx, &utils.GetAALReq{
			CelEngine:    c.celEngine,
			Rules:        c.c.Spec.AalRules,
			AssertionMap: claims,
		}),
	}, nil
}

func (c *Connector) GetIssuer() string {
	spec := c.c.Spec.GetOidcIdentityToken()
	if spec.GetIssuerURL() != "" {
		return spec.GetIssuerURL()
	}

	return spec.Issuer
}

func peekIssuer(idToken string) (string, error) {
	tok, err := jwt.ParseSigned(idToken)
	if err != nil {
		return "", err
	}

	var claims struct {
		Issuer string `json:"iss"`
	}

	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", err
	}

	return claims.Issuer, nil
}
