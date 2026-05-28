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

package admin

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	apisrvcommon "github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/grpcerr"
)

func (s *Server) CreateIdentityProvider(ctx context.Context, req *corev1.IdentityProvider) (*corev1.IdentityProvider, error) {

	if err := apivalidation.ValidateCommon(req, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
		},
	}); err != nil {
		return nil, err
	}

	if err := s.validateIdentityProvider(ctx, req); err != nil {
		return nil, err
	}

	{
		_, err := s.octeliumC.CoreC().GetIdentityProvider(ctx, apivalidation.ObjectToRGetOptions(req))
		if err == nil {
			return nil, grpcutils.AlreadyExists("The IdentityProvider %s already exists", req.Metadata.Name)
		}
		if !grpcerr.IsNotFound(err) {
			return nil, grpcutils.InternalWithErr(err)
		}
	}

	item := &corev1.IdentityProvider{
		Metadata: apisrvcommon.MetadataFrom(req.Metadata),
		Spec:     req.Spec,
		Status: &corev1.IdentityProvider_Status{
			Type: req.Status.Type,
		},
	}

	item, err := s.octeliumC.CoreC().CreateIdentityProvider(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return item, nil
}

func (s *Server) GetIdentityProvider(ctx context.Context, req *metav1.GetOptions) (*corev1.IdentityProvider, error) {
	if err := apisrvcommon.CheckGetOrDeleteOptions(req); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetIdentityProvider(ctx, apivalidation.GetOptionsToRGetOptions(req))
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	return ret, nil
}

func (s *Server) ListIdentityProvider(ctx context.Context, req *corev1.ListIdentityProviderOptions) (*corev1.IdentityProviderList, error) {

	itemList, err := s.octeliumC.CoreC().ListIdentityProvider(ctx, urscsrv.GetPublicListOptions(req))
	if err != nil {
		return nil, err
	}

	return itemList, nil
}

func (s *Server) DeleteIdentityProvider(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	g, err := s.octeliumC.CoreC().GetIdentityProvider(ctx, apivalidation.DeleteOptionsToRGetOptions(req))
	if err != nil {
		return nil, err
	}

	if err := apivalidation.CheckIsSystem(g); err != nil {
		return nil, err
	}

	_, err = s.octeliumC.CoreC().DeleteIdentityProvider(ctx, apivalidation.ObjectToRDeleteOptions(g))
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) UpdateIdentityProvider(ctx context.Context, req *corev1.IdentityProvider) (*corev1.IdentityProvider, error) {

	if err := apivalidation.ValidateCommon(req, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
		},
	}); err != nil {
		return nil, err
	}

	if err := s.validateIdentityProvider(ctx, req); err != nil {
		return nil, err
	}

	item, err := s.octeliumC.CoreC().GetIdentityProvider(ctx, apivalidation.ObjectToRGetOptions(req))
	if err != nil {
		return nil, err
	}

	if err := apivalidation.CheckIsSystem(item); err != nil {
		return nil, err
	}

	apisrvcommon.MetadataUpdate(item.Metadata, req.Metadata)
	item.Spec = req.Spec
	item.Status.Type = req.Status.Type

	item, err = s.octeliumC.CoreC().UpdateIdentityProvider(ctx, item)
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	return item, nil
}

func (s *Server) validateIdentityProvider(ctx context.Context, req *corev1.IdentityProvider) error {
	spec := req.Spec
	if spec == nil {
		return grpcutils.InvalidArg("Nil spec")
	}

	req.Status = &corev1.IdentityProvider_Status{}

	canonicalOIDCIssuerURL := func(arg string) (string, error) {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			return "", grpcutils.InvalidArg("issuerURL must be set")
		}
		if len(arg) > 2048 {
			return "", grpcutils.InvalidArg("issuerURL is too long")
		}
		if !utf8.ValidString(arg) {
			return "", grpcutils.InvalidArg("issuerURL must be valid UTF-8")
		}

		u, err := url.Parse(arg)
		if err != nil {
			return "", grpcutils.InvalidArg("issuerURL is invalid")
		}

		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.RawQuery = ""
		u.Fragment = ""
		u.User = nil

		p := strings.TrimRight(u.EscapedPath(), "/")
		u.Path = p

		if u.Scheme != "https" {
			return "", grpcutils.InvalidArg("issuerURL must use https")
		}

		if u.Host == "" {
			return "", grpcutils.InvalidArg("issuerURL host must be set")
		}

		if u.User != nil {
			return "", grpcutils.InvalidArg("issuerURL must not contain userinfo")
		}

		if u.RawQuery != "" || u.Fragment != "" {
			return "", grpcutils.InvalidArg("issuerURL must not contain query or fragment")
		}

		if p == "/.well-known/openid-configuration" ||
			strings.HasSuffix(p, "/.well-known/openid-configuration") {
			return "", grpcutils.InvalidArg("issuerURL must be the issuer, not the discovery URL")
		}

		return u.String(), nil
	}

	canonicalHTTPSURL := func(arg string, field string, allowQuery bool) (string, error) {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			return "", grpcutils.InvalidArg("%s must be set", field)
		}
		if len(arg) > 2048 {
			return "", grpcutils.InvalidArg("%s is too long", field)
		}
		if !utf8.ValidString(arg) {
			return "", grpcutils.InvalidArg("%s must be valid UTF-8", field)
		}

		u, err := url.Parse(arg)
		if err != nil {
			return "", grpcutils.InvalidArg("%s is invalid", field)
		}

		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.Fragment = ""
		u.User = nil

		if u.Scheme != "https" {
			return "", grpcutils.InvalidArg("%s must use https", field)
		}
		if u.Host == "" {
			return "", grpcutils.InvalidArg("%s host must be set", field)
		}
		if u.User != nil {
			return "", grpcutils.InvalidArg("%s must not contain userinfo", field)
		}
		if u.Fragment != "" {
			return "", grpcutils.InvalidArg("%s must not contain fragment", field)
		}
		if !allowQuery && u.RawQuery != "" {
			return "", grpcutils.InvalidArg("%s must not contain query", field)
		}

		return u.String(), nil
	}

	canonicalIssuerString := func(arg string) string {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			return ""
		}

		if issuer, err := canonicalOIDCIssuerURL(arg); err == nil {
			return issuer
		}

		return strings.TrimRight(arg, "/")
	}

	validateIssuerUniqueness := func(issuer string, typ corev1.IdentityProvider_Status_Type) error {
		issuer = canonicalIssuerString(issuer)
		if issuer == "" {
			return grpcutils.InvalidArg("Issuer cannot be empty")
		}

		idpList, err := s.octeliumC.CoreC().ListIdentityProvider(ctx, &rmetav1.ListOptions{})
		if err != nil {
			return err
		}

		for _, idp := range idpList.Items {
			if req.Metadata != nil && idp.Metadata != nil {
				if req.Metadata.Uid != "" && idp.Metadata.Uid == req.Metadata.Uid {
					continue
				}
				if req.Metadata.Uid == "" && idp.Metadata.Name == req.Metadata.Name {
					continue
				}
			}

			switch idp.Status.Type {
			case corev1.IdentityProvider_Status_OIDC,
				corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN:
			default:
				continue
			}

			if idp.Status.Type != typ {
				continue
			}

			var existingIssuer string

			switch idp.Status.Type {
			case corev1.IdentityProvider_Status_OIDC:
				existingIssuer = idp.Spec.GetOidc().GetIssuerURL()

			case corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN:
				idTokenSpec := idp.Spec.GetOidcIdentityToken()
				switch idTokenSpec.Type.(type) {
				case *corev1.IdentityProvider_Spec_OIDCIdentityToken_IssuerURL:
					existingIssuer = idTokenSpec.GetIssuerURL()
				default:
					existingIssuer = idTokenSpec.GetIssuer()
				}
			}

			if canonicalIssuerString(existingIssuer) == issuer {
				return grpcutils.InvalidArg("This issuer already exists: %s", issuer)
			}
		}

		return nil
	}

	validateOAuthScope := func(scope string) error {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return grpcutils.InvalidArg("scope cannot be empty")
		}
		if len(scope) > 128 {
			return grpcutils.InvalidArg("scope is too long")
		}
		if !utf8.ValidString(scope) {
			return grpcutils.InvalidArg("scope must be valid UTF-8")
		}

		for _, r := range scope {
			if r <= 0x20 || r == 0x7f {
				return grpcutils.InvalidArg("scope must not contain whitespace or control characters")
			}
		}

		return nil
	}

	validateScopes := func(scopes []string) error {
		if len(scopes) == 0 {
			return nil
		}
		if len(scopes) > 32 {
			return grpcutils.InvalidArg("Too many scopes")
		}

		seen := make(map[string]struct{}, len(scopes))
		for _, scope := range scopes {
			if err := validateOAuthScope(scope); err != nil {
				return err
			}

			if _, ok := seen[scope]; ok {
				return grpcutils.InvalidArg("Duplicate scope: %s", scope)
			}
			seen[scope] = struct{}{}
		}

		if _, ok := seen["openid"]; !ok {
			return grpcutils.InvalidArg("OIDC scopes must include openid")
		}

		return nil
	}

	validateClaimName := func(claim string, field string, required bool) error {
		claim = strings.TrimSpace(claim)
		if claim == "" {
			if required {
				return grpcutils.InvalidArg("%s must be set", field)
			}
			return nil
		}
		if len(claim) > 256 {
			return grpcutils.InvalidArg("%s is too long", field)
		}
		if !utf8.ValidString(claim) {
			return grpcutils.InvalidArg("%s must be valid UTF-8", field)
		}

		for _, r := range claim {
			if r <= 0x20 || r == 0x7f {
				return grpcutils.InvalidArg("%s must not contain whitespace or control characters", field)
			}
		}

		return nil
	}

	validateAudience := func(aud string) error {
		aud = strings.TrimSpace(aud)
		if aud == "" {
			return nil
		}
		if len(aud) > 512 {
			return grpcutils.InvalidArg("audience is too long")
		}
		if !utf8.ValidString(aud) {
			return grpcutils.InvalidArg("audience must be valid UTF-8")
		}

		for _, r := range aud {
			if r <= 0x20 || r == 0x7f {
				return grpcutils.InvalidArg("audience must not contain whitespace or control characters")
			}
		}

		return nil
	}

	switch spec.Type.(type) {
	case *corev1.IdentityProvider_Spec_Github_:
		typ := spec.GetGithub()

		if err := s.validateGenStr(typ.ClientID, true, "clientID"); err != nil {
			return err
		}

		if err := s.validateSecretOwner(ctx, typ.ClientSecret); err != nil {
			return err
		}

		req.Status.Type = corev1.IdentityProvider_Status_GITHUB

	case *corev1.IdentityProvider_Spec_Oidc:
		typ := spec.GetOidc()

		issuer, err := canonicalOIDCIssuerURL(typ.IssuerURL)
		if err != nil {
			return err
		}
		typ.IssuerURL = issuer

		if err := validateIssuerUniqueness(issuer, corev1.IdentityProvider_Status_OIDC); err != nil {
			return err
		}

		if err := s.validateGenStr(typ.ClientID, true, "clientID"); err != nil {
			return err
		}

		if err := s.validateSecretOwner(ctx, typ.ClientSecret); err != nil {
			return err
		}

		if err := validateScopes(typ.Scopes); err != nil {
			return err
		}

		if err := validateClaimName(typ.IdentifierClaim, "identifierClaim", false); err != nil {
			return err
		}

		req.Status.Type = corev1.IdentityProvider_Status_OIDC

	case *corev1.IdentityProvider_Spec_OidcIdentityToken:
		typ := spec.GetOidcIdentityToken()

		var issuer string

		switch typ.Type.(type) {
		case *corev1.IdentityProvider_Spec_OIDCIdentityToken_IssuerURL:
			canonicalIssuer, err := canonicalOIDCIssuerURL(typ.GetIssuerURL())
			if err != nil {
				return err
			}

			typ.Type = &corev1.IdentityProvider_Spec_OIDCIdentityToken_IssuerURL{
				IssuerURL: canonicalIssuer,
			}

			if strings.TrimSpace(typ.Issuer) != "" {
				return grpcutils.InvalidArg("You cannot define an issuer for issuerURL type")
			}

			issuer = canonicalIssuer

		case *corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksContent:
			content := strings.TrimSpace(typ.GetJwksContent())
			if content == "" {
				return grpcutils.InvalidArg("JWKS content must be set")
			}
			if len(content) > 256*1024 {
				return grpcutils.InvalidArg("JWKS content is too large")
			}

			var jwks jose.JSONWebKeySet
			if err := json.Unmarshal([]byte(content), &jwks); err != nil {
				return grpcutils.InvalidArg("Cannot unmarshal JWKS content")
			}
			if len(jwks.Keys) == 0 {
				return grpcutils.InvalidArg("JWKS content contains no keys")
			}

			if err := validateClaimName(typ.Issuer, "issuer", true); err != nil {
				return err
			}

			issuer = strings.TrimSpace(typ.Issuer)

		case *corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksURL:
			jwksURL, err := canonicalHTTPSURL(typ.GetJwksURL(), "jwksURL", false)
			if err != nil {
				return err
			}

			typ.Type = &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksURL{
				JwksURL: jwksURL,
			}

			if err := validateClaimName(typ.Issuer, "issuer", true); err != nil {
				return err
			}

			issuer = strings.TrimSpace(typ.Issuer)

		default:
			return grpcutils.InvalidArg("You must set either an issuerURL, JWKS Content or JWKS URL")
		}

		if err := validateAudience(typ.Audience); err != nil {
			return err
		}

		if err := validateIssuerUniqueness(issuer, corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN); err != nil {
			return err
		}

		req.Status.Type = corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN

	case *corev1.IdentityProvider_Spec_Saml:
		typ := spec.GetSaml()

		switch typ.MetadataType.(type) {
		case *corev1.IdentityProvider_Spec_SAML_Metadata:
			if len(typ.GetMetadata()) == 0 {
				return grpcutils.InvalidArg("Empty metadata content")
			}
			if len(typ.GetMetadata()) > 20000 {
				return grpcutils.InvalidArg("Metadata content is too large")
			}

		case *corev1.IdentityProvider_Spec_SAML_MetadataURL:
			metadataURL, err := canonicalHTTPSURL(typ.GetMetadataURL(), "metadataURL", false)
			if err != nil {
				return err
			}

			typ.MetadataType = &corev1.IdentityProvider_Spec_SAML_MetadataURL{
				MetadataURL: metadataURL,
			}

		default:
			return grpcutils.InvalidArg("Either metadataURL or metadata must be supplied")
		}

		if err := validateClaimName(typ.IdentifierAttribute, "identifierAttribute", false); err != nil {
			return err
		}

		if err := validateClaimName(typ.EntityID, "entityID", false); err != nil {
			return err
		}

		req.Status.Type = corev1.IdentityProvider_Status_SAML

	default:
		return grpcutils.InvalidArg("Must specify a type for the IdentityProvider")
	}

	if len(req.Spec.AalRules) > 128 {
		return grpcutils.InvalidArg("Too many aalRules")
	}

	for _, rule := range req.Spec.AalRules {
		if err := s.validateCondition(ctx, rule.Condition); err != nil {
			return err
		}

		switch rule.Aal {
		case corev1.IdentityProvider_Spec_AALRule_AAL_UNSET:
			return grpcutils.InvalidArg("AAL cannot be unset. It must be set to either AAL1, AAL2 or AAL3")
		}
	}

	if len(req.Spec.PostAuthenticationRules) > 128 {
		return grpcutils.InvalidArg("Too many postAuthenticationRules")
	}

	for _, rule := range req.Spec.PostAuthenticationRules {
		if err := s.validateCondition(ctx, rule.Condition); err != nil {
			return err
		}

		switch rule.Effect {
		case corev1.IdentityProvider_Spec_PostAuthenticationRule_EFFECT_UNKNOWN:
			return grpcutils.InvalidArg("Rule effect must be set to either ALLOW or DENY")
		}
	}

	return nil
}
