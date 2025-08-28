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

	"github.com/asaskevich/govalidator"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	apisrvcommon "github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
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
		_, err := s.octeliumC.CoreC().GetIdentityProvider(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
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

	ret, err := s.octeliumC.CoreC().GetIdentityProvider(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
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

	g, err := s.octeliumC.CoreC().GetIdentityProvider(ctx, &rmetav1.GetOptions{Name: req.Name, Uid: req.Uid})
	if err != nil {
		return nil, err
	}

	if err := apivalidation.CheckIsSystem(g); err != nil {
		return nil, err
	}

	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	_, err = s.octeliumC.CoreC().DeleteIdentityProvider(ctx, &rmetav1.DeleteOptions{Uid: g.Metadata.Uid})
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

	item, err := s.octeliumC.CoreC().GetIdentityProvider(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err != nil {
		return nil, err
	}

	if err := apivalidation.CheckIsSystem(item); err != nil {
		return nil, err
	}

	if item.Status.Type != req.Status.Type {
		return nil, grpcutils.InvalidArg("Cannot change the IdentityProvider type after creation.")
	}

	apisrvcommon.MetadataUpdate(item.Metadata, req.Metadata)
	item.Spec = req.Spec

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
		if typ.IssuerURL == "" {
			return grpcutils.InvalidArg("issuerURL must be set")
		}
		if !govalidator.IsURL(typ.IssuerURL) {
			return grpcutils.InvalidArg("issuerURL is not a valid URL: %s", typ.IssuerURL)
		}

		if !ldflags.IsTest() {
			if _, err := oidc.NewProvider(ctx, typ.IssuerURL); err != nil {
				return grpcutils.InvalidArg("failed to get oidc provider : %s", err.Error())
			}
		}

		if err := s.validateGenStr(typ.ClientID, true, "clientID"); err != nil {
			return err
		}
		if err := s.validateSecretOwner(ctx, typ.ClientSecret); err != nil {
			return err
		}

		if len(typ.Scopes) > 0 {
			if len(typ.Scopes) > 32 {
				return grpcutils.InvalidArg("Too many scopes")
			}
			for _, scope := range typ.Scopes {
				if err := apivalidation.ValidateGenASCII(scope); err != nil {
					return err
				}
			}
		}

		if typ.IdentifierClaim != "" {
			if err := apivalidation.ValidateGenASCII(typ.IdentifierClaim); err != nil {
				return err
			}
		}

		req.Status.Type = corev1.IdentityProvider_Status_OIDC
	case *corev1.IdentityProvider_Spec_OidcIdentityToken:
		typ := spec.GetOidcIdentityToken()
		switch typ.Type.(type) {
		case *corev1.IdentityProvider_Spec_OIDCIdentityToken_IssuerURL:
			if !govalidator.IsURL(typ.GetIssuerURL()) {
				return grpcutils.InvalidArg("Invalid issuer URL")
			}
		case *corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksContent:
		case *corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksURL:
			if !govalidator.IsURL(typ.GetJwksURL()) {
				return grpcutils.InvalidArg("Invalid issuer URL")
			}
		default:
			return grpcutils.InvalidArg("You must set either an issuerURL, JWKS Content or JWKS URL")
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
			if typ.GetMetadataURL() == "" {
				return grpcutils.InvalidArg("metadata URL must be set")
			}
			if !govalidator.IsURL(typ.GetMetadataURL()) {
				return grpcutils.InvalidArg("Invalid metadata URL")
			}
		default:
			return grpcutils.InvalidArg("Either metadataURL or metadata must be supplied")
		}

		if typ.IdentifierAttribute != "" {
			if err := apivalidation.ValidateGenASCII(typ.IdentifierAttribute); err != nil {
				return err
			}
		}

		if typ.EntityID != "" {
			if err := apivalidation.ValidateGenASCII(typ.EntityID); err != nil {
				return err
			}
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
