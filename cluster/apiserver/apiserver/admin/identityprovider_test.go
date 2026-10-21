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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

const testSAMLMetadata = `<?xml version="1.0" encoding="UTF-8"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></IDPSSODescriptor></EntityDescriptor>`

func genTestJWKSContent(t *testing.T) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err, "%+v", err)

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       key.Public(),
				KeyID:     utilrand.GetRandomStringCanonical(8),
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	}

	out, err := json.Marshal(&jwks)
	assert.Nil(t, err, "%+v", err)

	return string(out)
}

func genTestIdentityProvider(spec *corev1.IdentityProvider_Spec) *corev1.IdentityProvider {
	return &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec:     spec,
	}
}

func TestIdentityProvider(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	sec, err := srv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec:   &corev1.Secret_Spec{},
		Status: &corev1.Secret_Status{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		},
	})
	assert.Nil(t, err)

	invalids := []*corev1.IdentityProvider{
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		},
		{
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_Github_{
					Github: &corev1.IdentityProvider_Spec_Github{
						ClientID: utilrand.GetRandomStringCanonical(8),
						ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
							Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
								FromSecret: sec.Metadata.Name,
							},
						},
					},
				},
			},
		},
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomStringCanonical(8),
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomStringCanonical(8),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomStringCanonical(8),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: utilrand.GetRandomStringCanonical(8),
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			DisplayName: strings.Repeat("a", idpMaxDisplayNameLen+1),
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomStringCanonical(8),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID: utilrand.GetRandomStringCanonical(32),
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID: utilrand.GetRandomStringCanonical(32),
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID:  utilrand.GetRandomString(32),
					IssuerURL: "https://accounts.google.com/.well-known/openid-configuration",
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID:  utilrand.GetRandomString(32),
					IssuerURL: "https://example.com?a=b",
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID:  utilrand.GetRandomString(32),
					IssuerURL: "https://example.com#frag",
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID:  utilrand.GetRandomString(32),
					IssuerURL: "https://user:pass@example.com",
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID:  utilrand.GetRandomString(32),
					IssuerURL: "https://example.com",
					Scopes:    []string{"profile", "profile"},
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID:  utilrand.GetRandomString(32),
					IssuerURL: "https://example.com",
					Scopes:    []string{"pro file"},
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID:        utilrand.GetRandomString(32),
					IssuerURL:       "https://example.com",
					IdentifierClaim: "my claim",
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{
					EntityID: utilrand.GetRandomStringCanonical(8),
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{
					MetadataType: &corev1.IdentityProvider_Spec_SAML_Metadata{
						Metadata: "   ",
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{
					MetadataType: &corev1.IdentityProvider_Spec_SAML_Metadata{
						Metadata: "<EntityDescriptor><IDPSSODescriptor></EntityDescriptor>",
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{
					MetadataType: &corev1.IdentityProvider_Spec_SAML_MetadataURL{
						MetadataURL: "http://example.com/metadata",
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{
					MetadataType: &corev1.IdentityProvider_Spec_SAML_MetadataURL{
						MetadataURL: "https://example.com/metadata",
					},
					EntityID: "entity id with spaces",
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
					Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_IssuerURL{
						IssuerURL: "https://example.com",
					},
					Issuer: "https://example.com",
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
					Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksURL{
						JwksURL: "https://example.com/jwks",
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
					Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksURL{
						JwksURL: "https://example.com/jwks?a=b",
					},
					Issuer: "https://example.com",
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
					Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksContent{
						JwksContent: "not-a-json",
					},
					Issuer: "https://example.com",
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
					Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksContent{
						JwksContent: `{"keys": []}`,
					},
					Issuer: "https://example.com",
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			AalRules: []*corev1.IdentityProvider_Spec_AALRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{MatchAny: true},
					},
				},
			},
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomString(32),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			AalRules: []*corev1.IdentityProvider_Spec_AALRule{
				{
					Aal: corev1.IdentityProvider_Spec_AALRule_AAL2,
				},
			},
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomString(32),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			PostAuthenticationRules: []*corev1.IdentityProvider_Spec_PostAuthenticationRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{MatchAny: true},
					},
				},
			},
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomString(32),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			PostAuthenticationRules: []*corev1.IdentityProvider_Spec_PostAuthenticationRule{
				{
					Effect: corev1.IdentityProvider_Spec_PostAuthenticationRule_ALLOW,
				},
			},
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomString(32),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
	}

	for _, invalid := range invalids {
		_, err = srv.CreateIdentityProvider(ctx, invalid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		var rules []*corev1.IdentityProvider_Spec_AALRule
		for i := 0; i < idpMaxRules+1; i++ {
			rules = append(rules, &corev1.IdentityProvider_Spec_AALRule{
				Condition: &corev1.Condition{
					Type: &corev1.Condition_MatchAny{MatchAny: true},
				},
				Aal: corev1.IdentityProvider_Spec_AALRule_AAL2,
			})
		}

		_, err = srv.CreateIdentityProvider(ctx, genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			AalRules: rules,
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomString(32),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		var rules []*corev1.IdentityProvider_Spec_PostAuthenticationRule
		for i := 0; i < idpMaxRules+1; i++ {
			rules = append(rules, &corev1.IdentityProvider_Spec_PostAuthenticationRule{
				Condition: &corev1.Condition{
					Type: &corev1.Condition_MatchAny{MatchAny: true},
				},
				Effect: corev1.IdentityProvider_Spec_PostAuthenticationRule_ALLOW,
			})
		}

		_, err = srv.CreateIdentityProvider(ctx, genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			PostAuthenticationRules: rules,
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomString(32),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	valids := []*corev1.IdentityProvider{
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			DisplayName:            "My Github Provider",
			DisableEmailAsIdentity: true,
			IsDisabled:             true,
			AalRules: []*corev1.IdentityProvider_Spec_AALRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{MatchAny: true},
					},
					Aal: corev1.IdentityProvider_Spec_AALRule_AAL2,
				},
			},
			PostAuthenticationRules: []*corev1.IdentityProvider_Spec_PostAuthenticationRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{MatchAny: true},
					},
					Effect: corev1.IdentityProvider_Spec_PostAuthenticationRule_DENY,
				},
			},
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomString(32),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID:            utilrand.GetRandomString(32),
					IssuerURL:           "https://example.com",
					Scopes:              []string{"profile", "email"},
					IdentifierClaim:     "sub",
					CheckEmailVerified:  true,
					UseUserInfoEndpoint: true,
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID:  utilrand.GetRandomString(32),
					IssuerURL: "https://accounts.google.com",
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{
					MetadataType: &corev1.IdentityProvider_Spec_SAML_MetadataURL{
						MetadataURL: "https://example.com/metadata?appid=1234",
					},
					EntityID:            "https://example.com",
					IdentifierAttribute: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
					ForceAuthn:          true,
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{
					MetadataType: &corev1.IdentityProvider_Spec_SAML_Metadata{
						Metadata: testSAMLMetadata,
					},
				},
			},
		}),
		genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
					Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksContent{
						JwksContent: genTestJWKSContent(t),
					},
					Issuer:   fmt.Sprintf("https://%s.example.com", utilrand.GetRandomStringCanonical(8)),
					Audience: utilrand.GetRandomStringCanonical(8),
				},
			},
		}),
	}

	for _, valid := range valids {
		item, err := srv.CreateIdentityProvider(ctx, valid)
		assert.Nil(t, err, "%+v", err)
		assert.NotEqual(t, corev1.IdentityProvider_Status_TYPE_UNKNOWN, item.Status.Type)

		_, err = srv.CreateIdentityProvider(ctx, valid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err), "%+v", err)
	}

	{
		issuer := fmt.Sprintf("https://%s.example.com", utilrand.GetRandomStringCanonical(8))
		_, err = srv.CreateIdentityProvider(ctx, genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
					Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksURL{
						JwksURL: fmt.Sprintf("https://%s.example.com", utilrand.GetRandomStringCanonical(8)),
					},
					Issuer: issuer,
				},
			},
		}))
		assert.Nil(t, err, "%+v", err)

		_, err = srv.CreateIdentityProvider(ctx, genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
					Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksURL{
						JwksURL: fmt.Sprintf("https://%s.example.com", utilrand.GetRandomStringCanonical(8)),
					},
					Issuer: issuer,
				},
			},
		}))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
}

func TestIdentityProviderOIDCIssuer(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	sec, err := srv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	genOIDC := func(issuerURL string) *corev1.IdentityProvider {
		return genTestIdentityProvider(&corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID:  utilrand.GetRandomString(32),
					IssuerURL: issuerURL,
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		})
	}

	host := fmt.Sprintf("https://%s.example.com", utilrand.GetRandomStringCanonical(8))

	item, err := srv.CreateIdentityProvider(ctx, genOIDC(fmt.Sprintf("%s/", host)))
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, host, item.Spec.GetOidc().IssuerURL)
	assert.Equal(t, corev1.IdentityProvider_Status_OIDC, item.Status.Type)

	_, err = srv.CreateIdentityProvider(ctx, genOIDC(host))
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)

	{
		item.Spec.DisplayName = utilrand.GetRandomStringCanonical(8)
		updated, err := srv.UpdateIdentityProvider(ctx, item)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, item.Spec.DisplayName, updated.Spec.DisplayName)
		assert.Equal(t, host, updated.Spec.GetOidc().IssuerURL)
	}

	{
		other, err := srv.CreateIdentityProvider(ctx,
			genOIDC(fmt.Sprintf("https://%s.example.com", utilrand.GetRandomStringCanonical(8))))
		assert.Nil(t, err, "%+v", err)

		other.Spec.GetOidc().IssuerURL = host
		_, err = srv.UpdateIdentityProvider(ctx, other)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		ret, err := srv.GetIdentityProvider(ctx, &metav1.GetOptions{Uid: item.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, item.Metadata.Uid, ret.Metadata.Uid)

		_, err = srv.GetIdentityProvider(ctx, &metav1.GetOptions{
			Name: utilrand.GetRandomStringCanonical(8),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
	}

	{
		_, err = srv.DeleteIdentityProvider(ctx, &metav1.DeleteOptions{Uid: item.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.DeleteIdentityProvider(ctx, &metav1.DeleteOptions{Uid: item.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)

		_, err = srv.CreateIdentityProvider(ctx, genOIDC(host))
		assert.Nil(t, err, "%+v", err)
	}
}

func TestIdentityProviderURLBoundaries(t *testing.T) {
	for _, arg := range []string{
		"", " ", "https://%", "https:///path", "ftp://example.com", "https://user:pass@example.com", "https://example.com#fragment",
		"https://example.com/" + strings.Repeat("a", idpMaxURLLen), string([]byte{0xff}),
	} {
		_, err := canonicalHTTPSURL(arg, "url", true)
		assert.NotNil(t, err, "%q", arg)
		_, err = canonicalOIDCIssuerURL(arg)
		assert.NotNil(t, err, "%q", arg)
	}
	for _, arg := range []string{"https://example.com?query", "https://example.com?"} {
		_, err := canonicalHTTPSURL(arg, "url", false)
		assert.NotNil(t, err)
		_, err = canonicalHTTPSURL(arg, "url", true)
		assert.Nil(t, err)
		_, err = canonicalOIDCIssuerURL(arg)
		assert.NotNil(t, err)
	}
	got, err := canonicalHTTPSURL(" HTTPS://EXAMPLE.COM/path?key=value ", "url", true)
	assert.Nil(t, err)
	assert.Equal(t, "https://example.com/path?key=value", got)
	assert.Equal(t, "", canonicalIssuerString("  "))
	assert.Equal(t, "non-url-issuer", canonicalIssuerString(" non-url-issuer/// "))
	assert.Equal(t, "https://example.com", canonicalIssuerString("HTTPS://EXAMPLE.COM/"))
}

func TestIdentityProviderStringBoundaries(t *testing.T) {
	for _, tc := range []struct {
		arg   string
		valid bool
	}{
		{"", true}, {"日本語", true}, {strings.Repeat("a", idpMaxDisplayNameLen), true},
		{strings.Repeat("a", idpMaxDisplayNameLen+1), false}, {"name\x00", false}, {"name\x7f", false}, {string([]byte{0xff}), false},
	} {
		assert.Equal(t, tc.valid, validateIdentityProviderDisplayName(tc.arg) == nil)
	}
	for _, tc := range []struct {
		arg      string
		required bool
		valid    bool
	}{
		{"", false, true}, {"", true, false}, {" \t ", true, false}, {"scope", true, true},
		{"a b", true, false}, {"a\x7f", true, false}, {string([]byte{0xff}), true, false},
		{strings.Repeat("a", 16), true, true}, {strings.Repeat("a", 17), true, false},
	} {
		assert.Equal(t, tc.valid, validateIdentityProviderStr(tc.arg, "field", 16, tc.required) == nil)
	}
	assert.Nil(t, validateIdentityProviderScopes([]string{"openid", "profile"}))
	for _, scopes := range [][]string{{"openid", "openid"}, {""}, {"invalid scope"}, make([]string, idpMaxScopes+1)} {
		assert.NotNil(t, validateIdentityProviderScopes(scopes))
	}
}
