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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestProvider(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	type tknClaims struct {
		jwt.RegisteredClaims
		ClaimA string `json:"cla,omitempty"`
	}

	{
		// Various typical flows
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.Nil(t, err)
		k1 := jose.JSONWebKey{
			Key:       priv,
			KeyID:     utilrand.GetRandomStringCanonical(6),
			Algorithm: string(jose.RS256),
		}
		jwks := jose.JSONWebKeySet{}
		jwks.Keys = append(jwks.Keys, k1)

		jwksJSON, err := json.Marshal(jwks)
		assert.Nil(t, err, "%+v", err)

		zap.L().Debug("JWKS", zap.String("jwks", string(jwksJSON)))

		issuer := "https://auth-issuer.example.com"

		idp, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.IdentityProvider_Spec{
				Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
					OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
						Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksContent{
							JwksContent: string(jwksJSON),
						},
						Issuer:   issuer,
						Audience: cc.Status.Domain,
					},
				},
			},
		})
		assert.Nil(t, err)

		provider, err := NewConnector(ctx, &utils.ProviderOpts{
			OcteliumC:     fakeC.OcteliumC,
			ClusterConfig: cc,
			Provider:      idp,
		})
		assert.Nil(t, err)

		{
			usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, nil, nil)
			assert.Nil(t, err)

			usr.Usr.Spec.Type = corev1.User_Spec_WORKLOAD
			usr.Usr.Spec.Authentication = &corev1.User_Spec_Authentication{
				Identities: []*corev1.User_Spec_Authentication_Identity{
					{
						IdentityProvider: idp.Metadata.Name,
						Identifier:       utilrand.GetRandomStringCanonical(8),
					},
				},
			}
			usr.Usr, err = adminSrv.UpdateUser(ctx, usr.Usr)
			assert.Nil(t, err, "%+v", err)

			{
				// Correctly
				tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   usr.Usr.Spec.Authentication.Identities[0].Identifier,
						Issuer:    issuer,
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Audience:  jwt.ClaimStrings{cc.Status.Domain},
					},
				})
				tkn.Header["kid"] = k1.KeyID

				tknStr, err := tkn.SignedString(priv)
				assert.Nil(t, err)

				authUsr, _, err := provider.AuthenticateAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
					IdentityProviderRef: &metav1.ObjectReference{
						Name: idp.Metadata.Name,
					},
					Assertion: tknStr,
				})
				assert.Nil(t, err)
				assert.Equal(t, usr.Usr.Metadata.Uid, authUsr.Metadata.Uid)
			}

			{
				// Without audience
				tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   usr.Usr.Spec.Authentication.Identities[0].Identifier,
						Issuer:    issuer,
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
					},
				})
				tkn.Header["kid"] = k1.KeyID

				tknStr, err := tkn.SignedString(priv)
				assert.Nil(t, err)

				_, _, err = provider.AuthenticateAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
					IdentityProviderRef: &metav1.ObjectReference{
						Name: idp.Metadata.Name,
					},
					Assertion: tknStr,
				})
				assert.NotNil(t, err)
			}

			{
				// Invalid audience
				tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   usr.Usr.Spec.Authentication.Identities[0].Identifier,
						Issuer:    issuer,
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Audience:  jwt.ClaimStrings{"invalid-audience"},
					},
				})
				tkn.Header["kid"] = k1.KeyID

				tknStr, err := tkn.SignedString(priv)
				assert.Nil(t, err)

				_, _, err = provider.AuthenticateAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
					IdentityProviderRef: &metav1.ObjectReference{
						Name: idp.Metadata.Name,
					},
					Assertion: tknStr,
				})
				assert.NotNil(t, err)
			}

			{
				// Empty issuer
				tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   usr.Usr.Spec.Authentication.Identities[0].Identifier,
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Audience:  jwt.ClaimStrings{cc.Status.Domain},
					},
				})
				tkn.Header["kid"] = k1.KeyID

				tknStr, err := tkn.SignedString(priv)
				assert.Nil(t, err)

				_, _, err = provider.AuthenticateAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
					IdentityProviderRef: &metav1.ObjectReference{
						Name: idp.Metadata.Name,
					},
					Assertion: tknStr,
				})
				assert.NotNil(t, err)
			}

			{
				// Invalid issuer
				tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   usr.Usr.Spec.Authentication.Identities[0].Identifier,
						Issuer:    "https://some-other-issuer.org",
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Audience:  jwt.ClaimStrings{cc.Status.Domain},
					},
				})
				tkn.Header["kid"] = k1.KeyID

				tknStr, err := tkn.SignedString(priv)
				assert.Nil(t, err)

				_, _, err = provider.AuthenticateAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
					IdentityProviderRef: &metav1.ObjectReference{
						Name: idp.Metadata.Name,
					},
					Assertion: tknStr,
				})
				assert.NotNil(t, err)
			}

			{
				// No subject
				tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Issuer:    issuer,
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Audience:  jwt.ClaimStrings{cc.Status.Domain},
					},
				})
				tkn.Header["kid"] = k1.KeyID

				tknStr, err := tkn.SignedString(priv)
				assert.Nil(t, err)

				_, _, err = provider.AuthenticateAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
					IdentityProviderRef: &metav1.ObjectReference{
						Name: idp.Metadata.Name,
					},
					Assertion: tknStr,
				})
				assert.NotNil(t, err)
			}

			{
				// Non-existent subject
				tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   "non-existent-subject",
						Issuer:    issuer,
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Audience:  jwt.ClaimStrings{cc.Status.Domain},
					},
				})
				tkn.Header["kid"] = k1.KeyID

				tknStr, err := tkn.SignedString(priv)
				assert.Nil(t, err)

				_, _, err = provider.AuthenticateAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
					IdentityProviderRef: &metav1.ObjectReference{
						Name: idp.Metadata.Name,
					},
					Assertion: tknStr,
				})
				assert.NotNil(t, err)
			}

			{
				// Another key
				anotherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
				assert.Nil(t, err)
				tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   usr.Usr.Spec.Authentication.Identities[0].Identifier,
						Issuer:    issuer,
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Audience:  jwt.ClaimStrings{cc.Status.Domain},
					},
				})
				tkn.Header["kid"] = k1.KeyID

				tknStr, err := tkn.SignedString(anotherPriv)
				assert.Nil(t, err)

				_, _, err = provider.AuthenticateAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
					IdentityProviderRef: &metav1.ObjectReference{
						Name: idp.Metadata.Name,
					},
					Assertion: tknStr,
				})
				assert.NotNil(t, err)
			}

		}

	}

	/*
		{
			// Test conditions
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			assert.Nil(t, err)
			k1 := jose.JSONWebKey{
				Key:       priv,
				KeyID:     utilrand.GetRandomStringCanonical(6),
				Algorithm: string(jose.RS256),
			}
			jwks := jose.JSONWebKeySet{}
			jwks.Keys = append(jwks.Keys, k1)

			jwksJSON, err := json.Marshal(jwks)
			assert.Nil(t, err, "%+v", err)

			zap.L().Debug("JWKS", zap.String("jwks", string(jwksJSON)))

			issuer := "https://auth-issuer.example.com"

			idp, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec: &corev1.IdentityProvider_Spec{
					Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
						OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
							Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_JwksContent{
								JwksContent: string(jwksJSON),
							},
							Issuer:   issuer,
							Audience: cc.Status.Domain,
							Conditions: []string{
								`claims.cla == "val1"`,
							},
						},
					},
				},
			})
			assert.Nil(t, err)

			provider, err := NewConnector(ctx, &utils.ProviderOpts{
				OcteliumC:     fakeC.OcteliumC,
				ClusterConfig: cc,
				Provider:      idp,
			})
			assert.Nil(t, err)

			{
				usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, nil, nil)
				assert.Nil(t, err)

				usr.Usr.Spec.Type = corev1.User_Spec_WORKLOAD

				usr.Usr.Spec.Authentication = &corev1.User_Spec_Authentication{
					Identities: []*corev1.User_Spec_Authentication_Identity{
						{
							IdentityProvider: idp.Metadata.Name,
							Identifier:       utilrand.GetRandomStringCanonical(8),
						},
					},
				}
				usr.Usr, err = adminSrv.UpdateUser(ctx, usr.Usr)
				assert.Nil(t, err, "%+v", err)

				{
					// Correctly
					tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
						ClaimA: "val1",
						RegisteredClaims: jwt.RegisteredClaims{
							Subject:   usr.Usr.Spec.Authentication.Identities[0].Identifier,
							Issuer:    issuer,
							IssuedAt:  jwt.NewNumericDate(time.Now()),
							ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
							Audience:  jwt.ClaimStrings{cc.Status.Domain},
						},
					})
					tkn.Header["kid"] = k1.KeyID

					tknStr, err := tkn.SignedString(priv)
					assert.Nil(t, err)

					authUsr, _, err := provider.AuthenticateAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
						IdentityProviderRef: &metav1.ObjectReference{
							Name: idp.Metadata.Name,
						},
						Assertion: tknStr,
					})
					assert.Nil(t, err)
					assert.Equal(t, usr.Usr.Metadata.Uid, authUsr.Metadata.Uid)
				}

				{
					// Invalid condition
					tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
						ClaimA: "invalid-val",
						RegisteredClaims: jwt.RegisteredClaims{
							Subject:   usr.Usr.Spec.Authentication.Identities[0].Identifier,
							Issuer:    issuer,
							IssuedAt:  jwt.NewNumericDate(time.Now()),
							ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
							Audience:  jwt.ClaimStrings{cc.Status.Domain},
						},
					})
					tkn.Header["kid"] = k1.KeyID

					tknStr, err := tkn.SignedString(priv)
					assert.Nil(t, err)

					_, _, err = provider.AuthenticateAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
						IdentityProviderRef: &metav1.ObjectReference{
							Name: idp.Metadata.Name,
						},
						Assertion: tknStr,
					})
					assert.NotNil(t, err)
				}
			}

		}
	*/
}
