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

package utils

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestGetAAL(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	{
		out := GetAAL(ctx, &GetAALReq{
			CelEngine: celEngine,
		})
		assert.Equal(t, corev1.Session_Status_Authentication_Info_AAL_UNSET, out)
	}

	{
		out := GetAAL(ctx, &GetAALReq{
			CelEngine: celEngine,
			Rules: []*corev1.IdentityProvider_Spec_AALRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
					Aal: corev1.IdentityProvider_Spec_AALRule_AAL3,
				},
			},
		})
		assert.Equal(t, corev1.Session_Status_Authentication_Info_AAL3, out)
	}

	{
		out := GetAAL(ctx, &GetAALReq{
			CelEngine: celEngine,
			Rules: []*corev1.IdentityProvider_Spec_AALRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `ctx.assertionMap.k1 == "v1"`,
						},
					},
					Aal: corev1.IdentityProvider_Spec_AALRule_AAL3,
				},
			},
			AssertionMap: map[string]any{
				"k1": "v1",
			},
		})
		assert.Equal(t, corev1.Session_Status_Authentication_Info_AAL3, out)
	}

	{
		out := GetAAL(ctx, &GetAALReq{
			CelEngine: celEngine,
			Rules: []*corev1.IdentityProvider_Spec_AALRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: "2 < 1",
						},
					},
					Aal: corev1.IdentityProvider_Spec_AALRule_AAL3,
				},

				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					Aal: corev1.IdentityProvider_Spec_AALRule_AAL2,
				},
			},
		})
		assert.Equal(t, corev1.Session_Status_Authentication_Info_AAL2, out)
	}
}

func TestPeekAssertionIssuer(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	type tknClaims struct {
		jwt.RegisteredClaims
	}

	{
		_, err := peekAssertionIssuer("")
		assert.NotNil(t, err)

		_, err = peekAssertionIssuer(utilrand.GetRandomString(200))
		assert.NotNil(t, err)
	}

	{
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.Nil(t, err)
		issuer := fmt.Sprintf("https://%s.example.com", utilrand.GetRandomStringCanonical(8))

		tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   utilrand.GetRandomStringCanonical(8),
				Issuer:    issuer,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		})

		tknStr, err := tkn.SignedString(priv)
		assert.Nil(t, err)

		res, err := peekAssertionIssuer(tknStr)
		assert.Nil(t, err)
		assert.Equal(t, issuer, res)
	}
}

func TestIsAssertionIssuerForIdentityProvider(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	type tknClaims struct {
		jwt.RegisteredClaims
	}

	{

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.Nil(t, err)
		issuer := fmt.Sprintf("https://%s.example.com", utilrand.GetRandomStringCanonical(8))

		tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   utilrand.GetRandomStringCanonical(8),
				Issuer:    issuer,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		})

		tknStr, err := tkn.SignedString(priv)
		assert.Nil(t, err)

		{
			assert.True(t, IsAssertionIssuerForIdentityProvider(&corev1.IdentityProvider{
				Spec: &corev1.IdentityProvider_Spec{
					Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
						OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
							Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_IssuerURL{
								IssuerURL: issuer,
							},
						},
					},
				},
				Status: &corev1.IdentityProvider_Status{
					Type: corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN,
				},
			}, tknStr))
		}

		{
			assert.True(t, IsAssertionIssuerForIdentityProvider(&corev1.IdentityProvider{
				Spec: &corev1.IdentityProvider_Spec{
					Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
						OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
							Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_IssuerURL{
								IssuerURL: issuer + "/",
							},
						},
					},
				},
				Status: &corev1.IdentityProvider_Status{
					Type: corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN,
				},
			}, tknStr))
		}
	}
}

type testRegisteredClaims struct {
	jwt.RegisteredClaims
}

func newTestAssertion(t *testing.T, issuer string) string {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(t, err)

	tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &testRegisteredClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   utilrand.GetRandomStringCanonical(8),
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	})

	ret, err := tkn.SignedString(priv)
	assert.Nil(t, err)

	return ret
}

func TestGetCallbackURL(t *testing.T) {
	assert.Equal(t, "https://example.com/callback", GetCallbackURL("example.com"))
	assert.Equal(t, "https://sub.example.com/callback", GetCallbackURL("sub.example.com"))
	assert.NotEqual(t, GetCallbackURL("a.com"), GetCallbackURL("b.com"))
}

func TestPeekAssertionIssuerEdgeCases(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		_, err := peekAssertionIssuer(strings.Repeat("a", 15001))
		assert.NotNil(t, err)
	}

	{
		_, err := peekAssertionIssuer("aaa.bbb.ccc")
		assert.NotNil(t, err)
	}

	{
		_, err := peekAssertionIssuer("not-a-jwt-at-all")
		assert.NotNil(t, err)
	}

	{
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		assert.Nil(t, err)

		tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &testRegisteredClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   utilrand.GetRandomStringCanonical(8),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			},
		})

		tknStr, err := tkn.SignedString(priv)
		assert.Nil(t, err)

		ret, err := peekAssertionIssuer(tknStr)
		assert.Nil(t, err)
		assert.Equal(t, "", ret)
	}

	{
		issuer := fmt.Sprintf("https://%s.example.com", utilrand.GetRandomStringCanonical(8))

		ret, err := peekAssertionIssuer(newTestAssertion(t, issuer))
		assert.Nil(t, err)
		assert.Equal(t, issuer, ret)
	}
}

func TestIsAssertionIssuerForIdentityProviderNegative(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	issuer := fmt.Sprintf("https://%s.example.com", utilrand.GetRandomStringCanonical(8))
	assertion := newTestAssertion(t, issuer)

	newIDP := func(status corev1.IdentityProvider_Status_Type,
		spec *corev1.IdentityProvider_Spec) *corev1.IdentityProvider {
		return &corev1.IdentityProvider{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: spec,
			Status: &corev1.IdentityProvider_Status{
				Type: status,
			},
		}
	}

	oidcSpec := func(issuerURL string) *corev1.IdentityProvider_Spec {
		return &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
				OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
					Type: &corev1.IdentityProvider_Spec_OIDCIdentityToken_IssuerURL{
						IssuerURL: issuerURL,
					},
				},
			},
		}
	}

	{
		assert.False(t, IsAssertionIssuerForIdentityProvider(
			newIDP(corev1.IdentityProvider_Status_OIDC, oidcSpec(issuer)), assertion))
	}

	{
		assert.False(t, IsAssertionIssuerForIdentityProvider(
			newIDP(corev1.IdentityProvider_Status_GITHUB, oidcSpec(issuer)), assertion))
	}

	{
		assert.False(t, IsAssertionIssuerForIdentityProvider(
			newIDP(corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN,
				&corev1.IdentityProvider_Spec{}), assertion))
	}

	{
		assert.False(t, IsAssertionIssuerForIdentityProvider(
			newIDP(corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN,
				oidcSpec("https://other.example.com")), assertion))
	}

	{
		assert.False(t, IsAssertionIssuerForIdentityProvider(
			newIDP(corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN,
				oidcSpec(issuer)), "not-a-jwt"))
	}

	{
		assert.False(t, IsAssertionIssuerForIdentityProvider(
			newIDP(corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN,
				oidcSpec(issuer)), ""))
	}

	{
		assert.True(t, IsAssertionIssuerForIdentityProvider(
			newIDP(corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN,
				&corev1.IdentityProvider_Spec{
					Type: &corev1.IdentityProvider_Spec_OidcIdentityToken{
						OidcIdentityToken: &corev1.IdentityProvider_Spec_OIDCIdentityToken{
							Issuer: issuer,
						},
					},
				}), assertion))
	}

	{
		assert.True(t, IsAssertionIssuerForIdentityProvider(
			newIDP(corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN,
				oidcSpec(issuer+"/")), assertion))
	}
}

func TestGetUserFromIdentifier(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	sec, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
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
	assert.Nil(t, err)

	idp, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name:        "github-1",
			DisplayName: "Github 1",
		},

		Spec: &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: "xxx",
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		},
		Status: &corev1.IdentityProvider_Status{
			Type: corev1.IdentityProvider_Status_GITHUB,
		},
	})
	assert.Nil(t, err)

	idpName := idp.Metadata.Name

	newUsr := func(identifier string, usrType corev1.User_Spec_Type) *corev1.User {
		usr := &corev1.User{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("usr-%s", utilrand.GetRandomStringLowercase(8)),
			},
			Spec: &corev1.User_Spec{
				Type: usrType,
			},
		}

		if identifier != "" {
			usr.Spec.Authentication = &corev1.User_Spec_Authentication{
				Identities: []*corev1.User_Spec_Authentication_Identity{
					{
						IdentityProvider: idpName,
						Identifier:       identifier,
					},
				},
			}
		}

		ret, err := adminSrv.CreateUser(ctx, usr)
		assert.Nil(t, err, "%+v", err)
		return ret
	}

	{
		_, err := GetUserFromIdentifier(ctx, &GetUserFromIdentifierOpts{
			OcteliumC:            fakeC.OcteliumC,
			IdentityProviderName: idpName,
			Identifier:           "",
			UserType:             corev1.User_Spec_WORKLOAD,
		})
		assert.NotNil(t, err)
	}

	{
		_, err := GetUserFromIdentifier(ctx, &GetUserFromIdentifierOpts{
			OcteliumC:            fakeC.OcteliumC,
			IdentityProviderName: idpName,
			Identifier:           utilrand.GetRandomStringCanonical(12),
			UserType:             corev1.User_Spec_WORKLOAD,
		})
		assert.NotNil(t, err)
	}

	{
		identifier := utilrand.GetRandomStringLowercase(10)
		usr := newUsr(identifier, corev1.User_Spec_WORKLOAD)

		ret, err := GetUserFromIdentifier(ctx, &GetUserFromIdentifierOpts{
			OcteliumC:            fakeC.OcteliumC,
			IdentityProviderName: idpName,
			Identifier:           identifier,
			UserType:             corev1.User_Spec_WORKLOAD,
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, usr.Metadata.Uid, ret.Metadata.Uid)
	}

	{
		identifier := utilrand.GetRandomStringLowercase(10)
		newUsr(identifier, corev1.User_Spec_WORKLOAD)

		_, err := GetUserFromIdentifier(ctx, &GetUserFromIdentifierOpts{
			OcteliumC:            fakeC.OcteliumC,
			IdentityProviderName: idpName,
			Identifier:           identifier,
			UserType:             corev1.User_Spec_HUMAN,
		})
		assert.NotNil(t, err)
	}

	{
		identifier := utilrand.GetRandomStringLowercase(10)
		usr := newUsr(identifier, corev1.User_Spec_WORKLOAD)

		usr.Spec.IsDisabled = true
		_, err := adminSrv.UpdateUser(ctx, usr)
		assert.Nil(t, err)

		_, err = GetUserFromIdentifier(ctx, &GetUserFromIdentifierOpts{
			OcteliumC:            fakeC.OcteliumC,
			IdentityProviderName: idpName,
			Identifier:           identifier,
			UserType:             corev1.User_Spec_WORKLOAD,
		})
		assert.NotNil(t, err)
	}

	{
		identifier := utilrand.GetRandomStringLowercase(10)
		usr := newUsr(identifier, corev1.User_Spec_WORKLOAD)

		stored, err := fakeC.OcteliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid: usr.Metadata.Uid,
		})
		assert.Nil(t, err)

		stored.Status.IsLocked = true
		_, err = fakeC.OcteliumC.CoreC().UpdateUser(ctx, stored)
		assert.Nil(t, err)

		_, err = GetUserFromIdentifier(ctx, &GetUserFromIdentifierOpts{
			OcteliumC:            fakeC.OcteliumC,
			IdentityProviderName: idpName,
			Identifier:           identifier,
			UserType:             corev1.User_Spec_WORKLOAD,
		})
		assert.NotNil(t, err)
	}

	{
		identifier := utilrand.GetRandomStringLowercase(10)
		newUsr(identifier, corev1.User_Spec_WORKLOAD)

		_, err := GetUserFromIdentifier(ctx, &GetUserFromIdentifierOpts{
			OcteliumC:            fakeC.OcteliumC,
			IdentityProviderName: utilrand.GetRandomStringCanonical(8),
			Identifier:           identifier,
			UserType:             corev1.User_Spec_WORKLOAD,
		})
		assert.NotNil(t, err)
	}

	{
		identifier := utilrand.GetRandomStringLowercase(10)
		newUsr(identifier, corev1.User_Spec_WORKLOAD)

		_, err := GetUserFromIdentifier(ctx, &GetUserFromIdentifierOpts{
			OcteliumC:            fakeC.OcteliumC,
			IdentityProviderName: idpName,
			Identifier:           strings.ToUpper(identifier),
			UserType:             corev1.User_Spec_WORKLOAD,
		})
		assert.NotNil(t, err)
	}
}
