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

package authserver

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
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticateWithAuthenticationToken(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		_, err = srv.doAuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}

	{

		authTkn, err := srv.jwkCtl.CreateCredential(&corev1.Credential{
			Metadata: &metav1.Metadata{
				Uid:       vutils.UUIDv4(),
				CreatedAt: pbutils.Now(),
			},
			Spec: &corev1.Credential_Spec{
				ExpiresAt: pbutils.Timestamp(pbutils.Now().AsTime().Add(3 * time.Hour)),
			},
			Status: &corev1.Credential_Status{
				TokenID: vutils.UUIDv4(),
			},
		})
		assert.Nil(t, err)
		_, err = srv.doAuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: authTkn,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usrT.Usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENT,
				ExpiresAt:   pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		resp, err := srv.doAuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: tknResp.GetAuthenticationToken().AuthenticationToken,
		})
		assert.Nil(t, err)
		claims, err := srv.jwkCtl.VerifyAccessToken(resp.AccessToken)
		assert.Nil(t, err)
		sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: claims.SessionUID,
		})
		assert.Nil(t, err)

		assert.Equal(t, sess.Status.UserRef.Uid, usrT.Usr.Metadata.Uid)

		{
			_, err := srv.doAuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
				AuthenticationToken: tknResp.GetAuthenticationToken().AuthenticationToken,
			})
			assert.Nil(t, err)
		}
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:               usrT.Usr.Metadata.Name,
				Type:               corev1.Credential_Spec_AUTH_TOKEN,
				SessionType:        corev1.Session_Status_CLIENT,
				ExpiresAt:          pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
				MaxAuthentications: 1,
				AutoDelete:         true,
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		resp, err := srv.doAuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: tknResp.GetAuthenticationToken().AuthenticationToken,
		})
		assert.Nil(t, err)
		claims, err := srv.jwkCtl.VerifyAccessToken(resp.AccessToken)
		assert.Nil(t, err)
		sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: claims.SessionUID,
		})
		assert.Nil(t, err)

		assert.Equal(t, sess.Status.UserRef.Uid, usrT.Usr.Metadata.Uid)

		{
			_, err := srv.doAuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
				AuthenticationToken: tknResp.GetAuthenticationToken().AuthenticationToken,
			})
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsUnauthenticated(err))
		}
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usrT.Usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENT,
				ExpiresAt:   pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		_, err = srv.doAuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: tknResp.GetAuthenticationToken().AuthenticationToken,
		})
		assert.Nil(t, err)
	}
}

func TestAuthenticateWithAssertion(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		_, err = srv.doAuthenticateWithAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}
	{
		_, err = srv.doAuthenticateWithAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
			IdentityProviderRef: &metav1.ObjectReference{},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}
	{
		_, err = srv.doAuthenticateWithAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
			IdentityProviderRef: &metav1.ObjectReference{
				Uid: vutils.UUIDv4(),
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}
	{
		_, err = srv.doAuthenticateWithAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
			IdentityProviderRef: &metav1.ObjectReference{
				Name: utilrand.GetRandomStringCanonical(8),
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}

	{

		type tknClaims struct {
			jwt.RegisteredClaims
			ClaimA string `json:"cla,omitempty"`
		}

		cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

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

		err = srv.setIdentityProviders(ctx)
		assert.Nil(t, err)

		usr, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
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

			assertionStr, err := tkn.SignedString(priv)
			assert.Nil(t, err)

			resp, err := srv.doAuthenticateWithAssertion(ctx, &authv1.AuthenticateWithAssertionRequest{
				IdentityProviderRef: &metav1.ObjectReference{
					Name: idp.Metadata.Name,
				},
				Assertion: assertionStr,
			})
			assert.Nil(t, err)

			claims, err := srv.jwkCtl.VerifyAccessToken(resp.AccessToken)
			assert.Nil(t, err)

			sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
				Uid: claims.SessionUID,
			})
			assert.Nil(t, err)
			assert.Equal(t, usr.Usr.Metadata.Uid, sess.Status.UserRef.Uid)

		}

	}
}

func TestAuthenticateWithRefreshToken(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usrT.Usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENT,
				ExpiresAt:   pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		resp, err := srv.doAuthenticateWithAuthenticationToken(ctx, &authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: tknResp.GetAuthenticationToken().AuthenticationToken,
		})

		resp2, err := srv.doAuthenticateWithRefreshToken(getCtxRTSessTkn(resp), &authv1.AuthenticateWithRefreshTokenRequest{})
		assert.Nil(t, err)

		{
			sess, err := srv.getSessionFromRefreshToken(ctx, resp2.RefreshToken)
			assert.Nil(t, err)
			testInvalidateAccessToken(t, srv.octeliumC, sess)
			_, err = srv.doAuthenticateWithRefreshToken(getCtxRTSessTkn(resp), &authv1.AuthenticateWithRefreshTokenRequest{})
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsUnauthenticated(err))
		}

		_, err = srv.doAuthenticateWithRefreshToken(getCtxRTSessTkn(resp2), &authv1.AuthenticateWithRefreshTokenRequest{})
		assert.Nil(t, err, "%+v", err)
	}
}

func TestGetSessionFromGRPCCtx(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		_, err := srv.getSessionFromGRPCCtx(ctx)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}
	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		resp, err := srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.Nil(t, err)
		assert.Equal(t, usrT.Session.Metadata.Uid, resp.Metadata.Uid)
	}
	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		sess, err := srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.Nil(t, err)

		sess.Status.Authentication.TokenID = vutils.UUIDv4()
		sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}
	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		sess, err := srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.Nil(t, err)

		sess.Spec.State = corev1.Session_Spec_REJECTED
		sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))

		sess.Spec.State = corev1.Session_Spec_PENDING
		sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.Nil(t, err)

		sess.Spec.State = corev1.Session_Spec_ACTIVE
		sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.Nil(t, err)
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		sess, err := srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.Nil(t, err)

		sess.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(-1 * time.Minute))
		sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))

		sess.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(10 * time.Minute))
		sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.Nil(t, err)
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		sess, err := srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.Nil(t, err)

		sess.Status.Authentication.TokenID = vutils.UUIDv4()
		sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		sess, err := srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.Nil(t, err)

		sess.Status.Authentication.SetAt = pbutils.Timestamp(time.Now().Add(-1 * time.Hour))
		sess.Status.Authentication.RefreshTokenDuration = &metav1.Duration{
			Type: &metav1.Duration_Minutes{
				Minutes: 30,
			},
		}
		sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))

		sess.Status.Authentication.SetAt = pbutils.Timestamp(time.Now().Add(-1 * time.Hour))
		sess.Status.Authentication.RefreshTokenDuration = &metav1.Duration{
			Type: &metav1.Duration_Minutes{
				Minutes: 120,
			},
		}
		sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		_, err = srv.getSessionFromGRPCCtx(getCtxRT(usrT))
		assert.Nil(t, err)
	}
}

func TestAuthenticateWithAuthenticator(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{

		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		usrT.Device.Status.OsType = corev1.Device_Status_LINUX

		usrT.Device, err = srv.octeliumC.CoreC().UpdateDevice(ctx, usrT.Device)
		assert.Nil(t, err)

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		/*
			factor, err := srv.octeliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},

				Spec: &corev1.IdentityProvider_Spec{
					Type: &corev1.IdentityProvider_Spec_Totp{
						Totp: &corev1.IdentityProvider_Spec_TOTP{},
					},
				},
			})

			assert.Nil(t, err)
		*/

		authn, err := srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Authenticator_Spec{},
			Status: &corev1.Authenticator_Status{
				UserRef: umetav1.GetObjectReference(usrT.Usr),
				Type:    corev1.Authenticator_Status_TOTP,
				// IdentityProviderRef: umetav1.GetObjectReference(factor),
			},
		})
		assert.Nil(t, err)

		cc, err = srv.octeliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)

		usrT.Usr, err = srv.octeliumC.CoreC().UpdateUser(ctx, usrT.Usr)
		assert.Nil(t, err)

		usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
		assert.Nil(t, err)
		usrT.Resync()

		usrT.Resync()

		authn, err = srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
			Uid: authn.Metadata.Uid,
		})
		assert.Nil(t, err)

		getSecret := func(ctx context.Context, usr *corev1.User) (string, error) {
			authn, err := tst.C.OcteliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
				Uid: authn.Metadata.Uid,
			})
			assert.Nil(t, err)
			info := authn.Status.GetInfo().GetTotp().GetSharedSecret()

			plaintext, err := authenticators.DecryptData(ctx, fakeC.OcteliumC, info)
			if err != nil {
				return "", err
			}

			return string(plaintext), nil
		}

		authBeginResp, err := srv.doRegisterAuthenticatorBegin(getCtxRT(usrT), &authv1.RegisterAuthenticatorBeginRequest{
			AuthenticatorRef: umetav1.GetObjectReference(authn),
		})
		assert.Nil(t, err)

		k, err := otp.NewKeyFromURL(authBeginResp.ChallengeRequest.GetTotp().Url)
		assert.Nil(t, err)

		{
			passcode, err := totp.GenerateCode(k.Secret(), time.Now())
			assert.Nil(t, err)

			postResp, err := srv.doRegisterAuthenticatorFinish(getCtxRT(usrT), &authv1.RegisterAuthenticatorFinishRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Totp{
						Totp: &authv1.ChallengeResponse_TOTP{
							Response: passcode,
						},
					},
				},
			})
			assert.Nil(t, err)
			assert.NotNil(t, postResp)
		}

		{

			secret, err := getSecret(ctx, usrT.Usr)
			assert.Nil(t, err)
			passcode, err := totp.GenerateCode(secret, time.Now())
			assert.Nil(t, err)

			_, err = srv.doAuthenticateAuthenticatorBegin(getCtxRT(usrT), &authv1.AuthenticateAuthenticatorBeginRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
			})
			assert.Nil(t, err, "%+v", err)

			postResp, err := srv.doAuthenticateWithAuthenticator(getCtxRT(usrT), &authv1.AuthenticateWithAuthenticatorRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Totp{
						Totp: &authv1.ChallengeResponse_TOTP{
							Response: passcode,
						},
					},
				},
			})
			assert.Nil(t, err, "%+v", err)
			assert.NotNil(t, postResp, "%+v", err)
		}

	}
}
