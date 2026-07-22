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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v4"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestHandleOAuth2(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	usrT, err := tstuser.NewUserWithType(srv.octeliumC,
		adminSrv, nil, nil, corev1.User_Spec_WORKLOAD, corev1.Session_Status_CLIENTLESS)
	assert.Nil(t, err)

	cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Credential_Spec{
			User:        usrT.Usr.Metadata.Name,
			Type:        corev1.Credential_Spec_OAUTH2,
			SessionType: corev1.Session_Status_CLIENTLESS,
		},
	})
	assert.Nil(t, err, "%+v", err)

	tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
		CredentialRef: umetav1.GetObjectReference(cred),
	})
	assert.Nil(t, err)

	{

		reqHTTP := httptest.NewRequest("POST", "http://localhost/auth/v1/oauth2/token", nil)
		reqHTTP.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.handleOAuth2Token(w, reqHTTP)
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)
	}

	{

		reqBody := map[string]string{
			"client_id":     tknResp.GetOauth2Credentials().ClientID,
			"client_secret": tknResp.GetOauth2Credentials().ClientSecret,
			"grant_type":    "client_credentials",
		}
		reqBodyBytes, err := json.Marshal(&reqBody)
		assert.Nil(t, err)
		reqHTTP := httptest.NewRequest("POST", "http://localhost/auth/v1/oauth2/token", bytes.NewBuffer(reqBodyBytes))
		reqHTTP.Header.Add("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.handleOAuth2Token(w, reqHTTP)
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)
	}

	{
		data := url.Values{}
		data.Set("client_id", tknResp.GetOauth2Credentials().ClientID)
		data.Set("client_secret", tknResp.GetOauth2Credentials().ClientSecret)

		reqHTTP := httptest.NewRequest("POST", "http://localhost/auth/v1/oauth2/token", strings.NewReader(data.Encode()))
		reqHTTP.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.handleOAuth2Token(w, reqHTTP)
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)
	}

	{
		data := url.Values{}
		data.Set("client_id", "invalid_client_id")
		data.Set("client_secret", tknResp.GetOauth2Credentials().ClientSecret)
		data.Set("grant_type", "client_credentials")

		reqHTTP := httptest.NewRequest("POST", "http://localhost/auth/v1/oauth2/token", strings.NewReader(data.Encode()))
		reqHTTP.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.handleOAuth2Token(w, reqHTTP)
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusUnauthorized)
	}

	{
		data := url.Values{}
		data.Set("client_id", tknResp.GetOauth2Credentials().ClientID)
		data.Set("client_secret", tknResp.GetOauth2Credentials().ClientSecret)
		data.Set("grant_type", "client_credentials")

		{
			reqHTTP := httptest.NewRequest("POST", "http://localhost/auth/v1/oauth2/token", strings.NewReader(data.Encode()))
			reqHTTP.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			srv.handleOAuth2Token(w, reqHTTP)
			resp := w.Result()
			assert.Equal(t, resp.StatusCode, http.StatusOK)

			bb, err := io.ReadAll(resp.Body)
			assert.Nil(t, err)
			resp.Body.Close()

			ret := &oauthAccessTokenResponse{}
			err = json.Unmarshal(bb, ret)
			assert.Nil(t, err)

			claims, err := srv.jwkCtl.VerifyAccessToken(ret.AccessToken)
			assert.Nil(t, err)

			sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: claims.SessionUID})
			assert.Nil(t, err)

			assert.Equal(t, usrT.Usr.Metadata.Uid, sess.Status.UserRef.Uid)
			assert.NotEqual(t, 0, ret.ExpiresIn)
			assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
			assert.Equal(t, 0, len(sess.Status.LastAuthentications))
		}

		{
			reqHTTP := httptest.NewRequest("POST", "http://localhost/auth/v1/oauth2/token", strings.NewReader(data.Encode()))
			reqHTTP.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			srv.handleOAuth2Token(w, reqHTTP)
			resp := w.Result()
			assert.Equal(t, resp.StatusCode, http.StatusOK)

			bb, err := io.ReadAll(resp.Body)
			assert.Nil(t, err)
			resp.Body.Close()

			ret := &oauthAccessTokenResponse{}
			err = json.Unmarshal(bb, ret)
			assert.Nil(t, err)

			claims, err := srv.jwkCtl.VerifyAccessToken(ret.AccessToken)
			assert.Nil(t, err)

			sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: claims.SessionUID})
			assert.Nil(t, err)

			assert.Equal(t, usrT.Usr.Metadata.Uid, sess.Status.UserRef.Uid)
			assert.NotEqual(t, 0, ret.ExpiresIn)
			assert.Equal(t, 1, len(sess.Status.LastAuthentications))
			assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)

			tkn, err := srv.octeliumC.CoreC().GetCredential(ctx, &rmetav1.GetOptions{
				Uid: sess.Status.CredentialRef.Uid,
			})
			assert.Nil(t, err)

			sessList, err := srv.octeliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{
					urscsrv.FilterFieldEQValStr("status.credentialRef.uid", tkn.Metadata.Uid),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, 1, len(sessList.Items))
		}

		{
			reqHTTP := httptest.NewRequest("POST", "http://localhost/auth/v1/oauth2/token", strings.NewReader(data.Encode()))
			reqHTTP.Header.Add("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			srv.handleOAuth2Token(w, reqHTTP)
			resp := w.Result()
			assert.Equal(t, resp.StatusCode, http.StatusOK)

			bb, err := io.ReadAll(resp.Body)
			assert.Nil(t, err)
			resp.Body.Close()

			ret := &oauthAccessTokenResponse{}
			err = json.Unmarshal(bb, ret)
			assert.Nil(t, err)

			claims, err := srv.jwkCtl.VerifyAccessToken(ret.AccessToken)
			assert.Nil(t, err)

			sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: claims.SessionUID})
			assert.Nil(t, err)

			assert.Equal(t, usrT.Usr.Metadata.Uid, sess.Status.UserRef.Uid)
			assert.NotEqual(t, 0, ret.ExpiresIn)
			assert.Equal(t, 2, len(sess.Status.LastAuthentications))
			assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)

			tkn, err := srv.octeliumC.CoreC().GetCredential(ctx, &rmetav1.GetOptions{
				Uid: sess.Status.CredentialRef.Uid,
			})
			assert.Nil(t, err)

			sessList, err := srv.octeliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{
					urscsrv.FilterFieldEQValStr("status.credentialRef.uid", tkn.Metadata.Uid),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, 1, len(sessList.Items))
		}

	}
}

func TestHandleOAuth2Metadata(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	{

		reqHTTP := httptest.NewRequest("GET", "http://localhost/auth/v1/oauth2/token", nil)
		w := httptest.NewRecorder()
		srv.handleOAuth2Metadata(w, reqHTTP)
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		bb, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)
		resp.Body.Close()
		var oauth2Metadata oauth2Metadata
		err = json.Unmarshal(bb, &oauth2Metadata)
		assert.Nil(t, err)

		assert.Equal(t, srv.rootURL, oauth2Metadata.Issuer)
	}
}

func TestHandleOAuth2Assertion(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	type tknClaims struct {
		jwt.RegisteredClaims
	}

	{
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
						Audience: clusterCfg.Status.Domain,
					},
				},
			},
			Status: &corev1.IdentityProvider_Status{
				Type: corev1.IdentityProvider_Status_OIDC_IDENTITY_TOKEN,
			},
		})
		assert.Nil(t, err)

		err = srv.setIdentityProviders(ctx)
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
				tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, &tknClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   usr.Usr.Spec.Authentication.Identities[0].Identifier,
						Issuer:    issuer,
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Audience:  jwt.ClaimStrings{clusterCfg.Status.Domain},
					},
				})
				tkn.Header["kid"] = k1.KeyID

				tknStr, err := tkn.SignedString(priv)
				assert.Nil(t, err)

				data := url.Values{}
				data.Set("client_assertion_type", assertionTypeJWTBearer)
				data.Set("client_assertion", tknStr)
				data.Set("grant_type", "client_credentials")

				{
					reqHTTP := httptest.NewRequest("POST", "http://localhost/auth/v1/oauth2/token", strings.NewReader(data.Encode()))
					reqHTTP.Header.Add("Content-Type", "application/x-www-form-urlencoded")
					w := httptest.NewRecorder()
					srv.handleOAuth2Token(w, reqHTTP)
					resp := w.Result()
					assert.Equal(t, resp.StatusCode, http.StatusOK)

					bb, err := io.ReadAll(resp.Body)
					assert.Nil(t, err)
					resp.Body.Close()

					ret := &oauthAccessTokenResponse{}
					err = json.Unmarshal(bb, ret)
					assert.Nil(t, err)

					claims, err := srv.jwkCtl.VerifyAccessToken(ret.AccessToken)
					assert.Nil(t, err)

					sess, err := srv.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: claims.SessionUID})
					assert.Nil(t, err)

					assert.Equal(t, usr.Usr.Metadata.Uid, sess.Status.UserRef.Uid)
					assert.NotEqual(t, 0, ret.ExpiresIn)
					assert.Equal(t, sess.Status.Authentication.TokenID, claims.TokenID)
					assert.Equal(t, 0, len(sess.Status.LastAuthentications))
				}
			}
		}
	}
}

type oauth2TestResult struct {
	statusCode int
	token      *oauthAccessTokenResponse
	errResp    *oauth2ErrorResponse
}

func doOAuth2TokenReq(t *testing.T, srv *server, data url.Values) *oauth2TestResult {
	req := httptest.NewRequest("POST", "http://localhost/oauth2/token",
		strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	srv.handleOAuth2Token(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	bb, err := io.ReadAll(resp.Body)
	assert.Nil(t, err)

	ret := &oauth2TestResult{
		statusCode: resp.StatusCode,
	}

	if resp.StatusCode == http.StatusOK {
		ret.token = &oauthAccessTokenResponse{}
		assert.Nil(t, json.Unmarshal(bb, ret.token))
		return ret
	}

	ret.errResp = &oauth2ErrorResponse{}
	json.Unmarshal(bb, ret.errResp)

	return ret
}

func newOAuth2Credential(t *testing.T, ctx context.Context,
	adminSrv *admin.Server, usrName string) (*corev1.Credential, string, string) {

	cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Credential_Spec{
			User:        usrName,
			Type:        corev1.Credential_Spec_OAUTH2,
			SessionType: corev1.Session_Status_CLIENTLESS,
		},
	})
	assert.Nil(t, err, "%+v", err)

	tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
		CredentialRef: umetav1.GetObjectReference(cred),
	})
	assert.Nil(t, err)

	return cred,
		tknResp.GetOauth2Credentials().ClientID,
		tknResp.GetOauth2Credentials().ClientSecret
}

func TestCheckAndGetOAuthScopeStr(t *testing.T) {

	{
		scopes, err := checkAndGetOAuthScopeStr("")
		assert.Nil(t, err)
		assert.Nil(t, scopes)
	}

	{
		_, err := checkAndGetOAuthScopeStr(utilrand.GetRandomStringCanonical(2049))
		assert.NotNil(t, err)
	}

	{
		_, err := checkAndGetOAuthScopeStr(strings.Repeat("a", 2049))
		assert.NotNil(t, err)
	}

	{
		_, err := checkAndGetOAuthScopeStr("日本語テスト")
		assert.NotNil(t, err)
	}

	{
		_, err := checkAndGetOAuthScopeStr(fmt.Sprintf("valid %s", strings.Repeat("日", 10)))
		assert.NotNil(t, err)
	}
}

func TestReturnOAuth2Err(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	type entry struct {
		errCode    string
		statusCode int
	}

	entries := []entry{
		{"invalid_request", 400},
		{"invalid_client", 401},
		{"invalid_scope", 401},
		{"unsupported_grant_type", 400},
		{"server_error", 500},
	}

	for _, e := range entries {
		w := httptest.NewRecorder()
		srv.returnOAuth2Err(w, e.errCode, e.statusCode)

		resp := w.Result()
		assert.Equal(t, e.statusCode, resp.StatusCode, "%s", e.errCode)

		bb, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)
		resp.Body.Close()

		ret := &oauth2ErrorResponse{}
		assert.Nil(t, json.Unmarshal(bb, ret), "%s", e.errCode)
		assert.Equal(t, e.errCode, ret.Error)
	}
}

func TestHandleOAuth2TokenGrantType(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	{
		data := url.Values{}
		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusBadRequest, res.statusCode)
		assert.Equal(t, "unsupported_grant_type", res.errResp.Error)
	}

	{
		data := url.Values{}
		data.Set("grant_type", "authorization_code")
		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusBadRequest, res.statusCode)
		assert.Equal(t, "unsupported_grant_type", res.errResp.Error)
	}

	{
		data := url.Values{}
		data.Set("grant_type", "password")
		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusBadRequest, res.statusCode)
		assert.Equal(t, "unsupported_grant_type", res.errResp.Error)
	}

	{
		data := url.Values{}
		data.Set("grant_type", "refresh_token")
		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusBadRequest, res.statusCode)
		assert.Equal(t, "unsupported_grant_type", res.errResp.Error)
	}
}

func TestHandleOAuth2TokenRejections(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	newWorkloadUser := func() *tstuser.User {
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_WORKLOAD, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)
		return usrT
	}

	{
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", utilrand.GetRandomStringCanonical(8))
		data.Set("client_secret", utilrand.GetRandomString(200))

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
		assert.Equal(t, "invalid_client", res.errResp.Error)
	}

	{
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", utilrand.GetRandomStringCanonical(8))
		data.Set("client_secret", "")

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
		assert.Equal(t, "invalid_client", res.errResp.Error)
	}

	{
		usrT := newWorkloadUser()

		cred, err := adminSrv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usrT.Usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENTLESS,
			},
		})
		assert.Nil(t, err)

		tknResp, err := adminSrv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", cred.Status.Id)
		data.Set("client_secret", tknResp.GetAuthenticationToken().AuthenticationToken)

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
		assert.Equal(t, "invalid_client", res.errResp.Error)
	}

	{
		usrT := newWorkloadUser()
		_, clientID, clientSecret := newOAuth2Credential(t, ctx, adminSrv, usrT.Usr.Metadata.Name)

		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)
		data.Set("scope", strings.Repeat("a", 2049))

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
		assert.Equal(t, "invalid_scope", res.errResp.Error)
	}

	{
		usrT := newWorkloadUser()
		_, clientID, clientSecret := newOAuth2Credential(t, ctx, adminSrv, usrT.Usr.Metadata.Name)

		usr, err := srv.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid: usrT.Usr.Metadata.Uid,
		})
		assert.Nil(t, err)
		usr.Spec.Type = corev1.User_Spec_HUMAN
		_, err = srv.octeliumC.CoreC().UpdateUser(ctx, usr)
		assert.Nil(t, err)

		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusBadRequest, res.statusCode)
		assert.Equal(t, "invalid_request", res.errResp.Error)
	}

	{
		usrT := newWorkloadUser()
		_, clientID, clientSecret := newOAuth2Credential(t, ctx, adminSrv, usrT.Usr.Metadata.Name)

		usr, err := srv.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid: usrT.Usr.Metadata.Uid,
		})
		assert.Nil(t, err)
		usr.Spec.IsDisabled = true
		_, err = srv.octeliumC.CoreC().UpdateUser(ctx, usr)
		assert.Nil(t, err)

		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusBadRequest, res.statusCode)
		assert.Equal(t, "invalid_request", res.errResp.Error)
	}

	{
		usrT := newWorkloadUser()
		_, clientID, clientSecret := newOAuth2Credential(t, ctx, adminSrv, usrT.Usr.Metadata.Name)

		usr, err := srv.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid: usrT.Usr.Metadata.Uid,
		})
		assert.Nil(t, err)
		usr.Status.IsLocked = true
		_, err = srv.octeliumC.CoreC().UpdateUser(ctx, usr)
		assert.Nil(t, err)

		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusBadRequest, res.statusCode)
		assert.Equal(t, "invalid_request", res.errResp.Error)
	}
}

func TestHandleOAuth2TokenSessionState(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	getCredSession := func(cred *corev1.Credential) *corev1.Session {
		sessList, err := srv.octeliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{
			Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldEQValStr("status.credentialRef.uid", cred.Metadata.Uid),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(sessList.Items))
		return sessList.Items[0]
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_WORKLOAD, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		cred, clientID, clientSecret := newOAuth2Credential(t, ctx, adminSrv, usrT.Usr.Metadata.Name)

		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusOK, res.statusCode)
		assert.Equal(t, "Bearer", res.token.TokenType)
		assert.True(t, res.token.ExpiresIn > 0)
		assert.Equal(t, "", res.token.RefreshToken)

		sess := getCredSession(cred)

		sess.Status.IsLocked = true
		_, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		res = doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusBadRequest, res.statusCode)
		assert.Equal(t, "invalid_client", res.errResp.Error)
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_WORKLOAD, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		cred, clientID, clientSecret := newOAuth2Credential(t, ctx, adminSrv, usrT.Usr.Metadata.Name)

		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_id", clientID)
		data.Set("client_secret", clientSecret)

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusOK, res.statusCode)

		sess := getCredSession(cred)

		sess.Spec.State = corev1.Session_Spec_REJECTED
		_, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		res = doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusBadRequest, res.statusCode)
		assert.Equal(t, "invalid_client", res.errResp.Error)
	}
}

func TestHandleOAuth2MetadataFields(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	req := httptest.NewRequest("GET",
		"http://localhost/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	srv.handleOAuth2Metadata(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	bb, err := io.ReadAll(resp.Body)
	assert.Nil(t, err)

	ret := &oauth2Metadata{}
	assert.Nil(t, json.Unmarshal(bb, ret))

	assert.Equal(t, srv.rootURL, ret.Issuer)
	assert.Equal(t, fmt.Sprintf("%s/oauth2/token", srv.rootURL), ret.TokenEndpoint)
	assert.True(t, strings.HasPrefix(ret.TokenEndpoint, ret.Issuer))

	assert.True(t, slices.Contains(ret.GrantTypesSupported, "client_credentials"))
	assert.False(t, slices.Contains(ret.GrantTypesSupported, "password"))
	assert.False(t, slices.Contains(ret.GrantTypesSupported, "implicit"))

	assert.True(t, slices.Contains(ret.ResponseTypesSupported, "code"))
	assert.True(t, slices.Contains(ret.TokenEndpointAuthMethodsSupported, "client_secret_post"))
}

func TestHandleOAuth2AssertionRejections(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	{
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_assertion_type", assertionTypeJWTBearer)
		data.Set("client_assertion", "")

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
		assert.Equal(t, "invalid_client", res.errResp.Error)
	}

	{
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_assertion_type", assertionTypeJWTBearer)
		data.Set("client_assertion", utilrand.GetRandomString(200))

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
		assert.Equal(t, "invalid_client", res.errResp.Error)
	}

	{
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_assertion_type", assertionTypeJWTBearer)
		data.Set("client_assertion", "aaa.bbb.ccc")

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
		assert.Equal(t, "invalid_client", res.errResp.Error)
	}

	{
		data := url.Values{}
		data.Set("grant_type", "client_credentials")
		data.Set("client_assertion_type", "urn:some:other:type")
		data.Set("client_assertion", "aaa.bbb.ccc")

		res := doOAuth2TokenReq(t, srv, data)
		assert.Equal(t, http.StatusUnauthorized, res.statusCode)
		assert.Equal(t, "invalid_client", res.errResp.Error)
	}
}
