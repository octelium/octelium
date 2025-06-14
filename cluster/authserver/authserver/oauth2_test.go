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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
