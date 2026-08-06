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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/common/opkce"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestHandleIndex(t *testing.T) {

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

	/*
		adminSrv := admin.NewServer(&admin.Opts{
			OcteliumC:  fakeC.OcteliumC,
			IsEmbedded: true,
		})
	*/

	{
		reqHTTP := httptest.NewRequest("GET", "http://localhost/", nil)
		w := httptest.NewRecorder()
		srv.handleIndex(w, reqHTTP)
		resp := w.Result()
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, fmt.Sprintf("https://%s/login", srv.domain), resp.Header.Get("location"))

	}

	/*
		{
			usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
			assert.Nil(t, err)

			{
				req := httptest.NewRequest("GET", "http://localhost/", nil)
				w := httptest.NewRecorder()
				req.AddCookie(&http.Cookie{
					Name:  "octelium_rt",
					Value: string(usrT.GetAccessToken().RefreshToken),
					Path:  "/",
				})

				srv.handleIndex(w, req)
				resp := w.Result()
				assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
				assert.Equal(t, fmt.Sprintf("https://portal.%s", srv.domain), resp.Header.Get("location"))
			}


			usrT.Session.Status.Authentication.SetAt = pbutils.Timestamp(time.Now().Add(-24 * time.Hour))
			usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
			assert.Nil(t, err)

			{
				req := httptest.NewRequest("GET", "http://localhost/", nil)
				w := httptest.NewRecorder()
				req.AddCookie(&http.Cookie{
					Name:  "octelium_rt",
					Value: string(usrT.GetAccessToken().RefreshToken),
					Path:  "/",
				})

				srv.handleIndex(w, req)
				resp := w.Result()
				assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
				assert.Equal(t, fmt.Sprintf("https://%s/login", srv.domain), resp.Header.Get("location"))
			}
		}
	*/

	/*
		{
			usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
			assert.Nil(t, err)

			usrT.Session.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(-24 * time.Hour))
			usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
			assert.Nil(t, err)

			{
				req := httptest.NewRequest("GET", "http://localhost/", nil)
				w := httptest.NewRecorder()
				req.AddCookie(&http.Cookie{
					Name:  "octelium_rt",
					Value: string(usrT.GetAccessToken().RefreshToken),
					Path:  "/",
				})

				srv.handleIndex(w, req)
				resp := w.Result()
				assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
				assert.Equal(t, fmt.Sprintf("https://portal.%s", srv.domain), resp.Header.Get("location"))

			}
		}
	*/

}

func TestHandleLogin(t *testing.T) {

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

	{
		reqHTTP := httptest.NewRequest("GET", "http://localhost/login", nil)
		w := httptest.NewRecorder()
		srv.handleLogin(w, reqHTTP)
		resp := w.Result()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		usrT.Session.Status.IsBrowser = true
		usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
		assert.Nil(t, err)

		{
			req := httptest.NewRequest("GET", "http://localhost/login", nil)
			w := httptest.NewRecorder()
			req.AddCookie(&http.Cookie{
				Name:  "octelium_rt",
				Value: string(usrT.GetAccessToken().RefreshToken),
				Path:  "/",
			})

			srv.handleLogin(w, req)
			resp := w.Result()
			assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
			assert.Equal(t, srv.getPortalURL(), resp.Header.Get("location"))
		}

		usrT.Session.Status.Authentication.SetAt = pbutils.Timestamp(time.Now().Add(-24 * time.Hour))
		usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
		assert.Nil(t, err)

		{
			req := httptest.NewRequest("GET", "http://localhost/", nil)
			w := httptest.NewRecorder()
			req.AddCookie(&http.Cookie{
				Name:  "octelium_rt",
				Value: string(usrT.GetAccessToken().RefreshToken),
				Path:  "/",
			})

			srv.handleLogin(w, req)
			resp := w.Result()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		}
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		usrT.Session.Status.IsBrowser = true
		usrT.Session.Spec.ExpiresAt = pbutils.Timestamp(time.Now().Add(-24 * time.Hour))
		usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
		assert.Nil(t, err)

		{
			req := httptest.NewRequest("GET", "http://localhost/login", nil)
			w := httptest.NewRecorder()
			req.AddCookie(&http.Cookie{
				Name:  "octelium_rt",
				Value: string(usrT.GetAccessToken().RefreshToken),
				Path:  "/",
			})

			srv.handleLogin(w, req)
			resp := w.Result()
			assert.Equal(t, http.StatusOK, resp.StatusCode)

		}
	}

}

func TestHandleLoginClientRequest(t *testing.T) {

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

	doLogin := func(usrT *tstuser.User, loginReq *authv1.ClientLoginRequest) *http.Response {
		murl := fmt.Sprintf("http://localhost/login?octelium_req=%s",
			encodeLoginReq(t, loginReq))

		req := httptest.NewRequest("GET", murl, nil)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Value: string(usrT.GetAccessToken().RefreshToken),
			Path:  "/",
		})

		w := httptest.NewRecorder()
		srv.handleLogin(w, req)
		return w.Result()
	}

	countCredentials := func() int {
		credList, err := srv.octeliumC.CoreC().ListCredential(ctx, &rmetav1.ListOptions{})
		assert.Nil(t, err)
		return len(credList.Items)
	}

	t.Run("no-silent-token", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		codeVerifier, err := opkce.NewVerifier()
		assert.Nil(t, err)

		totalCreds := countCredentials()

		resp := doLogin(usrT, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcdefgh",
			CodeChallenge:  opkce.GetChallenge(codeVerifier),
		})

		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)

		location := resp.Header.Get("Location")
		assert.Equal(t, fmt.Sprintf("%s/callback/success", srv.rootURL), location)
		assert.NotContains(t, location, "octelium_response")
		assert.NotContains(t, location, "localhost:12345")

		assert.Equal(t, totalCreds, countCredentials())

		state, err := srv.loadPendingClientAuth(ctx, usrT.Session)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "http://localhost:12345/callback/success/abcdefgh", state.CallbackURL)
		assert.Equal(t, opkce.GetChallenge(codeVerifier), state.CodeChallenge)
	})

	t.Run("no-silent-token-legacy-client", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		totalCreds := countCredentials()

		resp := doLogin(usrT, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcd",
		})

		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.NotContains(t, resp.Header.Get("Location"), "octelium_response")
		assert.Equal(t, totalCreds, countCredentials())

		state, err := srv.loadPendingClientAuth(ctx, usrT.Session)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "http://localhost:12345/callback/success/abcd", state.CallbackURL)
		assert.Empty(t, state.CodeChallenge)
	})

	t.Run("invalid-request", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		resp := doLogin(usrT, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   80,
			CallbackSuffix: "abcd",
		})

		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, srv.getPortalURL(), resp.Header.Get("Location"))

		_, err = srv.loadPendingClientAuth(ctx, usrT.Session)
		assert.NotNil(t, err)
	})
}
