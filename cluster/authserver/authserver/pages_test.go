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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
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
