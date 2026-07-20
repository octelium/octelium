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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/octovigilc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/octovigil/octovigil"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestHandleAuth(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

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

	githubIDP, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
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

	oidcIDP, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name:        "oidc-1",
			DisplayName: "OIDC 1",
		},

		Spec: &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					IssuerURL: "https://accounts.google.com",
					ClientID:  "xxx",
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		},
		Status: &corev1.IdentityProvider_Status{
			Type: corev1.IdentityProvider_Status_OIDC,
		},
	})
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	t.Run("null body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://localhost/begin", nil)
		req.Header.Set("X-Octelium-Origin", srv.rootURL)
		w := httptest.NewRecorder()
		srv.handleAuth(w, req)
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)
	})

	t.Run("non-existent-provider", func(t *testing.T) {
		reqBody := &postAuthReq{
			UID: vutils.UUIDv4(),
		}
		reqBodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "http://localhost/begin", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("X-Octelium-Origin", srv.rootURL)
		w := httptest.NewRecorder()
		srv.handleAuth(w, req)
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)
	})

	defaultUA := "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"

	t.Run("github", func(t *testing.T) {
		reqBody := &postAuthReq{
			UID:       githubIDP.Metadata.Uid,
			UserAgent: defaultUA,
		}

		reqBodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "http://localhost/begin", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("X-Octelium-Origin", srv.rootURL)
		req.Header.Set("user-agent", defaultUA)

		w := httptest.NewRecorder()
		srv.handleAuth(w, req)
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		bb, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)
		resp.Body.Close()
		var postAuthResp postAuthResp
		err = json.Unmarshal(bb, &postAuthResp)
		assert.Nil(t, err)
	})

	t.Run("github-no-origin", func(t *testing.T) {
		reqBody := &postAuthReq{
			UID:       githubIDP.Metadata.Uid,
			UserAgent: defaultUA,
		}

		reqBodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "http://localhost/begin", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("user-agent", defaultUA)

		w := httptest.NewRecorder()
		srv.handleAuth(w, req)
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusBadRequest)

	})

	t.Run("oidc", func(t *testing.T) {
		reqBody := &postAuthReq{
			UID:       oidcIDP.Metadata.Uid,
			UserAgent: defaultUA,
		}

		reqBodyBytes, _ := json.Marshal(reqBody)
		req := httptest.NewRequest("POST", "http://localhost/begin", bytes.NewBuffer(reqBodyBytes))
		req.Header.Set("user-agent", defaultUA)
		req.Header.Set("X-Octelium-Origin", srv.rootURL)
		w := httptest.NewRecorder()
		srv.handleAuth(w, req)
		resp := w.Result()
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		bb, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)
		resp.Body.Close()
		var postAuthResp postAuthResp
		err = json.Unmarshal(bb, &postAuthResp)
		assert.Nil(t, err)

		url, err := url.Parse(postAuthResp.LoginURL)
		assert.Nil(t, err)

		res, err := srv.octeliumC.CacheC().GetCache(context.Background(), &rcachev1.GetCacheRequest{
			Key: []byte(getAuthKey(url.Query().Get("state"))),
		})
		assert.Nil(t, err)

		var userState loginState
		err = json.Unmarshal([]byte(res.Data), &userState)
		assert.Nil(t, err)
		assert.Equal(t, reqBody.UID, userState.UID)
	})
}

func TestAuthenticateUser(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	err = vutils.WaitUntilPortIsAvailable(octovigilc.GetPort())
	assert.Nil(t, err)
	octovigilSrv, err := octovigil.New(ctx, fakeC.OcteliumC)
	assert.Nil(t, err)
	err = octovigilSrv.Run(ctx)
	assert.Nil(t, err, "%+v", err)
	defer octovigilSrv.Close()

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

	gh, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
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
	})
	assert.Nil(t, err)

	oidcp, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name:        "oidc-1",
			DisplayName: "OIDC 1",
		},

		Spec: &corev1.IdentityProvider_Spec{

			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					IssuerURL: "https://accounts.google.com",
					ClientID:  "xxx",
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	samlp, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name:        "saml-1",
			DisplayName: "SAML 1",
		},

		Spec: &corev1.IdentityProvider_Spec{
			DisableEmailAsIdentity: true,
			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{
					MetadataType: &corev1.IdentityProvider_Spec_SAML_MetadataURL{
						MetadataURL: "https://mocksaml.com/api/saml/metadata",
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	samlpAllowEmail, err := fakeC.OcteliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name:        "saml-2",
			DisplayName: "SAML 2",
		},

		Spec: &corev1.IdentityProvider_Spec{
			// AllowUserEmail: true,

			Type: &corev1.IdentityProvider_Spec_Saml{
				Saml: &corev1.IdentityProvider_Spec_SAML{
					MetadataType: &corev1.IdentityProvider_Spec_SAML_MetadataURL{
						MetadataURL: "https://mocksaml.com/api/saml/metadata",
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	/*
		clusterCfg.Spec.Authentication.WebIdentityProviders = append(clusterCfg.Spec.Authentication.WebIdentityProviders,
			gh.Metadata.Name, oidcp.Metadata.Name, samlp.Metadata.Name)

		_, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, clusterCfg)
		assert.Nil(t, err)
	*/

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	{
		_, err = srv.authenticateUser(ctx, &corev1.Session_Status_Authentication_Info{
			Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
				IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
					IdentityProviderRef: &metav1.ObjectReference{
						Name: "github-1",
					},
					Type: corev1.IdentityProvider_Status_GITHUB,
				},
			},
		}, gh)
		assert.NotNil(t, err)
	}

	{
		usr := &corev1.User{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("usr-%s", utilrand.GetRandomStringLowercase(8)),
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_HUMAN,
				Authentication: &corev1.User_Spec_Authentication{
					Identities: []*corev1.User_Spec_Authentication_Identity{
						{
							IdentityProvider: "github-1",
							Identifier:       "ghuser1",
						},
					},
				},
			},
		}

		usr, err = adminSrv.CreateUser(ctx, usr)
		assert.Nil(t, err)
		usrK8s, err := srv.authenticateUser(ctx, &corev1.Session_Status_Authentication_Info{
			Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
				IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
					Identifier: "ghuser1",
					IdentityProviderRef: &metav1.ObjectReference{
						Name: "github-1",
					},
					Type: corev1.IdentityProvider_Status_GITHUB,
				},
			},
		}, gh)
		assert.Nil(t, err)
		assert.Equal(t, usr.Metadata.Name, usrK8s.Metadata.Name)
		assert.Equal(t, usr.Metadata.Uid, string(usrK8s.Metadata.Uid))
	}

	{
		usr := &corev1.User{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("usr-%s", utilrand.GetRandomStringLowercase(8)),
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_HUMAN,
				Authentication: &corev1.User_Spec_Authentication{
					Identities: []*corev1.User_Spec_Authentication_Identity{
						{
							IdentityProvider: "oidc-1",
							Identifier:       "linus@example.com",
						},
					},
				},
			},
		}

		usr, err = adminSrv.CreateUser(ctx, usr)
		assert.Nil(t, err)
		_, err = srv.authenticateUser(ctx, &corev1.Session_Status_Authentication_Info{
			Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
				IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
					Identifier: "linus@example.com",
					IdentityProviderRef: &metav1.ObjectReference{
						Name: "oidc-1",
					},
					Type: corev1.IdentityProvider_Status_OIDC,
				},
			},
		}, oidcp)
		assert.Nil(t, err)

		_, err = srv.authenticateUser(ctx, &corev1.Session_Status_Authentication_Info{
			Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
				IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
					Identifier: "LinuS@example.com",
					IdentityProviderRef: &metav1.ObjectReference{
						Name: "oidc-1",
					},
					Type: corev1.IdentityProvider_Status_OIDC,
				},
			},
		}, oidcp)
		assert.NotNil(t, err)
	}

	{
		usr := &corev1.User{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("usr-%s", utilrand.GetRandomStringLowercase(8)),
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_HUMAN,
				Authentication: &corev1.User_Spec_Authentication{
					Identities: []*corev1.User_Spec_Authentication_Identity{
						{
							IdentityProvider: "saml-1",
							Identifier:       "linus@example.com",
						},
					},
				},
			},
		}

		usr, err = adminSrv.CreateUser(ctx, usr)
		assert.Nil(t, err)

		usrK8s, err := srv.authenticateUser(ctx, &corev1.Session_Status_Authentication_Info{
			Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
				IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
					Identifier: "linus@example.com",
					IdentityProviderRef: &metav1.ObjectReference{
						Name: "saml-1",
					},
					Type: corev1.IdentityProvider_Status_SAML,
				},
			},
		}, samlp)
		assert.Nil(t, err)
		assert.Equal(t, usr.Metadata.Name, usrK8s.Metadata.Name)
		assert.Equal(t, usr.Metadata.Uid, string(usrK8s.Metadata.Uid))

		_, err = srv.authenticateUser(ctx, &corev1.Session_Status_Authentication_Info{
			Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
				IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
					Identifier: "LinuS@example.com",
					IdentityProviderRef: &metav1.ObjectReference{
						Name: "saml-1",
					},
					Type: corev1.IdentityProvider_Status_SAML,
				},
			},
		}, samlp)
		assert.NotNil(t, err)
	}

	{
		usr := &corev1.User{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("usr-%s", utilrand.GetRandomStringLowercase(8)),
			},
			Spec: &corev1.User_Spec{
				Type:  corev1.User_Spec_HUMAN,
				Email: "geo2@example.com",
			},
		}

		usr, err = adminSrv.CreateUser(ctx, usr)
		assert.Nil(t, err)

		usrK8s, err := srv.authenticateUser(ctx, &corev1.Session_Status_Authentication_Info{
			Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
				IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
					Identifier:          "id",
					Email:               "geo2@example.com",
					IdentityProviderRef: umetav1.GetObjectReference(samlpAllowEmail),
					Type:                corev1.IdentityProvider_Status_SAML,
				},
			},
		}, samlpAllowEmail)
		assert.Nil(t, err)
		assert.Equal(t, usr.Metadata.Name, usrK8s.Metadata.Name)
		assert.Equal(t, usr.Metadata.Uid, string(usrK8s.Metadata.Uid))

	}

	{
		usr := &corev1.User{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("usr-%s", utilrand.GetRandomStringLowercase(8)),
			},
			Spec: &corev1.User_Spec{
				Type:  corev1.User_Spec_HUMAN,
				Email: "geo3@example.com",
			},
		}

		usr, err = adminSrv.CreateUser(ctx, usr)
		assert.Nil(t, err)

		_, err := srv.authenticateUser(ctx, &corev1.Session_Status_Authentication_Info{
			Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
				IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
					Identifier:          "id",
					Email:               "geo3@example.com",
					IdentityProviderRef: umetav1.GetObjectReference(samlp),
					Type:                corev1.IdentityProvider_Status_SAML,
				},
			},
		}, samlp)
		assert.NotNil(t, err)
	}
}

func TestHandleSuccessCallback(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	t.Run("default", func(t *testing.T) {
		req := httptest.NewRequest("POST", "http://localhost/begin", nil)
		req.Header.Set("origin", srv.rootURL)
		w := httptest.NewRecorder()
		srv.handleAuthSuccess(w, req)
		resp := w.Result()

		assert.Equal(t, resp.StatusCode, http.StatusSeeOther)
		assert.Equal(t, fmt.Sprintf("%s/login", srv.rootURL), resp.Header.Get("Location"))
	})

	t.Run("logged-in", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "http://localhost/begin", nil)
		req.Header.Set("origin", srv.rootURL)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Value: string(usrT.GetAccessToken().RefreshToken),
			Path:  "/",
		})
		q := req.URL.Query()
		murl := fmt.Sprintf("https://%s.%s", utilrand.GetRandomStringCanonical(8), srv.domain)
		q.Set("redirect", murl)
		req.URL.RawQuery = q.Encode()

		w := httptest.NewRecorder()
		srv.handleAuthSuccess(w, req)
		resp := w.Result()

		assert.Equal(t, resp.StatusCode, http.StatusSeeOther)
		assert.Equal(t, murl, resp.Header.Get("Location"))
	})

	t.Run("logged-in-no-redirect", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "http://localhost/begin", nil)
		req.Header.Set("origin", srv.rootURL)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Value: string(usrT.GetAccessToken().RefreshToken),
			Path:  "/",
		})

		w := httptest.NewRecorder()
		srv.handleAuthSuccess(w, req)
		resp := w.Result()

		assert.Equal(t, resp.StatusCode, http.StatusSeeOther)
		assert.Equal(t, fmt.Sprintf("https://portal.%s", srv.domain), resp.Header.Get("Location"))
	})

	t.Run("logged-in-localhost", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "http://localhost/begin", nil)
		req.Header.Set("origin", srv.rootURL)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Value: string(usrT.GetAccessToken().RefreshToken),
			Path:  "/",
		})
		q := req.URL.Query()
		murl := fmt.Sprintf("http://localhost:%d?octelium_req=%s", utilrand.GetRandomRangeMath(1000, 20000), utilrand.GetRandomStringCanonical(8))
		q.Set("redirect", murl)
		req.URL.RawQuery = q.Encode()

		w := httptest.NewRecorder()
		srv.handleAuthSuccess(w, req)
		resp := w.Result()

		assert.Equal(t, resp.StatusCode, http.StatusSeeOther)
		assert.Equal(t, murl, resp.Header.Get("Location"))
	})

	t.Run("other-domain", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "http://localhost/begin", nil)
		req.Header.Set("origin", srv.rootURL)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Value: string(usrT.GetAccessToken().RefreshToken),
			Path:  "/",
		})
		q := req.URL.Query()
		murl := fmt.Sprintf("https://%s.com", utilrand.GetRandomStringCanonical(8))
		q.Set("redirect", murl)
		req.URL.RawQuery = q.Encode()

		w := httptest.NewRecorder()
		srv.handleAuthSuccess(w, req)
		resp := w.Result()

		assert.Equal(t, resp.StatusCode, http.StatusSeeOther)
		assert.Equal(t, fmt.Sprintf("https://portal.%s", srv.domain), resp.Header.Get("Location"))
	})

}

func TestDoPostAuthenticationRules(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
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

	idp, err := adminSrv.CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					IssuerURL: "https://example.com",
					ClientID:  utilrand.GetRandomString(32),
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	{
		err := srv.doPostAuthenticationRules(ctx, idp, nil, nil)
		assert.Nil(t, err)
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		err = srv.doPostAuthenticationRules(ctx, idp, usrT.Usr, &corev1.Session_Status_Authentication_Info{})
		assert.Nil(t, err)
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		idp.Spec.PostAuthenticationRules = []*corev1.IdentityProvider_Spec_PostAuthenticationRule{
			{
				Condition: &corev1.Condition{
					Type: &corev1.Condition_Match{
						Match: `ctx.authenticationInfo.aal == "AAL1"`,
					},
				},
				Effect: corev1.IdentityProvider_Spec_PostAuthenticationRule_DENY,
			},
		}

		err = srv.doPostAuthenticationRules(ctx, idp, usrT.Usr, &corev1.Session_Status_Authentication_Info{
			Aal: corev1.Session_Status_Authentication_Info_AAL1,
		})
		assert.NotNil(t, err)

		idp.Spec.PostAuthenticationRules = nil
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		idp.Spec.PostAuthenticationRules = []*corev1.IdentityProvider_Spec_PostAuthenticationRule{
			{
				Condition: &corev1.Condition{
					Type: &corev1.Condition_Match{
						Match: fmt.Sprintf(`ctx.user.metadata.name == "%s"`, usrT.Usr.Metadata.Name),
					},
				},
				Effect: corev1.IdentityProvider_Spec_PostAuthenticationRule_ALLOW,
			},
			{
				Condition: &corev1.Condition{
					Type: &corev1.Condition_Match{
						Match: `ctx.authenticationInfo.aal == "AAL1"`,
					},
				},
				Effect: corev1.IdentityProvider_Spec_PostAuthenticationRule_DENY,
			},
		}

		err = srv.doPostAuthenticationRules(ctx, idp, usrT.Usr, &corev1.Session_Status_Authentication_Info{
			Aal: corev1.Session_Status_Authentication_Info_AAL1,
		})
		assert.Nil(t, err)

		idp.Spec.PostAuthenticationRules = nil
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		idp.Spec.PostAuthenticationRules = []*corev1.IdentityProvider_Spec_PostAuthenticationRule{
			{
				Condition: &corev1.Condition{
					Type: &corev1.Condition_Match{
						Match: fmt.Sprintf(`ctx.identityProvider.metadata.uid == "%s"`, idp.Metadata.Uid),
					},
				},
				Effect: corev1.IdentityProvider_Spec_PostAuthenticationRule_DENY,
			},
		}

		err = srv.doPostAuthenticationRules(ctx, idp, usrT.Usr, &corev1.Session_Status_Authentication_Info{
			Aal: corev1.Session_Status_Authentication_Info_AAL1,
		})
		assert.NotNil(t, err)

		idp.Spec.PostAuthenticationRules = nil
	}
}

func encodeLoginReq(t *testing.T, req *authv1.ClientLoginRequest) string {
	b, err := pbutils.Marshal(req)
	assert.Nil(t, err)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestGetLoginReq(t *testing.T) {

	{
		_, err := getLoginReq("")
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(utilrand.GetRandomString(600))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(base64.RawURLEncoding.EncodeToString(utilrand.GetRandomBytesMust(64)))
		assert.NotNil(t, err)
	}

	{
		ret, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcd",
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "abcd", ret.CallbackSuffix)
	}

	{
		ret, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   65535,
			CallbackSuffix: "abcdefgh",
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "abcdefgh", ret.CallbackSuffix)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			CallbackPort:   12345,
			CallbackSuffix: "abcd",
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   9999,
			CallbackSuffix: "abcd",
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   0,
			CallbackSuffix: "abcd",
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abc",
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcdefghi",
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "",
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "日本語テスト",
		}))
		assert.NotNil(t, err)
	}
}

func TestValidateLoginQuery(t *testing.T) {

	assert.Nil(t, validateLoginQuery("redirect=https%3A%2F%2Fexample.com"))
	assert.Nil(t, validateLoginQuery("a=1&b=2"))

	assert.NotNil(t, validateLoginQuery(utilrand.GetRandomStringCanonical(1200)))

	assert.Nil(t, validateLoginQuery(fmt.Sprintf("octelium_req=%s",
		encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcd",
		}))))

	assert.NotNil(t, validateLoginQuery(fmt.Sprintf("octelium_req=%s",
		encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   80,
			CallbackSuffix: "abcd",
		}))))

	assert.NotNil(t, validateLoginQuery("octelium_req=xxxx"))
}

func TestValidatePostAuthReq(t *testing.T) {

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

	defaultUA := "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"

	assert.NotNil(t, srv.validatePostAuthReq(nil))

	assert.NotNil(t, srv.validatePostAuthReq(&postAuthReq{}))

	assert.NotNil(t, srv.validatePostAuthReq(&postAuthReq{
		UID:       vutils.UUIDv4(),
		UserAgent: "",
	}))

	assert.NotNil(t, srv.validatePostAuthReq(&postAuthReq{
		UID:       utilrand.GetRandomStringCanonical(8),
		UserAgent: defaultUA,
	}))

	assert.Nil(t, srv.validatePostAuthReq(&postAuthReq{
		UID:       vutils.UUIDv4(),
		UserAgent: defaultUA,
	}))

	assert.NotNil(t, srv.validatePostAuthReq(&postAuthReq{
		UID:       vutils.UUIDv4(),
		UserAgent: defaultUA,
		Query:     utilrand.GetRandomStringCanonical(1200),
	}))

	assert.Nil(t, srv.validatePostAuthReq(&postAuthReq{
		UID:       vutils.UUIDv4(),
		UserAgent: defaultUA,
		Query:     "redirect=https%3A%2F%2Fexample.com",
	}))
}

func TestCheckXOcteliumOrigin(t *testing.T) {

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
		req := httptest.NewRequest("POST", "http://localhost/begin", nil)
		assert.NotNil(t, srv.checkXOcteliumOrigin(req))
	}

	{
		req := httptest.NewRequest("POST", "http://localhost/begin", nil)
		req.Header.Set("X-Octelium-Origin", "https://evil.example.com")
		assert.NotNil(t, srv.checkXOcteliumOrigin(req))
	}

	{
		req := httptest.NewRequest("POST", "http://localhost/begin", nil)
		req.Header.Set("X-Octelium-Origin", fmt.Sprintf("%s.evil.com", srv.rootURL))
		assert.NotNil(t, srv.checkXOcteliumOrigin(req))
	}

	{
		req := httptest.NewRequest("POST", "http://localhost/begin", nil)
		req.Header.Set("X-Octelium-Origin", srv.rootURL)
		assert.Nil(t, srv.checkXOcteliumOrigin(req))
	}
}

func TestGenerateCallbackURL(t *testing.T) {

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
		callbackURL, isApp, err := srv.generateCallbackURL("")
		assert.Nil(t, err)
		assert.Equal(t, "", callbackURL)
		assert.False(t, isApp)
	}

	{
		callbackURL, isApp, err := srv.generateCallbackURL("a=1&b=2")
		assert.Nil(t, err)
		assert.Equal(t, "", callbackURL)
		assert.False(t, isApp)
	}

	{
		redirect := fmt.Sprintf("https://%s.%s", utilrand.GetRandomStringCanonical(8), srv.domain)
		callbackURL, isApp, err := srv.generateCallbackURL(fmt.Sprintf("redirect=%s", redirect))
		assert.Nil(t, err)
		assert.Equal(t, redirect, callbackURL)
		assert.False(t, isApp)
	}

	{
		redirect := fmt.Sprintf("https://%s.com", utilrand.GetRandomStringCanonical(8))
		callbackURL, isApp, err := srv.generateCallbackURL(fmt.Sprintf("redirect=%s", redirect))
		assert.Nil(t, err)
		assert.Equal(t, "", callbackURL)
		assert.False(t, isApp)
	}

	{
		callbackURL, isApp, err := srv.generateCallbackURL(fmt.Sprintf("octelium_req=%s",
			encodeLoginReq(t, &authv1.ClientLoginRequest{
				ApiVersion:     authv1.ClientLoginRequest_V1,
				CallbackPort:   12345,
				CallbackSuffix: "abcd",
			})))
		assert.Nil(t, err)
		assert.True(t, isApp)
		assert.Equal(t, "http://localhost:12345/callback/success/abcd", callbackURL)
	}

	{
		_, _, err := srv.generateCallbackURL("octelium_req=invalid")
		assert.NotNil(t, err)
	}

	{
		redirect := fmt.Sprintf("https://%s.%s", utilrand.GetRandomStringCanonical(8), srv.domain)
		callbackURL, isApp, err := srv.generateCallbackURL(fmt.Sprintf("redirect=%s&octelium_req=%s",
			redirect,
			encodeLoginReq(t, &authv1.ClientLoginRequest{
				ApiVersion:     authv1.ClientLoginRequest_V1,
				CallbackPort:   12345,
				CallbackSuffix: "abcd",
			})))
		assert.Nil(t, err)
		assert.True(t, isApp)
		assert.Equal(t, "http://localhost:12345/callback/success/abcd", callbackURL)
	}
}

func TestGetLogoutCookies(t *testing.T) {

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

	cookies := srv.getLogoutCookies()
	assert.Equal(t, 3, len(cookies))

	found := map[string]bool{}

	for _, cookie := range cookies {
		found[cookie.Name] = true
		assert.Equal(t, "", cookie.Value)
		assert.Equal(t, -1, cookie.MaxAge)
		assert.True(t, cookie.HttpOnly)
		assert.True(t, cookie.Secure)
		assert.Equal(t, srv.domain, cookie.Domain)
		assert.Equal(t, "/", cookie.Path)
	}

	assert.True(t, found["octelium_auth"])
	assert.True(t, found["octelium_rt"])
	assert.True(t, found["octelium_login_state"])

	w := httptest.NewRecorder()
	srv.setLogoutCookies(w)
	assert.Equal(t, 3, len(w.Result().Cookies()))
}

func TestSetLoginCookies(t *testing.T) {

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

	usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
	assert.Nil(t, err)

	accessToken, err := srv.generateAccessToken(usrT.Session)
	assert.Nil(t, err)
	refreshToken, err := srv.generateRefreshToken(usrT.Session)
	assert.Nil(t, err)

	w := httptest.NewRecorder()
	srv.setLoginCookies(w, accessToken, refreshToken, usrT.Session)

	cookies := w.Result().Cookies()
	assert.Equal(t, 3, len(cookies))

	byName := map[string]*http.Cookie{}
	for _, cookie := range cookies {
		byName[cookie.Name] = cookie
	}

	assert.Equal(t, accessToken, byName["octelium_auth"].Value)
	assert.Equal(t, refreshToken, byName["octelium_rt"].Value)
	assert.Equal(t, "", byName["octelium_login_state"].Value)

	assert.True(t, byName["octelium_auth"].HttpOnly)
	assert.True(t, byName["octelium_auth"].Secure)
	assert.Equal(t, srv.domain, byName["octelium_auth"].Domain)

	assert.True(t, byName["octelium_rt"].HttpOnly)
	assert.True(t, byName["octelium_rt"].Secure)

	assert.True(t, byName["octelium_rt"].Expires.After(byName["octelium_auth"].Expires))
}

func TestCheckSessionValid(t *testing.T) {

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

	newSession := func() *corev1.Session {
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)
		return usrT.Session
	}

	{
		assert.Nil(t, srv.checkSessionValid(newSession()))
	}

	{
		sess := newSession()
		sess.Status.IsLocked = true
		assert.NotNil(t, srv.checkSessionValid(sess))
	}

	{
		sess := newSession()
		sess.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATION_REQUIRED
		assert.NotNil(t, srv.checkSessionValid(sess))
	}

	{
		sess := newSession()
		sess.Status.AuthenticatorAction = corev1.Session_Status_REGISTRATION_REQUIRED
		assert.Nil(t, srv.checkSessionValid(sess))
	}

	{
		sess := newSession()
		sess.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATION_RECOMMENDED
		assert.Nil(t, srv.checkSessionValid(sess))
	}
}

func TestDoAuthenticatorEnforcementRule(t *testing.T) {

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

	usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
	assert.Nil(t, err)

	authnList := &corev1.AuthenticatorList{}

	{
		ret := srv.doAuthenticatorEnforcementRule(ctx, nil, nil, usrT.Usr, usrT.Session, authnList)
		assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_EFFECT_UNKNOWN, ret)
	}

	{
		ret := srv.doAuthenticatorEnforcementRule(ctx,
			[]*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE,
				},
			}, nil, usrT.Usr, usrT.Session, authnList)
		assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE, ret)
	}

	{
		ret := srv.doAuthenticatorEnforcementRule(ctx,
			[]*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: fmt.Sprintf(`ctx.user.metadata.name == "%s"`, usrT.Usr.Metadata.Name),
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_RECOMMEND,
				},
			}, nil, usrT.Usr, usrT.Session, authnList)
		assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_RECOMMEND, ret)
	}

	{
		ret := srv.doAuthenticatorEnforcementRule(ctx,
			[]*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `ctx.user.metadata.name == "does-not-exist"`,
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE,
				},
			}, nil, usrT.Usr, usrT.Session, authnList)
		assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_EFFECT_UNKNOWN, ret)
	}

	{
		ret := srv.doAuthenticatorEnforcementRule(ctx,
			[]*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `invalid CEL expr`,
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE,
				},
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_IGNORE,
				},
			}, nil, usrT.Usr, usrT.Session, authnList)
		assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_IGNORE, ret)
	}
}

func TestHandleAuthenticatorEndpointsUnauthenticated(t *testing.T) {

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

	handlers := map[string]func(http.ResponseWriter, *http.Request){
		"authenticate": srv.handleAuthenticatorAuthenticate,
		"register":     srv.handleAuthenticatorRegister,
		"list":         srv.handleAuthenticatorList,
		"denied":       srv.handleDenied,
	}

	for name, handler := range handlers {
		req := httptest.NewRequest("GET", "http://localhost/authenticators", nil)
		w := httptest.NewRecorder()
		handler(w, req)
		resp := w.Result()

		assert.Equal(t, http.StatusSeeOther, resp.StatusCode, "%s", name)
		assert.Equal(t, fmt.Sprintf("%s/login", srv.rootURL), resp.Header.Get("Location"), "%s", name)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
	assert.Nil(t, err)

	for name, handler := range handlers {
		req := httptest.NewRequest("GET", "http://localhost/authenticators", nil)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Value: string(usrT.GetAccessToken().RefreshToken),
			Path:  "/",
		})

		w := httptest.NewRecorder()
		handler(w, req)
		resp := w.Result()

		assert.NotEqual(t, fmt.Sprintf("%s/login", srv.rootURL),
			resp.Header.Get("Location"), "%s", name)
	}
}
