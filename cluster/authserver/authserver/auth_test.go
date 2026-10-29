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
	"strings"
	"testing"
	"testing/iotest"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/octovigilc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/octovigil/octovigil"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/clientlogin"
	"github.com/octelium/octelium/pkg/common/opkce"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
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
		assert.Equal(t, fmt.Sprintf("https://portal.%s", srv.domain), resp.Header.Get("Location"))
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

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		idp.Spec.PostAuthenticationRules = []*corev1.IdentityProvider_Spec_PostAuthenticationRule{
			{
				Condition: &corev1.Condition{
					Type: &corev1.Condition_Match{
						Match: `int(ctx.user.metadata.name) > 0`,
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

func TestGetLoginReqPKCE(t *testing.T) {

	codeVerifier, err := opkce.NewVerifier()
	assert.Nil(t, err)
	codeChallenge := opkce.GetChallenge(codeVerifier)

	{
		ret, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcdefgh",
			CodeChallenge:  codeChallenge,
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, authv1.ClientLoginRequest_V2, ret.ApiVersion)
		assert.Equal(t, codeChallenge, ret.CodeChallenge)
	}

	{
		ret, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcdefgh",
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, authv1.ClientLoginRequest_V1, ret.ApiVersion)
		assert.Equal(t, 0, len(ret.CodeChallenge))
	}

	{
		ret, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V2,
			CallbackPort:   12345,
			CallbackSuffix: "abcdefgh",
			CodeChallenge:  codeChallenge,
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, authv1.ClientLoginRequest_V2, ret.ApiVersion)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V2,
			CallbackPort:   12345,
			CallbackSuffix: "abcdefgh",
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcdefgh",
			CodeChallenge:  codeChallenge[:opkce.ChallengeLen-1],
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcdefgh",
			CodeChallenge:  append(codeChallenge, 0x0),
		}))
		assert.NotNil(t, err)
	}

	{
		arg := encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   65535,
			CallbackSuffix: "abcdefgh",
			CodeChallenge:  codeChallenge,
		})
		assert.Less(t, len(arg), 128)
	}
}

func TestGetLoginReqApp(t *testing.T) {

	codeVerifier, err := opkce.NewVerifier()
	assert.Nil(t, err)
	codeChallenge := opkce.GetChallenge(codeVerifier)

	{
		ret, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:    authv1.ClientLoginRequest_V1,
			CodeChallenge: codeChallenge,
			CallbackType:  authv1.ClientLoginRequest_APP,
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, authv1.ClientLoginRequest_V2, ret.ApiVersion)
		assert.Equal(t, authv1.ClientLoginRequest_APP, ret.CallbackType)
		assert.Equal(t, codeChallenge, ret.CodeChallenge)
		assert.Equal(t, clientlogin.AppCallbackURL, getLoginReqCallbackURL(ret))
	}

	{
		ret, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:    authv1.ClientLoginRequest_V2,
			CodeChallenge: codeChallenge,
			CallbackType:  authv1.ClientLoginRequest_APP,
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, authv1.ClientLoginRequest_APP, ret.CallbackType)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:   authv1.ClientLoginRequest_V1,
			CallbackType: authv1.ClientLoginRequest_APP,
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:    authv1.ClientLoginRequest_V1,
			CodeChallenge: codeChallenge[:opkce.ChallengeLen-1],
			CallbackType:  authv1.ClientLoginRequest_APP,
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:    authv1.ClientLoginRequest_V1,
			CallbackPort:  12345,
			CodeChallenge: codeChallenge,
			CallbackType:  authv1.ClientLoginRequest_APP,
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackSuffix: "abcdefgh",
			CodeChallenge:  codeChallenge,
			CallbackType:   authv1.ClientLoginRequest_APP,
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:    authv1.ClientLoginRequest_V1,
			CodeChallenge: codeChallenge,
			CallbackType:  authv1.ClientLoginRequest_CallbackType(100),
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := getLoginReq(encodeLoginReq(t, &authv1.ClientLoginRequest{
			ApiVersion:    authv1.ClientLoginRequest_V1,
			CodeChallenge: codeChallenge,
		}))
		assert.NotNil(t, err)
	}
}

func TestGetLoginReqCallbackURL(t *testing.T) {
	assert.Equal(t, "http://localhost:12345/callback/success/abcd",
		getLoginReqCallbackURL(&authv1.ClientLoginRequest{
			CallbackPort:   12345,
			CallbackSuffix: "abcd",
		}))

	assert.Equal(t, "com.octelium.client:/callback/success",
		getLoginReqCallbackURL(&authv1.ClientLoginRequest{
			CallbackType: authv1.ClientLoginRequest_APP,
		}))
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

	{
		codeVerifier, err := opkce.NewVerifier()
		assert.Nil(t, err)

		callbackURL, isApp, err := srv.generateCallbackURL(fmt.Sprintf("octelium_req=%s",
			encodeLoginReq(t, &authv1.ClientLoginRequest{
				ApiVersion:    authv1.ClientLoginRequest_V1,
				CodeChallenge: opkce.GetChallenge(codeVerifier),
				CallbackType:  authv1.ClientLoginRequest_APP,
			})))
		assert.Nil(t, err)
		assert.True(t, isApp)
		assert.Equal(t, clientlogin.AppCallbackURL, callbackURL)
	}

	{
		_, _, err := srv.generateCallbackURL(fmt.Sprintf("octelium_req=%s",
			encodeLoginReq(t, &authv1.ClientLoginRequest{
				ApiVersion:   authv1.ClientLoginRequest_V1,
				CallbackType: authv1.ClientLoginRequest_APP,
			})))
		assert.NotNil(t, err)
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

	assert.Equal(t, -1, byName["octelium_login_state"].MaxAge)
	assert.True(t, byName["octelium_login_state"].HttpOnly)
	assert.True(t, byName["octelium_login_state"].Secure)
	assert.Equal(t, srv.domain, byName["octelium_login_state"].Domain)
	assert.Equal(t, "/", byName["octelium_login_state"].Path)

	{
		var hdr string
		for _, itm := range w.Result().Header["Set-Cookie"] {
			if strings.HasPrefix(itm, "octelium_login_state=") {
				hdr = itm
			}
		}

		assert.True(t, hdr != "")
		assert.True(t, strings.Contains(hdr, "Max-Age=0"), "%s", hdr)
	}
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

func TestHasPendingAuthenticatorAction(t *testing.T) {

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
		assert.False(t, srv.hasPendingAuthenticatorAction(newSession()))
	}

	{
		sess := newSession()
		sess.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATION_REQUIRED
		assert.True(t, srv.hasPendingAuthenticatorAction(sess))
	}

	{
		sess := newSession()
		sess.Status.AuthenticatorAction = corev1.Session_Status_REGISTRATION_REQUIRED
		assert.True(t, srv.hasPendingAuthenticatorAction(sess))
	}

	{
		sess := newSession()
		sess.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATION_RECOMMENDED
		assert.False(t, srv.hasPendingAuthenticatorAction(sess))
	}

	{
		sess := newSession()
		sess.Status.AuthenticatorAction = corev1.Session_Status_REGISTRATION_RECOMMENDED
		assert.False(t, srv.hasPendingAuthenticatorAction(sess))
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
		ret, err := srv.doAuthenticatorEnforcementRule(ctx, nil, nil, usrT.Usr, usrT.Session, authnList)
		assert.Nil(t, err)
		assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_EFFECT_UNKNOWN, ret)
	}

	{
		ret, err := srv.doAuthenticatorEnforcementRule(ctx,
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
		assert.Nil(t, err)
		assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE, ret)
	}

	{
		ret, err := srv.doAuthenticatorEnforcementRule(ctx,
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
		assert.Nil(t, err)
		assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_RECOMMEND, ret)
	}

	{
		ret, err := srv.doAuthenticatorEnforcementRule(ctx,
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
		assert.Nil(t, err)
		assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_EFFECT_UNKNOWN, ret)
	}

	{
		ret, err := srv.doAuthenticatorEnforcementRule(ctx,
			[]*corev1.ClusterConfig_Spec_Authenticator_EnforcementRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `int(ctx.user.metadata.name) > 0`,
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
		assert.NotNil(t, err)
		assert.Equal(t, corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_EFFECT_UNKNOWN, ret)
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

func TestHandleClientApproval(t *testing.T) {
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

	newReq := func(usrT *tstuser.User) *http.Request {
		req := httptest.NewRequest("GET", "http://localhost/callback/success/approval", nil)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Value: string(usrT.GetAccessToken().RefreshToken),
			Path:  "/",
		})
		return req
	}

	t.Run("unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest("GET", "http://localhost/callback/success/approval", nil)
		w := httptest.NewRecorder()
		srv.handleClientApproval(w, req)
		resp := w.Result()

		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, fmt.Sprintf("%s/login", srv.rootURL), resp.Header.Get("Location"))
	})

	t.Run("no-pending-request", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		w := httptest.NewRecorder()
		srv.handleClientApproval(w, newReq(usrT))
		resp := w.Result()

		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, srv.getPortalURL(), resp.Header.Get("Location"))
	})

	t.Run("renders-the-page", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		codeVerifier, err := opkce.NewVerifier()
		assert.Nil(t, err)

		assert.Nil(t, srv.savePendingClientAuth(ctx, usrT.Session, &pendingClientAuth{
			CallbackURL:   "http://localhost:12345/callback/success/abcdefgh",
			CodeChallenge: opkce.GetChallenge(codeVerifier),
		}))

		w := httptest.NewRecorder()
		srv.handleClientApproval(w, newReq(usrT))
		resp := w.Result()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		w = httptest.NewRecorder()
		srv.handleClientApproval(w, newReq(usrT))
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
	})
}

func TestHandleClientApprovalDecision(t *testing.T) {
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

	callbackURL := "http://localhost:12345/callback/success/abcdefgh"

	newReq := func(usrT *tstuser.User, isApproved bool) *http.Request {
		body, err := json.Marshal(&postApprovalReq{IsApproved: isApproved})
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "http://localhost/callback/success/approval",
			bytes.NewReader(body))
		req.Header.Set("X-Octelium-Origin", srv.rootURL)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Value: string(usrT.GetAccessToken().RefreshToken),
			Path:  "/",
		})
		return req
	}

	getResp := func(w *httptest.ResponseRecorder) *postApprovalResp {
		ret := &postApprovalResp{}
		assert.Nil(t, json.NewDecoder(w.Result().Body).Decode(ret))
		return ret
	}

	t.Run("invalid-origin", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		req := newReq(usrT, true)
		req.Header.Set("X-Octelium-Origin", "https://evil.example.com")

		w := httptest.NewRecorder()
		srv.handleClientApprovalDecision(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("unauthenticated", func(t *testing.T) {
		body, err := json.Marshal(&postApprovalReq{IsApproved: true})
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "http://localhost/callback/success/approval",
			bytes.NewReader(body))
		req.Header.Set("X-Octelium-Origin", srv.rootURL)

		w := httptest.NewRecorder()
		srv.handleClientApprovalDecision(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
	})

	t.Run("no-pending-request", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		w := httptest.NewRecorder()
		srv.handleClientApprovalDecision(w, newReq(usrT, true))

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("approved", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		codeVerifier, err := opkce.NewVerifier()
		assert.Nil(t, err)
		codeChallenge := opkce.GetChallenge(codeVerifier)

		assert.Nil(t, srv.savePendingClientAuth(ctx, usrT.Session, &pendingClientAuth{
			CallbackURL:   callbackURL,
			CodeChallenge: codeChallenge,
		}))

		w := httptest.NewRecorder()
		srv.handleClientApprovalDecision(w, newReq(usrT, true))
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		u, err := url.Parse(getResp(w).RedirectURL)
		assert.Nil(t, err)
		assert.Equal(t, "12345", u.Port())
		assert.Equal(t, "/callback/success/abcdefgh", u.Path)

		loginResp := decodeLoginResp(t, u)
		assert.NotEmpty(t, loginResp.AuthenticationToken)
		assert.Equal(t, codeChallenge, loginResp.CodeChallenge)

		cred, err := srv.getCredentialFromToken(ctx, loginResp.AuthenticationToken)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, codeChallenge, cred.Status.GetPkce().GetCodeChallenge())

		w = httptest.NewRecorder()
		srv.handleClientApprovalDecision(w, newReq(usrT, true))
		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("rejected", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		codeVerifier, err := opkce.NewVerifier()
		assert.Nil(t, err)

		assert.Nil(t, srv.savePendingClientAuth(ctx, usrT.Session, &pendingClientAuth{
			CallbackURL:   callbackURL,
			CodeChallenge: opkce.GetChallenge(codeVerifier),
		}))

		w := httptest.NewRecorder()
		srv.handleClientApprovalDecision(w, newReq(usrT, false))
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Equal(t, srv.getPortalURL(), getResp(w).RedirectURL)

		_, err = srv.loadPendingClientAuth(ctx, usrT.Session)
		assert.NotNil(t, err)
	})

	t.Run("approved-legacy-client", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		assert.Nil(t, srv.savePendingClientAuth(ctx, usrT.Session, &pendingClientAuth{
			CallbackURL: callbackURL,
		}))

		w := httptest.NewRecorder()
		srv.handleClientApprovalDecision(w, newReq(usrT, true))
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		u, err := url.Parse(getResp(w).RedirectURL)
		assert.Nil(t, err)

		loginResp := decodeLoginResp(t, u)
		assert.NotEmpty(t, loginResp.AuthenticationToken)
		assert.Empty(t, loginResp.CodeChallenge)

		cred, err := srv.getCredentialFromToken(ctx, loginResp.AuthenticationToken)
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, cred.Status.GetPkce())
	})
}

func doClientLoginFlow(t *testing.T, ctx context.Context, srv *server, adminSrv *admin.Server,
	loginReq *authv1.ClientLoginRequest, codeVerifier []byte) {

	usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
	assert.Nil(t, err)

	cookie := &http.Cookie{
		Name:  "octelium_rt",
		Value: string(usrT.GetAccessToken().RefreshToken),
		Path:  "/",
	}

	req := httptest.NewRequest("GET",
		fmt.Sprintf("http://localhost/login?octelium_req=%s", encodeLoginReq(t, loginReq)), nil)
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Result().StatusCode)
	assert.Equal(t, fmt.Sprintf("%s/callback/success", srv.rootURL), w.Result().Header.Get("Location"))

	req = httptest.NewRequest("GET", "http://localhost/callback/success", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	srv.handleAuthSuccess(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Result().StatusCode)
	assert.Equal(t, fmt.Sprintf("%s/callback/success/approval", srv.rootURL),
		w.Result().Header.Get("Location"))

	req = httptest.NewRequest("GET", "http://localhost/callback/success/approval", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	srv.handleClientApproval(w, req)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	body, err := json.Marshal(&postApprovalReq{IsApproved: true})
	assert.Nil(t, err)
	req = httptest.NewRequest("POST", "http://localhost/callback/success/approval",
		bytes.NewReader(body))
	req.Header.Set("X-Octelium-Origin", srv.rootURL)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	srv.handleClientApprovalDecision(w, req)
	assert.Equal(t, http.StatusOK, w.Result().StatusCode)

	out := &postApprovalResp{}
	assert.Nil(t, json.NewDecoder(w.Result().Body).Decode(out))

	u, err := url.Parse(out.RedirectURL)
	assert.Nil(t, err)
	switch loginReq.CallbackType {
	case authv1.ClientLoginRequest_APP:
		assert.Equal(t, clientlogin.AppCallbackScheme, u.Scheme)
		assert.Equal(t, "", u.Host)
		assert.Equal(t, clientlogin.AppCallbackPath, u.Path)
	default:
		assert.Equal(t, fmt.Sprintf("%d", loginReq.CallbackPort), u.Port())
		assert.Equal(t, fmt.Sprintf("/callback/success/%s", loginReq.CallbackSuffix), u.Path)
	}

	loginResp := decodeLoginResp(t, u)
	assert.NotEmpty(t, loginResp.AuthenticationToken)
	assert.Equal(t, loginReq.CodeChallenge, loginResp.CodeChallenge)

	sessTkn, err := srv.doAuthenticateWithAuthenticationToken(ctx,
		&authv1.AuthenticateWithAuthenticationTokenRequest{
			AuthenticationToken: loginResp.AuthenticationToken,
			CodeVerifier:        codeVerifier,
		})
	assert.Nil(t, err, "%+v", err)
	assert.NotEmpty(t, sessTkn.AccessToken)
}

func TestClientLoginFlow(t *testing.T) {
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

	t.Run("legacy-client", func(t *testing.T) {
		doClientLoginFlow(t, ctx, srv, adminSrv, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcde",
		}, nil)
	})

	t.Run("client", func(t *testing.T) {
		codeVerifier, err := opkce.NewVerifier()
		assert.Nil(t, err)

		doClientLoginFlow(t, ctx, srv, adminSrv, &authv1.ClientLoginRequest{
			ApiVersion:     authv1.ClientLoginRequest_V1,
			CallbackPort:   12345,
			CallbackSuffix: "abcdefgh",
			CodeChallenge:  opkce.GetChallenge(codeVerifier),
		}, codeVerifier)
	})

	t.Run("app", func(t *testing.T) {
		codeVerifier, err := opkce.NewVerifier()
		assert.Nil(t, err)

		doClientLoginFlow(t, ctx, srv, adminSrv, &authv1.ClientLoginRequest{
			ApiVersion:    authv1.ClientLoginRequest_V1,
			CodeChallenge: opkce.GetChallenge(codeVerifier),
			CallbackType:  authv1.ClientLoginRequest_APP,
		}, codeVerifier)
	})
}

func TestClientLoginFlowAuthenticatorAction(t *testing.T) {
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

	loginReq := &authv1.ClientLoginRequest{
		ApiVersion:     authv1.ClientLoginRequest_V1,
		CallbackPort:   12345,
		CallbackSuffix: "abcdefgh",
	}

	countCredentials := func() int {
		credList, err := srv.octeliumC.CoreC().ListCredential(ctx, &rmetav1.ListOptions{})
		assert.Nil(t, err)
		return len(credList.Items)
	}

	newCookie := func(usrT *tstuser.User) *http.Cookie {
		return &http.Cookie{
			Name:  "octelium_rt",
			Value: string(usrT.GetAccessToken().RefreshToken),
			Path:  "/",
		}
	}

	setAction := func(usrT *tstuser.User, action corev1.Session_Status_AuthenticatorAction) {
		var err error
		usrT.Session.Status.AuthenticatorAction = action
		usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
		assert.Nil(t, err)
	}

	doLogin := func(cookie *http.Cookie) *http.Response {
		req := httptest.NewRequest("GET",
			fmt.Sprintf("http://localhost/login?octelium_req=%s", encodeLoginReq(t, loginReq)), nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		srv.handleLogin(w, req)
		return w.Result()
	}

	doApprovalDecision := func(cookie *http.Cookie) *http.Response {
		body, err := json.Marshal(&postApprovalReq{IsApproved: true})
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "http://localhost/callback/success/approval",
			bytes.NewReader(body))
		req.Header.Set("X-Octelium-Origin", srv.rootURL)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		srv.handleClientApprovalDecision(w, req)
		return w.Result()
	}

	doCheckBlocked := func(t *testing.T,
		action corev1.Session_Status_AuthenticatorAction, redirectPath string) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		setAction(usrT, action)

		cookie := newCookie(usrT)
		totalCreds := countCredentials()

		resp := doLogin(cookie)
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Location"), redirectPath)

		_, err = srv.loadPendingClientAuth(ctx, usrT.Session)
		assert.NotNil(t, err)

		req := httptest.NewRequest("GET", "http://localhost/callback/success", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		srv.handleAuthSuccess(w, req)
		assert.Equal(t, http.StatusSeeOther, w.Result().StatusCode)
		assert.Contains(t, w.Result().Header.Get("Location"), redirectPath)

		req = httptest.NewRequest("GET", "http://localhost/callback/success/approval", nil)
		req.AddCookie(cookie)
		w = httptest.NewRecorder()
		srv.handleClientApproval(w, req)
		assert.Equal(t, http.StatusSeeOther, w.Result().StatusCode)
		assert.Contains(t, w.Result().Header.Get("Location"), redirectPath)

		assert.Equal(t, http.StatusUnauthorized, doApprovalDecision(cookie).StatusCode)

		assert.Equal(t, totalCreds, countCredentials())
	}

	t.Run("authentication-required", func(t *testing.T) {
		doCheckBlocked(t, corev1.Session_Status_AUTHENTICATION_REQUIRED, "/authenticators/authenticate")
	})

	t.Run("registration-required", func(t *testing.T) {
		doCheckBlocked(t, corev1.Session_Status_REGISTRATION_REQUIRED, "/authenticators/register")
	})

	t.Run("pending-request-is-not-consumable", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		callbackURL := "http://localhost:12345/callback/success/abcdefgh"

		assert.Nil(t, srv.savePendingClientAuth(ctx, usrT.Session, &pendingClientAuth{
			CallbackURL: callbackURL,
		}))

		setAction(usrT, corev1.Session_Status_AUTHENTICATION_REQUIRED)

		totalCreds := countCredentials()

		assert.Equal(t, http.StatusUnauthorized, doApprovalDecision(newCookie(usrT)).StatusCode)
		assert.Equal(t, totalCreds, countCredentials())

		_, err = srv.generateClientCallbackURL(ctx, usrT.Session, callbackURL, nil)
		assert.NotNil(t, err)

		state, err := srv.loadPendingClientAuth(ctx, usrT.Session)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, callbackURL, state.CallbackURL)
	})

	t.Run("action-cleared", func(t *testing.T) {
		usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		setAction(usrT, corev1.Session_Status_AUTHENTICATION_REQUIRED)

		cookie := newCookie(usrT)

		resp := doLogin(cookie)
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("Location"), "/authenticators/authenticate")

		setAction(usrT, corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET)

		resp = doLogin(cookie)
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, fmt.Sprintf("%s/callback/success", srv.rootURL), resp.Header.Get("Location"))

		req := httptest.NewRequest("GET", "http://localhost/callback/success/approval", nil)
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		srv.handleClientApproval(w, req)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)

		resp = doApprovalDecision(cookie)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		out := &postApprovalResp{}
		assert.Nil(t, json.NewDecoder(resp.Body).Decode(out))

		u, err := url.Parse(out.RedirectURL)
		assert.Nil(t, err)
		assert.Equal(t, "12345", u.Port())

		loginResp := decodeLoginResp(t, u)
		assert.NotEmpty(t, loginResp.AuthenticationToken)

		sessTkn, err := srv.doAuthenticateWithAuthenticationToken(ctx,
			&authv1.AuthenticateWithAuthenticationTokenRequest{
				AuthenticationToken: loginResp.AuthenticationToken,
			})
		assert.Nil(t, err, "%+v", err)
		assert.NotEmpty(t, sessTkn.AccessToken)
	})
}

func decodeLoginResp(t *testing.T, u *url.URL) *authv1.ClientLoginResponse {
	respBytes, err := base64.RawURLEncoding.DecodeString(u.Query().Get("octelium_response"))
	assert.Nil(t, err)

	ret := &authv1.ClientLoginResponse{}
	assert.Nil(t, pbutils.Unmarshal(respBytes, ret))
	return ret
}

func TestHandleAuthMalformedRequests(t *testing.T) {
	srv := &server{rootURL: "https://example.com"}
	ua := "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"

	valid := &postAuthReq{
		UID:       "00000000-0000-4000-8000-000000000001",
		UserAgent: ua,
	}
	validBytes, err := json.Marshal(valid)
	assert.Nil(t, err)

	tests := []struct {
		name   string
		body   io.Reader
		origin string
		ua     string
	}{
		{name: "Empty", body: strings.NewReader(""), origin: srv.rootURL, ua: ua},
		{name: "Null", body: strings.NewReader("null"), origin: srv.rootURL, ua: ua},
		{name: "Array", body: strings.NewReader("[]"), origin: srv.rootURL, ua: ua},
		{name: "TruncatedJSON", body: strings.NewReader(`{"uid":`), origin: srv.rootURL, ua: ua},
		{name: "TrailingJSON", body: strings.NewReader(string(validBytes) + "{}"), origin: srv.rootURL, ua: ua},
		{name: "OversizedBody", body: strings.NewReader(string(validBytes) + strings.Repeat(" ", 513)), origin: srv.rootURL, ua: ua},
		{name: "ReadError", body: iotest.ErrReader(errors.New("read error")), origin: srv.rootURL, ua: ua},
		{name: "MissingOrigin", body: bytes.NewReader(validBytes), ua: ua},
		{name: "ForeignOrigin", body: bytes.NewReader(validBytes), origin: "https://evil.example.com", ua: ua},
		{name: "NullOrigin", body: bytes.NewReader(validBytes), origin: "null", ua: ua},
		{name: "UserAgentMismatch", body: bytes.NewReader(validBytes), origin: srv.rootURL, ua: ua + " other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://example.com/begin", tt.body)
			req.Header.Set("X-Octelium-Origin", tt.origin)
			req.Header.Set("User-Agent", tt.ua)
			w := httptest.NewRecorder()
			srv.handleAuth(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Empty(t, w.Header().Get("Location"))
			assert.Empty(t, w.Result().Cookies())
		})
	}
}

func TestHandleClientApprovalMalformedBody(t *testing.T) {
	ctx := context.Background()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
	assert.Nil(t, err)

	before, err := srv.octeliumC.CoreC().ListCredential(ctx, &rmetav1.ListOptions{})
	assert.Nil(t, err)

	tests := []struct {
		name string
		body io.Reader
	}{
		{name: "Empty", body: strings.NewReader("")},
		{name: "Array", body: strings.NewReader("[]")},
		{name: "InvalidType", body: strings.NewReader(`{"isApproved":"true"}`)},
		{name: "TruncatedJSON", body: strings.NewReader(`{"isApproved":`)},
		{name: "TrailingJSON", body: strings.NewReader(`{"isApproved":true}{}`)},
		{name: "OversizedBody", body: strings.NewReader(`{"isApproved":true}` + strings.Repeat(" ", 513))},
		{name: "ReadError", body: iotest.ErrReader(errors.New("read error"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := &pendingClientAuth{
				CallbackURL:   "http://localhost:12345/callback/success/abcd",
				CodeChallenge: utilrand.GetRandomBytesMust(32),
			}
			assert.Nil(t, srv.savePendingClientAuth(ctx, usrT.Session, state))

			req := httptest.NewRequest(http.MethodPost,
				"https://example.com/callback/success/approval", tt.body)
			req.Header.Set("X-Octelium-Origin", srv.rootURL)
			req.AddCookie(&http.Cookie{
				Name:  "octelium_rt",
				Value: usrT.GetAccessToken().RefreshToken,
			})
			w := httptest.NewRecorder()
			srv.handleClientApprovalDecision(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Empty(t, w.Header().Get("Location"))
			assert.Empty(t, w.Body.String())
			got, err := srv.loadPendingClientAuth(ctx, usrT.Session)
			assert.Nil(t, err)
			assert.Equal(t, state, got)
		})
	}

	after, err := srv.octeliumC.CoreC().ListCredential(ctx, &rmetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Equal(t, len(before.Items), len(after.Items))
}

type callbackProvider interface {
	utils.Provider
}

type callbackTestProvider struct {
	callbackProvider
	idp    *corev1.IdentityProvider
	info   *corev1.Session_Status_Authentication_Info
	err    error
	called bool
}

func (p *callbackTestProvider) Provider() *corev1.IdentityProvider {
	return p.idp
}

func (p *callbackTestProvider) HandleCallback(r *http.Request,
	login *utils.GetLoginResponse) (*corev1.Session_Status_Authentication_Info, error) {
	p.called = true
	return p.info, p.err
}

func newCallbackTestEnv(t *testing.T) (*server, *admin.Server) {
	t.Helper()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	return &server{
		rootURL:    srv.rootURL,
		domain:     srv.domain,
		authDomain: srv.authDomain,
		octeliumC:  srv.octeliumC,
		genCache:   srv.genCache,
		jwkCtl:     srv.jwkCtl,
		ccCtl:      srv.ccCtl,
		celEngine:  srv.celEngine,
		geoipCtl:   srv.geoipCtl,
		authEvents: srv.authEvents,
	}, adminSrv
}

func TestHandleAuthCallback(t *testing.T) {
	ctx := context.Background()
	srv, adminSrv := newCallbackTestEnv(t)

	tests := []struct {
		name   string
		mutate func(*callbackTestProvider, *corev1.User, *loginState)
		valid  bool
		called bool
	}{
		{name: "Valid", valid: true, called: true},
		{name: "DisabledProvider", mutate: func(p *callbackTestProvider, usr *corev1.User, state *loginState) {
			p.idp.Spec.IsDisabled = true
		}},
		{name: "LockedProvider", mutate: func(p *callbackTestProvider, usr *corev1.User, state *loginState) {
			p.idp.Status.IsLocked = true
		}},
		{name: "RemovedProvider", mutate: func(p *callbackTestProvider, usr *corev1.User, state *loginState) {
			state.UID = "removed"
		}},
		{name: "ProviderError", called: true, mutate: func(p *callbackTestProvider, usr *corev1.User, state *loginState) {
			p.err = errors.New("invalid authorization code")
		}},
		{name: "EmptyIdentifier", called: true, mutate: func(p *callbackTestProvider, usr *corev1.User, state *loginState) {
			p.info.GetIdentityProvider().Identifier = ""
		}},
		{name: "UnknownUser", called: true, mutate: func(p *callbackTestProvider, usr *corev1.User, state *loginState) {
			p.info.GetIdentityProvider().Email = "unknown@example.com"
		}},
		{name: "DisabledUser", called: true, mutate: func(p *callbackTestProvider, usr *corev1.User, state *loginState) {
			usr.Spec.IsDisabled = true
		}},
		{name: "LockedUser", called: true, mutate: func(p *callbackTestProvider, usr *corev1.User, state *loginState) {
			usr.Status.IsLocked = true
		}},
		{name: "WorkloadUser", called: true, mutate: func(p *callbackTestProvider, usr *corev1.User, state *loginState) {
			usr.Spec.Type = corev1.User_Spec_WORKLOAD
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usrReq := tstuser.GenUserHuman(nil)
			usrReq.Spec.Email = fmt.Sprintf("%s@example.com", usrReq.Metadata.Name)
			usr, err := adminSrv.CreateUser(ctx, usrReq)
			assert.Nil(t, err)
			p := &callbackTestProvider{
				idp: &corev1.IdentityProvider{
					Metadata: &metav1.Metadata{Name: "test-idp", Uid: utilrand.GetRandomStringCanonical(36)},
					Spec:     &corev1.IdentityProvider_Spec{},
					Status:   &corev1.IdentityProvider_Status{Type: corev1.IdentityProvider_Status_OIDC},
				},
			}
			p.info = &corev1.Session_Status_Authentication_Info{
				Type: corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER,
				Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
					IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
						IdentityProviderRef: umetav1.GetObjectReference(p.idp),
						Identifier:          usr.Metadata.Name,
						Email:               usr.Spec.Email,
						Type:                corev1.IdentityProvider_Status_OIDC,
					},
				},
			}
			state := &loginState{
				ID:          newStateID(),
				UID:         p.idp.Metadata.Uid,
				CallbackURL: "https://portal.example.com/home",
				Login:       &utils.GetLoginResponse{},
			}
			if tt.mutate != nil {
				tt.mutate(p, usr, state)
				_, err = srv.octeliumC.CoreC().UpdateUser(ctx, usr)
				assert.Nil(t, err)
			}
			srv.webProvidersC.Lock()
			srv.webProvidersC.connectors = []utils.Provider{p}
			srv.webProvidersC.Unlock()
			assert.Nil(t, srv.saveLoginState(ctx, state))

			newReq := func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "https://example.com/callback?state="+state.ID, nil)
				req.AddCookie(&http.Cookie{Name: "octelium_login_state", Value: state.ID})
				return req
			}
			w := httptest.NewRecorder()
			srv.handleAuthCallback(w, newReq())
			assert.Equal(t, http.StatusSeeOther, w.Code)
			assert.Equal(t, tt.called, p.called)

			sessions, err := srv.octeliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{
				Filters: []*rmetav1.ListOptions_Filter{urscsrv.FilterStatusUserUID(usr.Metadata.Uid)},
			})
			assert.Nil(t, err)
			if tt.valid {
				assert.Equal(t, 1, len(sessions.Items))
				u, err := url.Parse(w.Header().Get("Location"))
				assert.Nil(t, err)
				assert.Equal(t, "/callback/success", u.Path)
				assert.Equal(t, state.CallbackURL, u.Query().Get("redirect"))
				cookies := w.Result().Cookies()
				assert.Equal(t, 3, len(cookies))
				for _, cookie := range cookies {
					assert.True(t, cookie.Secure)
					if cookie.Name == "octelium_rt" {
						assert.True(t, cookie.HttpOnly)
						sess, err := srv.getSessionFromRefreshToken(ctx, cookie.Value)
						assert.Nil(t, err)
						assert.Equal(t, usr.Metadata.Uid, sess.Status.UserRef.Uid)
						assert.True(t, sess.Status.IsBrowser)
					}
				}
			} else {
				assert.Empty(t, sessions.Items)
				assert.Empty(t, w.Result().Cookies())
				assert.Equal(t, srv.rootURL, w.Header().Get("Location"))
			}

			p.called = false
			w = httptest.NewRecorder()
			srv.handleAuthCallback(w, newReq())
			assert.Equal(t, http.StatusSeeOther, w.Code)
			assert.Equal(t, srv.rootURL, w.Header().Get("Location"))
			assert.False(t, p.called)
			assert.Empty(t, w.Result().Cookies())
		})
	}
}

func TestSetAuthCallbackResponse(t *testing.T) {
	ctx := context.Background()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
	assert.Nil(t, err)

	tests := []struct {
		name   string
		action corev1.Session_Status_AuthenticatorAction
		state  *loginState
		path   string
	}{
		{name: "NoState", path: "/callback/success"},
		{name: "EmptyState", state: &loginState{}, path: "/callback/success"},
		{name: "WebRedirect", state: &loginState{CallbackURL: "https://portal.example.com/path"}, path: "/callback/success"},
		{name: "ClientApproval", state: &loginState{IsApp: true, CallbackURL: "http://localhost:12345/callback/success/abcd", CodeChallenge: utilrand.GetRandomBytesMust(32)}, path: "/callback/success"},
		{name: "AuthenticationRequired", action: corev1.Session_Status_AUTHENTICATION_REQUIRED, state: &loginState{}, path: "/authenticators/authenticate"},
		{name: "AuthenticationRecommended", action: corev1.Session_Status_AUTHENTICATION_RECOMMENDED, state: &loginState{}, path: "/authenticators/authenticate"},
		{name: "RegistrationRequired", action: corev1.Session_Status_REGISTRATION_REQUIRED, state: &loginState{}, path: "/authenticators/register"},
		{name: "RegistrationRecommended", action: corev1.Session_Status_REGISTRATION_RECOMMENDED, state: &loginState{}, path: "/authenticators/register"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := pbutils.Clone(usrT.Session).(*corev1.Session)
			sess.Status.AuthenticatorAction = tt.action
			req := httptest.NewRequest(http.MethodGet, "https://example.com/callback", nil)
			w := httptest.NewRecorder()
			assert.Nil(t, srv.setAuthCallbackResponse(req, w, tt.state, sess))
			assert.Equal(t, http.StatusSeeOther, w.Code)
			u, err := url.Parse(w.Header().Get("Location"))
			assert.Nil(t, err)
			assert.Equal(t, "https", u.Scheme)
			assert.Equal(t, srv.domain, u.Host)
			assert.Equal(t, tt.path, u.Path)
			assert.NotContains(t, u.RawQuery, "octelium_response")
			assert.Equal(t, 3, len(w.Result().Cookies()))

			if tt.state != nil && tt.state.IsApp {
				pending, err := srv.loadPendingClientAuth(ctx, sess)
				assert.Nil(t, err)
				assert.Equal(t, tt.state.CallbackURL, pending.CallbackURL)
				assert.Equal(t, tt.state.CodeChallenge, pending.CodeChallenge)
				assert.Empty(t, u.RawQuery)
			}
			if tt.action != corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET {
				state, err := srv.loadAuthenticatorCallbackState(ctx, sess)
				assert.Nil(t, err)
				assert.Equal(t, tt.state.CallbackURL, state.CallbackURL)
			}
		})
	}

	sess := pbutils.Clone(usrT.Session).(*corev1.Session)
	sess.Status.AuthenticatorAction = corev1.Session_Status_AuthenticatorAction(100)
	w := httptest.NewRecorder()
	assert.NotNil(t, srv.setAuthCallbackResponse(httptest.NewRequest(http.MethodGet, "/callback", nil), w, nil, sess))
	assert.Empty(t, w.Result().Cookies())
	assert.Empty(t, w.Header().Get("Location"))
}
