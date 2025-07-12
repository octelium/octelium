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

package oidc

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/oauth2-proxy/mockoidc"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
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

	oidcSrv, err := mockoidc.Run()
	assert.Nil(t, err)

	defer oidcSrv.Shutdown()

	time.Sleep(1 * time.Second)

	sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: oidcSrv.ClientSecret,
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
					ClientID:  oidcSrv.ClientID,
					IssuerURL: fmt.Sprintf("%s/oidc", oidcSrv.Addr()),
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

	provider, err := NewConnector(ctx, &utils.ProviderOpts{
		OcteliumC:     fakeC.OcteliumC,
		Provider:      idp,
		ClusterConfig: cc,
	})
	assert.Nil(t, err)

	{
		myUsr := &mockoidc.MockUser{
			Subject:       utilrand.GetRandomStringCanonical(16),
			Email:         fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
			EmailVerified: true,
		}
		oidcSrv.QueueUser(myUsr)

		state := utilrand.GetRandomStringCanonical(32)
		codeURL, reqID, err := provider.LoginURL(state)
		assert.Nil(t, err)

		var redirectURL string
		{
			req := httptest.NewRequest(http.MethodGet, codeURL, nil)
			rw := httptest.NewRecorder()
			oidcSrv.Authorize(rw, req)

			resp := rw.Result()
			assert.Equal(t, http.StatusFound, resp.StatusCode)

			redirURL, err := url.Parse(rw.Header().Get("Location"))
			assert.Nil(t, err)
			assert.Equal(t, state, redirURL.Query().Get("state"))

			redirectURL = redirURL.String()
		}

		{
			req := httptest.NewRequest(http.MethodGet, redirectURL, nil)

			usr, err := provider.HandleCallback(req, reqID)
			assert.Nil(t, err)

			assert.Equal(t, myUsr.Email, usr.GetIdentityProvider().Email)
			assert.Equal(t, myUsr.Email, usr.GetIdentityProvider().Identifier)
			assert.Equal(t, idp.Metadata.Uid, usr.GetIdentityProvider().IdentityProviderRef.Uid)
		}
	}

	{
		// With subject as the identifier
		idp.Spec.GetOidc().IdentifierClaim = "sub"
		myUsr := &mockoidc.MockUser{
			Subject:       utilrand.GetRandomStringCanonical(16),
			Email:         fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
			EmailVerified: true,
		}
		oidcSrv.QueueUser(myUsr)

		state := utilrand.GetRandomStringCanonical(32)
		codeURL, reqID, err := provider.LoginURL(state)
		assert.Nil(t, err)

		var redirectURL string
		{
			req := httptest.NewRequest(http.MethodGet, codeURL, nil)
			rw := httptest.NewRecorder()
			oidcSrv.Authorize(rw, req)

			resp := rw.Result()
			assert.Equal(t, http.StatusFound, resp.StatusCode)

			redirURL, err := url.Parse(rw.Header().Get("Location"))
			assert.Nil(t, err)
			assert.Equal(t, state, redirURL.Query().Get("state"))

			redirectURL = redirURL.String()
		}

		{
			req := httptest.NewRequest(http.MethodGet, redirectURL, nil)

			usr, err := provider.HandleCallback(req, reqID)
			assert.Nil(t, err)

			assert.Equal(t, myUsr.Email, usr.GetIdentityProvider().Email)
			assert.Equal(t, myUsr.Subject, usr.GetIdentityProvider().Identifier)
			assert.Equal(t, idp.Metadata.Uid, usr.GetIdentityProvider().IdentityProviderRef.Uid)
		}
		idp.Spec.GetOidc().IdentifierClaim = ""
	}

	{
		// Without EmailVerified
		myUsr := &mockoidc.MockUser{
			Subject: utilrand.GetRandomStringCanonical(16),
			Email:   fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
		}
		oidcSrv.QueueUser(myUsr)

		state := utilrand.GetRandomStringCanonical(32)
		codeURL, reqID, err := provider.LoginURL(state)
		assert.Nil(t, err)

		var redirectURL string
		{
			req := httptest.NewRequest(http.MethodGet, codeURL, nil)
			rw := httptest.NewRecorder()
			oidcSrv.Authorize(rw, req)

			resp := rw.Result()
			assert.Equal(t, http.StatusFound, resp.StatusCode)

			redirURL, err := url.Parse(rw.Header().Get("Location"))
			assert.Nil(t, err)
			assert.Equal(t, state, redirURL.Query().Get("state"))

			redirectURL = redirURL.String()
		}

		{
			req := httptest.NewRequest(http.MethodGet, redirectURL, nil)

			usr, err := provider.HandleCallback(req, reqID)
			assert.Nil(t, err)

			assert.Equal(t, myUsr.Email, usr.GetIdentityProvider().Email)
			assert.Equal(t, myUsr.Email, usr.GetIdentityProvider().Identifier)
			assert.Equal(t, idp.Metadata.Uid, usr.GetIdentityProvider().IdentityProviderRef.Uid)
		}
	}

	{
		// Now check for EmailVerified while the email is not verified
		idp.Spec.GetOidc().CheckEmailVerified = true
		myUsr := &mockoidc.MockUser{
			Subject: utilrand.GetRandomStringCanonical(16),
			Email:   fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
		}
		oidcSrv.QueueUser(myUsr)

		state := utilrand.GetRandomStringCanonical(32)
		codeURL, reqID, err := provider.LoginURL(state)
		assert.Nil(t, err)

		var redirectURL string
		{
			req := httptest.NewRequest(http.MethodGet, codeURL, nil)
			rw := httptest.NewRecorder()
			oidcSrv.Authorize(rw, req)

			resp := rw.Result()
			assert.Equal(t, http.StatusFound, resp.StatusCode)

			redirURL, err := url.Parse(rw.Header().Get("Location"))
			assert.Nil(t, err)
			assert.Equal(t, state, redirURL.Query().Get("state"))

			redirectURL = redirURL.String()
		}

		{
			req := httptest.NewRequest(http.MethodGet, redirectURL, nil)

			_, err := provider.HandleCallback(req, reqID)
			assert.NotNil(t, err)

		}
		idp.Spec.GetOidc().CheckEmailVerified = false
	}

}
