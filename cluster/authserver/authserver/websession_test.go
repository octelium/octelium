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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestGetOrCreateWebDevSess(t *testing.T) {

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

	generateRefreshToken := func(sess *corev1.Session) string {
		tkn, err := srv.jwkCtl.CreateRefreshToken(sess)
		assert.Nil(t, err)
		return tkn
	}

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
	})
	assert.Nil(t, err)

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Add("user-agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1")
		assert.Nil(t, err)
		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		_, err = srv.createOrUpdateSessWeb(req, usrT.Usr, nil, cc, idp)
		assert.Nil(t, err)
	}

	{
		usrT, err := tstuser.NewUser(srv.octeliumC, adminSrv, nil, nil)
		assert.Nil(t, err)
		req := httptest.NewRequest("POST", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_auth",
			Value: utilrand.GetRandomString(430),
		})
		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		assert.Nil(t, err)
		_, err = srv.createOrUpdateSessWeb(req, usrT.Usr, nil, cc, idp)
		assert.Nil(t, err)

		req.Header.Add("user-agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1")
		_, err = srv.createOrUpdateSessWeb(req, usrT.Usr, nil, cc, idp)
		assert.Nil(t, err)
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		req := httptest.NewRequest("POST", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Value: generateRefreshToken(usrT.Session),
		})
		assert.Nil(t, err)
		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		resp, err := srv.createOrUpdateSessWeb(req, usrT.Usr, nil, cc, idp)
		assert.Nil(t, err)
		assert.NotEqual(t, usrT.Session.Status.Authentication.TokenID, resp.Status.Authentication.TokenID)
		// assert.Equal(t, usrT.Session.Status.Authentication.TokenID, resp.sess.Status.LastAuthentications[0].TokenID)
		assert.True(t, resp.Status.Authentication.SetAt.AsTime().
			After(usrT.Session.Status.Authentication.SetAt.AsTime()))
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		req := httptest.NewRequest("POST", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  "octelium_rt",
			Value: generateRefreshToken(usrT.Session),
		})
		assert.Nil(t, err)
		_, err = fakeC.OcteliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{Uid: usrT.Session.Metadata.Uid})
		assert.Nil(t, err)

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)
		_, err = srv.createOrUpdateSessWeb(req, usrT.Usr, nil, cc, idp)
		assert.Nil(t, err)
	}
}
