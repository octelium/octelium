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

package github

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func newGithubTestSecret(t *testing.T, ctx context.Context, tst *tests.T) *corev1.Secret {
	sec, err := tst.C.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
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
	return sec
}

func newGithubIDP(clientID, secretName string) *corev1.IdentityProvider {
	return &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
			Uid:  utilrand.GetRandomStringCanonical(16),
		},
		Spec: &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: clientID,
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: secretName,
						},
					},
				},
			},
		},
		Status: &corev1.IdentityProvider_Status{
			Type: corev1.IdentityProvider_Status_GITHUB,
		},
	}
}

func TestNewConnector(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	sec := newGithubTestSecret(t, ctx, tst)

	{
		_, err := NewConnector(ctx, &utils.ProviderOpts{
			OcteliumC:     fakeC.OcteliumC,
			ClusterConfig: cc,
			Provider: &corev1.IdentityProvider{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec: &corev1.IdentityProvider_Spec{},
			},
		})
		assert.NotNil(t, err)
	}

	{
		_, err := NewConnector(ctx, &utils.ProviderOpts{
			OcteliumC:     fakeC.OcteliumC,
			ClusterConfig: cc,
			Provider:      newGithubIDP("client-id", utilrand.GetRandomStringCanonical(8)),
		})
		assert.NotNil(t, err)
	}

	{
		idp := newGithubIDP("client-id", sec.Metadata.Name)

		c, err := NewConnector(ctx, &utils.ProviderOpts{
			OcteliumC:     fakeC.OcteliumC,
			ClusterConfig: cc,
			Provider:      idp,
		})
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, c)

		assert.Equal(t, idp.Metadata.Name, c.Name())
		assert.Equal(t, "github", c.Type())
		assert.Equal(t, idp.Metadata.Uid, c.Provider().Metadata.Uid)
	}
}

func TestOauth2Config(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	sec := newGithubTestSecret(t, ctx, tst)

	clientID := utilrand.GetRandomStringCanonical(16)

	c, err := NewConnector(ctx, &utils.ProviderOpts{
		OcteliumC:     fakeC.OcteliumC,
		ClusterConfig: cc,
		Provider:      newGithubIDP(clientID, sec.Metadata.Name),
	})
	assert.Nil(t, err)

	cfg := c.oauth2Config()

	assert.Equal(t, clientID, cfg.ClientID)
	assert.True(t, len(cfg.ClientSecret) > 0)
	assert.Equal(t, "https://github.com/login/oauth/authorize", cfg.Endpoint.AuthURL)
	assert.Equal(t, "https://github.com/login/oauth/access_token", cfg.Endpoint.TokenURL)
	assert.Equal(t, []string{"user:email"}, cfg.Scopes)
	assert.Equal(t, utils.GetCallbackURL(cc.Status.Domain), cfg.RedirectURL)
	assert.Equal(t, fmt.Sprintf("https://%s/callback", cc.Status.Domain), cfg.RedirectURL)
}

func TestGetLogin(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	sec := newGithubTestSecret(t, ctx, tst)

	clientID := utilrand.GetRandomStringCanonical(16)

	c, err := NewConnector(ctx, &utils.ProviderOpts{
		OcteliumC:     fakeC.OcteliumC,
		ClusterConfig: cc,
		Provider:      newGithubIDP(clientID, sec.Metadata.Name),
	})
	assert.Nil(t, err)

	state := utilrand.GetRandomStringCanonical(36)

	ret, err := c.GetLogin(httptest.NewRequest("GET", "/", nil), state)
	assert.Nil(t, err, "%+v", err)
	assert.True(t, len(ret.LoginURL) > 0)

	u, err := url.Parse(ret.LoginURL)
	assert.Nil(t, err)

	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "github.com", u.Host)
	assert.Equal(t, "/login/oauth/authorize", u.Path)

	q := u.Query()
	assert.Equal(t, clientID, q.Get("client_id"))
	assert.Equal(t, state, q.Get("state"))
	assert.Equal(t, "user:email", q.Get("scope"))
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, utils.GetCallbackURL(cc.Status.Domain), q.Get("redirect_uri"))

	{
		other, err := c.GetLogin(httptest.NewRequest("GET", "/", nil),
			utilrand.GetRandomStringCanonical(36))
		assert.Nil(t, err)
		assert.NotEqual(t, ret.LoginURL, other.LoginURL)
	}
}

func TestHandleCallbackError(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	sec := newGithubTestSecret(t, ctx, tst)

	c, err := NewConnector(ctx, &utils.ProviderOpts{
		OcteliumC:     fakeC.OcteliumC,
		ClusterConfig: cc,
		Provider:      newGithubIDP("client-id", sec.Metadata.Name),
	})
	assert.Nil(t, err)

	{
		req := httptest.NewRequest("GET",
			"https://example.com/callback?error=access_denied&error_description=the+user+denied", nil)

		_, err := c.HandleCallback(req, nil)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "the user denied")
	}

	{
		req := httptest.NewRequest("GET",
			"https://example.com/callback?error=server_error", nil)

		_, err := c.HandleCallback(req, nil)
		assert.NotNil(t, err)
	}
}
