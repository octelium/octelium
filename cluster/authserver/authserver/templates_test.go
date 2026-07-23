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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
)

func TestRenderIndex(t *testing.T) {
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

	srv.genCache.Set("authserver-app-js-hash", "xxx", cache.NoExpiration)

	req := httptest.NewRequest("GET", "http://localhost/", nil)
	w := httptest.NewRecorder()
	srv.handleLogin(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	_, err = io.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, resp.StatusCode, http.StatusOK)
}

var rgxCSPNonce = regexp.MustCompile(`'nonce-([a-zA-Z0-9]+)'`)

func newIdPWithNames(t *testing.T, ctx context.Context, srv *server,
	name, metadataDisplayName, specDisplayName string) *corev1.IdentityProvider {

	sec, err := srv.octeliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
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

	idp, err := srv.octeliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name:        name,
			DisplayName: metadataDisplayName,
		},
		Spec: &corev1.IdentityProvider_Spec{
			DisplayName: specDisplayName,
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

	return idp
}

func TestSetHTMLSecurityHeaders(t *testing.T) {

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

	nonce := utilrand.GetRandomStringCanonical(24)

	w := httptest.NewRecorder()
	srv.setHTMLSecurityHeaders(w, nonce)

	csp := w.Header().Get("Content-Security-Policy")

	assert.True(t, strings.Contains(csp, "default-src 'none'"))
	assert.True(t, strings.Contains(csp, fmt.Sprintf("script-src 'self' 'nonce-%s'", nonce)))
	assert.True(t, strings.Contains(csp, "frame-ancestors 'none'"))
	assert.True(t, strings.Contains(csp, "frame-src 'none'"))
	assert.True(t, strings.Contains(csp, "object-src 'none'"))
	assert.True(t, strings.Contains(csp, "base-uri 'none'"))
	assert.True(t, strings.Contains(csp, "form-action 'self'"))
	assert.True(t, strings.Contains(csp,
		fmt.Sprintf("connect-src 'self' https://octelium-api.%s", srv.domain)))

	assert.False(t, strings.Contains(csp, "unsafe-eval"))
	assert.False(t, strings.Contains(csp, "script-src 'unsafe-inline'"))

	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))

	{
		w2 := httptest.NewRecorder()
		srv.setHTMLSecurityHeaders(w2, utilrand.GetRandomStringCanonical(24))
		assert.NotEqual(t, csp, w2.Header().Get("Content-Security-Policy"))
	}
}

func TestSetDomainCookie(t *testing.T) {

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

	w := httptest.NewRecorder()
	srv.setDomainCookie(w)

	cookies := w.Result().Cookies()
	assert.Equal(t, 1, len(cookies))

	cookie := cookies[0]
	assert.Equal(t, "octelium_domain", cookie.Name)
	assert.Equal(t, srv.domain, cookie.Value)
	assert.Equal(t, srv.domain, cookie.Domain)
	assert.Equal(t, "/", cookie.Path)
	assert.True(t, cookie.Secure)
	assert.False(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteNoneMode, cookie.SameSite)
}

func TestGetTemplateIndexArgs(t *testing.T) {

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

	getState := func() *templateState {
		args, err := srv.getTemplateIndexArgs(utilrand.GetRandomStringCanonical(24))
		assert.Nil(t, err, "%+v", err)

		ret := &templateState{}
		assert.Nil(t, json.Unmarshal([]byte(args.State), ret))
		return ret
	}

	{
		state := getState()
		assert.Equal(t, srv.domain, state.Domain)
		assert.False(t, state.IsPasskeyLoginEnabled)
		assert.Equal(t, 0, len(state.IdentityProviders))
	}

	idpSpecName := newIdPWithNames(t, ctx, srv,
		utilrand.GetRandomStringCanonical(8), "meta-display", "spec-display")
	idpMetaName := newIdPWithNames(t, ctx, srv,
		utilrand.GetRandomStringCanonical(8), "only-meta-display", "")
	idpNoDisplay := newIdPWithNames(t, ctx, srv,
		utilrand.GetRandomStringCanonical(8), "", "")

	assert.Nil(t, srv.setIdentityProviders(ctx))

	{
		state := getState()
		assert.Equal(t, 3, len(state.IdentityProviders))

		byUID := map[string]templateStateProvider{}
		for _, itm := range state.IdentityProviders {
			byUID[itm.UID] = itm
		}

		assert.Equal(t, "spec-display", byUID[idpSpecName.Metadata.Uid].DisplayName)
		assert.Equal(t, "only-meta-display", byUID[idpMetaName.Metadata.Uid].DisplayName)
		assert.Equal(t, idpNoDisplay.Metadata.Name, byUID[idpNoDisplay.Metadata.Uid].DisplayName)
	}

	{
		idp, err := srv.octeliumC.CoreC().GetIdentityProvider(ctx, &rmetav1.GetOptions{
			Uid: idpSpecName.Metadata.Uid,
		})
		assert.Nil(t, err)

		idp.Spec.IsDisabled = true
		_, err = srv.octeliumC.CoreC().UpdateIdentityProvider(ctx, idp)
		assert.Nil(t, err)

		assert.Nil(t, srv.setIdentityProviders(ctx))

		state := getState()
		assert.Equal(t, 2, len(state.IdentityProviders))

		for _, itm := range state.IdentityProviders {
			assert.NotEqual(t, idpSpecName.Metadata.Uid, itm.UID)
		}
	}
}

func TestGetTemplateIndexArgsPasskey(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	clusterCfg.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
		EnablePasskeyLogin: true,
	}
	clusterCfg, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, clusterCfg)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	args, err := srv.getTemplateIndexArgs(utilrand.GetRandomStringCanonical(24))
	assert.Nil(t, err, "%+v", err)

	state := &templateState{}
	assert.Nil(t, json.Unmarshal([]byte(args.State), state))

	assert.True(t, state.IsPasskeyLoginEnabled)
}

func TestRenderIndexNonce(t *testing.T) {

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

	w := httptest.NewRecorder()
	srv.renderIndex(w)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.Nil(t, err)

	csp := resp.Header.Get("Content-Security-Policy")
	assert.True(t, len(csp) > 0)

	match := rgxCSPNonce.FindStringSubmatch(csp)
	assert.Equal(t, 2, len(match))

	nonce := match[1]
	assert.Equal(t, 24, len(nonce))

	assert.True(t, strings.Contains(string(body), fmt.Sprintf(`nonce="%s"`, nonce)))
	assert.True(t, strings.Contains(string(body), "__OCTELIUM_STATE__"))
	assert.True(t, strings.Contains(string(body), "__OCTELIUM_GLOBALS__"))
	assert.True(t, strings.HasPrefix(string(body), "<!DOCTYPE html>"))

	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))

	found := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "octelium_domain" {
			found = true
			assert.Equal(t, srv.domain, cookie.Value)
		}
	}
	assert.True(t, found)

	{
		w2 := httptest.NewRecorder()
		srv.renderIndex(w2)
		csp2 := w2.Result().Header.Get("Content-Security-Policy")

		match2 := rgxCSPNonce.FindStringSubmatch(csp2)
		assert.Equal(t, 2, len(match2))
		assert.NotEqual(t, nonce, match2[1])
	}
}

func TestRenderLoggedIn(t *testing.T) {

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

	w := httptest.NewRecorder()
	srv.renderLoggedIn(w)

	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	assert.Nil(t, err)
	assert.True(t, len(body) > 0)

	assert.False(t, strings.Contains(string(body), "__OCTELIUM_STATE__"))

	csp := resp.Header.Get("Content-Security-Policy")
	assert.True(t, strings.Contains(csp, "default-src 'none'"))
	assert.True(t, strings.Contains(csp, "frame-ancestors 'none'"))

	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	found := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "octelium_domain" {
			found = true
		}
	}
	assert.True(t, found)
}
