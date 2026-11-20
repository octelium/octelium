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
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/loginicon"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
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

	srv.genCache.Set("authserver-app-js-hash", "xxx")

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
var rgxInterTagWhitespace = regexp.MustCompile(`>\s+<`)

func assertMinifiedBody(t *testing.T, body []byte) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	assert.Nil(t, err)

	assert.False(t, strings.Contains(string(body), "\n"))
	assert.False(t, rgxInterTagWhitespace.Match(body))
	assert.Equal(t, 1, doc.Find("head > meta[charset]").Length())
	assert.NotEmpty(t, doc.Find("head > title").Text())
	assert.Equal(t, 1, doc.Find("body > #root").Length())
}

func getGlobalsFromBody(t *testing.T, body []byte, nonce string) *templateGlobals {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	assert.Nil(t, err)

	script := doc.Find("script").FilterFunction(func(_ int, sel *goquery.Selection) bool {
		return strings.Contains(sel.Text(), "window.__OCTELIUM_GLOBALS__")
	})
	assert.Equal(t, 1, script.Length())
	assert.Equal(t, nonce, script.AttrOr("nonce", ""))

	_, globalsJSON, found := strings.Cut(script.Text(), " = ")
	assert.True(t, found)

	ret := &templateGlobals{}
	assert.Nil(t, json.Unmarshal([]byte(globalsJSON), ret))
	return ret
}

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
	assertMinifiedBody(t, body)

	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Empty(t, resp.Cookies())

	globals := getGlobalsFromBody(t, body, nonce)
	assert.Equal(t, srv.domain, globals.Cluster.Domain)

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
	assert.True(t, strings.HasPrefix(string(body), "<!DOCTYPE html>"))
	assertMinifiedBody(t, body)

	csp := resp.Header.Get("Content-Security-Policy")
	assert.True(t, strings.Contains(csp, "default-src 'none'"))
	assert.True(t, strings.Contains(csp, "frame-ancestors 'none'"))

	match := rgxCSPNonce.FindStringSubmatch(csp)
	assert.Equal(t, 2, len(match))

	nonce := match[1]
	assert.Equal(t, 24, len(nonce))

	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Empty(t, resp.Cookies())

	globals := getGlobalsFromBody(t, body, nonce)
	assert.Equal(t, srv.domain, globals.Cluster.Domain)

	{
		w2 := httptest.NewRecorder()
		srv.renderLoggedIn(w2)
		csp2 := w2.Result().Header.Get("Content-Security-Policy")

		match2 := rgxCSPNonce.FindStringSubmatch(csp2)
		assert.Equal(t, 2, len(match2))
		assert.NotEqual(t, nonce, match2[1])
	}

	{
		srv.loggedInPageC.Store(nil)

		w2 := httptest.NewRecorder()
		srv.renderLoggedIn(w2)
		assert.Equal(t, http.StatusInternalServerError, w2.Result().StatusCode)
	}
}

func TestRenderIndexCache(t *testing.T) {

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

	doRender := func() string {
		w := httptest.NewRecorder()
		srv.renderIndex(w)
		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)

		csp := resp.Header.Get("Content-Security-Policy")
		match := rgxCSPNonce.FindStringSubmatch(csp)
		assert.Equal(t, 2, len(match))

		nonce := match[1]
		assert.True(t, strings.Contains(string(body), fmt.Sprintf(`nonce="%s"`, nonce)))

		return strings.ReplaceAll(string(body), nonce, "")
	}

	{
		assert.Equal(t, doRender(), doRender())
		assert.False(t, strings.Contains(doRender(), "spec-display"))
	}

	idp := newIdPWithNames(t, ctx, srv,
		utilrand.GetRandomStringCanonical(8), "meta-display", "spec-display")

	{
		assert.Nil(t, srv.setIdentityProviders(ctx))

		body := doRender()
		assert.True(t, strings.Contains(body, "spec-display"))
		assert.True(t, strings.Contains(body, idp.Metadata.Uid))

		w := httptest.NewRecorder()
		srv.renderLoggedIn(w)
		loggedInBody := w.Body.String()
		assert.False(t, strings.Contains(loggedInBody, "spec-display"))
		assert.False(t, strings.Contains(loggedInBody, idp.Metadata.Uid))
		assert.True(t, strings.Contains(loggedInBody, "__OCTELIUM_GLOBALS__"))
	}

	{
		assert.Nil(t, srv.onClusterConfigUpdate(ctx, clusterCfg, clusterCfg))
		assert.True(t, strings.Contains(doRender(), "spec-display"))
	}
}

func TestLoginIcon(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	svg := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 50"><rect width="200" height="50"/></svg>`
	svgDataURL := "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))

	var pngBuf bytes.Buffer
	assert.Nil(t, png.Encode(&pngBuf, image.NewRGBA(image.Rect(0, 0, 4, 4))))
	pngIcon := pngBuf.Bytes()
	pngDataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngIcon)

	getLoginIcons := func(srv *server) []string {
		var ret []string
		for _, render := range []func(w http.ResponseWriter){srv.renderIndex, srv.renderLoggedIn} {
			w := httptest.NewRecorder()
			render(w)

			resp := w.Result()
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			csp := resp.Header.Get("Content-Security-Policy")
			assert.True(t, strings.Contains(csp, "img-src 'self' data:"))

			match := rgxCSPNonce.FindStringSubmatch(csp)
			assert.Equal(t, 2, len(match))

			globals := getGlobalsFromBody(t, w.Body.Bytes(), match[1])
			assert.Equal(t, srv.domain, globals.Cluster.Domain)

			if globals.Login == nil {
				ret = append(ret, "")
			} else {
				assert.NotEmpty(t, globals.Login.Icon)
				ret = append(ret, globals.Login.Icon)
			}
		}

		return ret
	}

	assertLoginIcon := func(srv *server, icon string) {
		assert.Eventually(t, func() bool {
			icons := getLoginIcons(srv)
			return icons[0] == icon && icons[1] == icon
		}, 10*time.Second, 50*time.Millisecond)
	}

	setLoginIcon := func(icon *corev1.ClusterConfig_Spec_Authentication_Login_Icon) *corev1.ClusterConfig {
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		if icon == nil {
			cc.Spec.Authentication = nil
		} else {
			cc.Spec.Authentication = &corev1.ClusterConfig_Spec_Authentication{
				Login: &corev1.ClusterConfig_Spec_Authentication_Login{
					Icon: icon,
				},
			}
		}

		cc, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)

		return cc
	}

	t.Run("inline", func(t *testing.T) {
		clusterCfg, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
		assert.Nil(t, err)

		assertLoginIcon(srv, "")

		for _, tc := range []struct {
			icon     *corev1.ClusterConfig_Spec_Authentication_Login_Icon
			expected string
		}{
			{
				icon: &corev1.ClusterConfig_Spec_Authentication_Login_Icon{
					Type: &corev1.ClusterConfig_Spec_Authentication_Login_Icon_Inline{
						Inline: svg,
					},
				},
				expected: svgDataURL,
			},
			{
				icon: &corev1.ClusterConfig_Spec_Authentication_Login_Icon{
					Type: &corev1.ClusterConfig_Spec_Authentication_Login_Icon_InlineBytes{
						InlineBytes: pngIcon,
					},
				},
				expected: pngDataURL,
			},
			{
				icon:     nil,
				expected: "",
			},
			{
				icon: &corev1.ClusterConfig_Spec_Authentication_Login_Icon{
					Type: &corev1.ClusterConfig_Spec_Authentication_Login_Icon_InlineBytes{
						InlineBytes: []byte(svg),
					},
				},
				expected: svgDataURL,
			},
			{
				icon:     &corev1.ClusterConfig_Spec_Authentication_Login_Icon{},
				expected: "",
			},
			{
				icon: &corev1.ClusterConfig_Spec_Authentication_Login_Icon{
					Type: &corev1.ClusterConfig_Spec_Authentication_Login_Icon_Inline{
						Inline: "<html><script>alert(1)</script></html>",
					},
				},
				expected: "",
			},
			{
				icon: &corev1.ClusterConfig_Spec_Authentication_Login_Icon{
					Type: &corev1.ClusterConfig_Spec_Authentication_Login_Icon_InlineBytes{
						InlineBytes: append(pngIcon, make([]byte, loginicon.MaxSize)...),
					},
				},
				expected: "",
			},
		} {
			cc := setLoginIcon(tc.icon)
			assert.Nil(t, srv.onClusterConfigUpdate(ctx, cc, clusterCfg))
			assertLoginIcon(srv, tc.expected)
		}
	})

	t.Run("fromConfig", func(t *testing.T) {
		cfg, err := fakeC.OcteliumC.CoreC().CreateConfig(ctx, &corev1.Config{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec:   &corev1.Config_Spec{},
			Status: &corev1.Config_Status{},
			Data: &corev1.Config_Data{
				Type: &corev1.Config_Data_Value{
					Value: svg,
				},
			},
		})
		assert.Nil(t, err)

		clusterCfg := setLoginIcon(&corev1.ClusterConfig_Spec_Authentication_Login_Icon{
			Type: &corev1.ClusterConfig_Spec_Authentication_Login_Icon_FromConfig{
				FromConfig: cfg.Metadata.Name,
			},
		})

		srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
		assert.Nil(t, err)

		assertLoginIcon(srv, svgDataURL)

		{
			other, err := fakeC.OcteliumC.CoreC().CreateConfig(ctx, &corev1.Config{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec:   &corev1.Config_Spec{},
				Status: &corev1.Config_Status{},
				Data: &corev1.Config_Data{
					Type: &corev1.Config_Data_ValueBytes{
						ValueBytes: pngIcon,
					},
				},
			})
			assert.Nil(t, err)

			assert.Nil(t, srv.onConfigUpdate(ctx, other))
			assertLoginIcon(srv, svgDataURL)
		}

		{
			cfg.Data = &corev1.Config_Data{
				Type: &corev1.Config_Data_ValueBytes{
					ValueBytes: pngIcon,
				},
			}
			cfg, err = fakeC.OcteliumC.CoreC().UpdateConfig(ctx, cfg)
			assert.Nil(t, err)

			assert.Nil(t, srv.onConfigUpdate(ctx, cfg))
			assertLoginIcon(srv, pngDataURL)
		}

		{
			cfg.Data = &corev1.Config_Data{
				Type: &corev1.Config_Data_Value{
					Value: "hello world",
				},
			}
			cfg, err = fakeC.OcteliumC.CoreC().UpdateConfig(ctx, cfg)
			assert.Nil(t, err)

			assert.Nil(t, srv.onConfigUpdate(ctx, cfg))
			assertLoginIcon(srv, "")
		}

		{
			cfg.Data = &corev1.Config_Data{
				Type: &corev1.Config_Data_Value{
					Value: svg,
				},
			}
			cfg, err = fakeC.OcteliumC.CoreC().UpdateConfig(ctx, cfg)
			assert.Nil(t, err)

			assert.Nil(t, srv.onConfigUpdate(ctx, cfg))
			assertLoginIcon(srv, svgDataURL)
		}

		{
			_, err = fakeC.OcteliumC.CoreC().DeleteConfig(ctx, apivalidation.ObjectToRDeleteOptions(cfg))
			assert.Nil(t, err)

			assert.Nil(t, srv.onConfigUpdate(ctx, cfg))
			assertLoginIcon(srv, "")
		}
	})

	t.Run("fromConfig not found", func(t *testing.T) {
		clusterCfg := setLoginIcon(&corev1.ClusterConfig_Spec_Authentication_Login_Icon{
			Type: &corev1.ClusterConfig_Spec_Authentication_Login_Icon_FromConfig{
				FromConfig: utilrand.GetRandomStringCanonical(8),
			},
		})

		srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
		assert.Nil(t, err)

		assertLoginIcon(srv, "")
	})
}
