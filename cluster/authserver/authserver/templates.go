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
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
)

var indexTmpl2 = template.Must(template.New("index.html").Parse(`
<script nonce="{{ .Nonce }}">window.__OCTELIUM_STATE__ = {{ .State }}</script>
<script nonce="{{ .Nonce }}">window.__OCTELIUM_GLOBALS__ = {{ .Globals }}</script>
`))

type indexTemplateArgs struct {
	Nonce   string
	State   template.JS
	Globals template.JS
}

func (s *server) renderIndex(w http.ResponseWriter) {
	nonce := utilrand.GetRandomStringCanonical(24)

	data, err := s.getTemplateIndexArgs(nonce)
	if err != nil {
		zap.L().Error("Could not get index template args", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	blob, err := fs.ReadFile(fsWeb, filepath.Join("web", "index.html"))
	if err != nil {
		zap.L().Error("Could not read index.html file from web fs", zap.Error(err))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(blob))
	if err != nil {
		zap.L().Error("Could not get index.html doc", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var scripts bytes.Buffer
	if err := indexTmpl2.Execute(&scripts, data); err != nil {
		zap.L().Error("Could not execute index template", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	head := doc.Find("head").First()
	if head.Length() == 0 {
		zap.L().Error("Could not find head element in index.html")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	head.AppendHtml(scripts.String())

	var out bytes.Buffer
	out.WriteString("<!DOCTYPE html>")
	if err := goquery.Render(&out, head.Parent()); err != nil {
		zap.L().Error("Could not render index.html", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.setDomainCookie(w)
	s.setHTMLSecurityHeaders(w, nonce)
	w.Write(out.Bytes())
}

func (s *server) getTemplateIndexArgs(nonce string) (*indexTemplateArgs, error) {
	state := &templateState{
		Domain: s.domain,
	}

	cc := s.ccCtl.Get()
	if cc.Spec.Authenticator != nil && cc.Spec.Authenticator.EnablePasskeyLogin {
		state.IsPasskeyLoginEnabled = true
	}

	s.webProvidersC.RLock()
	defer s.webProvidersC.RUnlock()

	for _, idp := range s.webProvidersC.connectors {
		if idp.Provider().Spec.IsDisabled {
			continue
		}

		item := templateStateProvider{
			UID:         idp.Provider().Metadata.Uid,
			DisplayName: idp.Provider().Spec.DisplayName,
		}

		if item.DisplayName == "" {
			item.DisplayName = idp.Provider().Metadata.DisplayName
		}

		if item.DisplayName == "" {
			item.DisplayName = idp.Provider().Metadata.Name
		}

		state.IdentityProviders = append(state.IdentityProviders, item)
	}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}

	globalsJSON, err := json.Marshal(s.getTemplateGlobals())
	if err != nil {
		return nil, err
	}

	return &indexTemplateArgs{
		Nonce:   nonce,
		State:   template.JS(stateJSON),
		Globals: template.JS(globalsJSON),
	}, nil
}

type templateState struct {
	Domain                string                  `json:"domain"`
	IdentityProviders     []templateStateProvider `json:"identityProviders,omitempty"`
	IsPasskeyLoginEnabled bool                    `json:"isPasskeyLoginEnabled,omitempty"`
}

type templateStateProvider struct {
	UID         string `json:"uid,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	PicURL      string `json:"picURL,omitempty"`
}

type templateGlobals struct {
	Cluster templateGlobalsCluster `json:"cluster,omitempty"`
}

type templateGlobalsCluster struct {
	Domain      string `json:"domain,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

func (s *server) renderLoggedIn(w http.ResponseWriter) {
	nonce := utilrand.GetRandomStringCanonical(24)

	blob, err := fs.ReadFile(fsWeb, filepath.Join("web", "index.html"))
	if err != nil {
		zap.L().Error("Could not read index.html file from web fs", zap.Error(err))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	s.setDomainCookie(w)
	s.setHTMLSecurityHeaders(w, nonce)
	w.Write(blob)
}

func (s *server) setHTMLSecurityHeaders(w http.ResponseWriter, nonce string) {
	csp := strings.Join([]string{
		"default-src 'none'",
		fmt.Sprintf("script-src 'self' 'nonce-%s'", nonce),
		fmt.Sprintf("style-src 'self' 'unsafe-inline' 'nonce-%s'", nonce),
		"img-src 'self' data:",
		"font-src 'self'",
		fmt.Sprintf("connect-src 'self' https://octelium-api.%s", s.domain),
		"frame-src 'none'",
		"frame-ancestors 'none'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
	}, "; ")

	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func (s *server) setDomainCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "octelium_domain",
		Value:    s.domain,
		Secure:   true,
		Domain:   s.domain,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
	})
}
