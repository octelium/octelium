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
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"go.uber.org/zap"
)

var indexTmpl2 = template.Must(template.New("index.html").Parse(`
<script>window.__OCTELIUM_STATE__ = {{ .State }}</script>
<script>window.__OCTELIUM_GLOBALS__ = {{ .Globals }}</script>
`))

func (s *server) renderIndex(w http.ResponseWriter) {

	data := s.getTemplateIndexArgs()

	blob, err := fs.ReadFile(fsWeb, filepath.Join("web", "/index.html"))
	if err != nil {
		zap.L().Error("Could not read index.html file from web fs", zap.Error(err))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(blob)))
	if err != nil {
		zap.L().Error("Could not get index.html doc", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var b bytes.Buffer
	var b2 bytes.Buffer

	b2.Write([]byte(`<!DOCTYPE html>`))

	err = indexTmpl2.Execute(&b, data)
	if err != nil {
		zap.L().Debug("Could not read index.html file from web fs", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := goquery.Render(&b2, doc.Find("head").First().AppendHtml(b.String()).Parent()); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.setDomainCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b2.Bytes())
}

func (s *server) getTemplateIndexArgs() map[string]any {

	tmplArgs := map[string]any{
		"Globals": s.getTemplateGlobals(),
	}

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

	tmplArgs["State"] = state

	return tmplArgs
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

	blob, err := fs.ReadFile(fsWeb, filepath.Join("web", "/index.html"))
	if err != nil {
		zap.L().Error("Could not read index.html file from web fs", zap.Error(err))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	s.setDomainCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(blob)
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
