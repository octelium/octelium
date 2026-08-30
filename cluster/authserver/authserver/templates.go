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
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
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

var getIndexHTML = sync.OnceValues(func() ([]byte, error) {
	return fs.ReadFile(fsWeb, filepath.Join("web", "index.html"))
})

type indexPage struct {
	segments [][]byte
	size     int
}

func newIndexPage(blob []byte, noncePlaceholder string) *indexPage {
	ret := &indexPage{
		segments: bytes.Split(blob, []byte(noncePlaceholder)),
	}

	for _, segment := range ret.segments {
		ret.size += len(segment)
	}

	return ret
}

func (p *indexPage) render(nonce string) []byte {
	ret := make([]byte, 0, p.size+(len(p.segments)-1)*len(nonce))

	for i, segment := range p.segments {
		if i > 0 {
			ret = append(ret, nonce...)
		}
		ret = append(ret, segment...)
	}

	return ret
}

func (s *server) buildIndexPage() (*indexPage, error) {
	noncePlaceholder := utilrand.GetRandomStringCanonical(32)

	data, err := s.getTemplateIndexArgs(noncePlaceholder)
	if err != nil {
		return nil, err
	}

	blob, err := getIndexHTML()
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}

	var scripts bytes.Buffer
	if err := indexTmpl2.Execute(&scripts, data); err != nil {
		return nil, err
	}

	head := doc.Find("head").First()
	if head.Length() == 0 {
		return nil, errors.Errorf("Could not find head element in index.html")
	}

	head.AppendHtml(scripts.String())

	var out bytes.Buffer
	out.WriteString("<!DOCTYPE html>")
	if err := goquery.Render(&out, head.Parent()); err != nil {
		return nil, err
	}

	return newIndexPage(out.Bytes(), noncePlaceholder), nil
}

func (s *server) setIndexPage() error {
	page, err := s.buildIndexPage()
	if err != nil {
		return err
	}

	s.indexPageC.Store(page)

	return nil
}

func (s *server) renderIndex(w http.ResponseWriter) {
	page := s.indexPageC.Load()
	if page == nil {
		zap.L().Error("The index page has not been set")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	nonce := utilrand.GetRandomStringCanonical(24)

	s.setDomainCookie(w)
	s.setHTMLSecurityHeaders(w, nonce)
	w.Write(page.render(nonce))
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
	Domain string `json:"domain,omitempty"`
}

func (s *server) renderLoggedIn(w http.ResponseWriter) {
	nonce := utilrand.GetRandomStringCanonical(24)

	blob, err := getIndexHTML()
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
		"style-src 'self' 'unsafe-inline'",
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
