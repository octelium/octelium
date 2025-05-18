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

package portal

import (
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"

	"go.uber.org/zap"
)

var indexTmpl2 = template.Must(template.New("index.html").Parse(`
<script>window.__OCTELIUM_STATE__ = {{ .State }}</script>
<script>window.__OCTELIUM_GLOBALS__ = {{ .Globals }}</script>
`))

func (s *server) renderIndex(w http.ResponseWriter) {

	// data := s.getTemplateIndexArgs()

	blob, err := fs.ReadFile(fsWeb, filepath.Join("web", "/index.html"))
	if err != nil {
		zap.L().Error("Could not read index.html file from web fs", zap.Error(err))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	/*
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
	*/

	w.Write(blob)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func (s *server) getTemplateIndexArgs() map[string]any {

	tmplArgs := map[string]any{
		"Globals": s.getTemplateGlobals(),
	}

	return tmplArgs
}

type templateGlobals struct {
	Cluster templateGlobalsCluster `json:"cluster,omitempty"`
}

type templateGlobalsCluster struct {
	Domain      string `json:"domain,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}
