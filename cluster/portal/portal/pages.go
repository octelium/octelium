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
	"embed"
	"io/fs"
	"net/http"

	"go.uber.org/zap"
)

//go:embed web
var fsWeb embed.FS

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "octelium_domain",
		Value:    s.domain,
		Secure:   true,
		Domain:   s.domain,
		Path:     "/",
		SameSite: http.SameSiteNoneMode,
	})

	s.renderIndex(w)
}

func (s *server) handleStatic() http.Handler {
	subFS, err := fs.Sub(fsWeb, "web")
	if err != nil {
		zap.L().Fatal("Could not initialize static file system", zap.Error(err))
	}

	httpFS := http.FS(subFS)

	return http.FileServer(httpFS)
}
