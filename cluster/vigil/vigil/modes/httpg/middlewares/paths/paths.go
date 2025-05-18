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

package paths

import (
	"context"
	"net/http"
	"strings"

	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
)

type middleware struct {
	next http.Handler
}

func New(ctx context.Context, next http.Handler) (http.Handler, error) {
	return &middleware{
		next: next,
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqCtx := middlewares.GetCtxRequestContext(req.Context())
	svcCfg := reqCtx.ServiceConfig
	if svcCfg != nil && svcCfg.GetHttp() != nil && svcCfg.GetHttp().Path != nil {
		pth := svcCfg.GetHttp().Path
		if pth.RemovePrefix != "" {
			req.URL.Path = fixPrefixSlash(strings.TrimPrefix(req.URL.Path, pth.RemovePrefix))
			if req.URL.RawPath != "" {
				req.URL.RawPath = fixPrefixSlash(strings.TrimPrefix(req.URL.RawPath, pth.RemovePrefix))
			}

			req.RequestURI = req.URL.RequestURI()
		}

		if pth.AddPrefix != "" {
			req.URL.Path = fixPrefixSlash(pth.AddPrefix + req.URL.Path)
			if req.URL.RawPath != "" {
				req.URL.RawPath = fixPrefixSlash(pth.AddPrefix + req.URL.RawPath)
			}

			req.RequestURI = req.URL.RequestURI()
		}

	}

	m.next.ServeHTTP(rw, req)
}

func fixPrefixSlash(arg string) string {
	if arg == "" {
		return arg
	}

	if arg[0] == '/' {
		return arg
	}

	return "/" + arg
}
