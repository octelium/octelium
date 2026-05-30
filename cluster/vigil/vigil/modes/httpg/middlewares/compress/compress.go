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

package compress

import (
	"compress/gzip"
	"context"
	"net/http"
	"strings"

	"github.com/klauspost/compress/gzhttp"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"
)

var contentTypes = []string{
	"text/html",
	"text/plain",
	"text/css",
	"text/xml",
	"text/javascript",
	"application/javascript",
	"application/json",
	"application/xml",
	"image/svg+xml",
	"application/wasm",
}

type middleware struct {
	next    http.Handler
	handler http.Handler
}

func New(ctx context.Context, next http.Handler) (http.Handler, error) {
	wrapper, err := gzhttp.NewWrapper(
		gzhttp.ContentTypes(contentTypes),
		gzhttp.CompressionLevel(gzip.DefaultCompression),
		gzhttp.MinSize(gzhttp.DefaultMinSize),
	)
	if err != nil {
		zap.L().Warn("Could not create gzhttp wrapper",
			zap.Error(err))
		return &middleware{next: next, handler: next}, nil
	}

	return &middleware{next: next, handler: wrapper(next)}, nil
}

func (c *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if isStreamingRequest(req) {
		c.next.ServeHTTP(rw, req)
		return
	}

	c.handler.ServeHTTP(rw, req)
}

func isStreamingRequest(req *http.Request) bool {
	hdr := req.Header
	if httpguts.HeaderValuesContainsToken(hdr["Connection"], "Upgrade") {
		return true
	}

	if strings.EqualFold(hdr.Get("X-Accel-Buffering"), "no") {
		return true
	}

	if strings.Contains(hdr.Get("Accept"), "text/event-stream") {
		return true
	}

	reqCtx := middlewares.GetCtxRequestContext(req.Context())
	if reqCtx != nil && reqCtx.Service != nil &&
		ucorev1.ToService(reqCtx.Service).IsKubernetes() {
		p := req.URL.Path
		if strings.HasSuffix(p, "/exec") ||
			strings.HasSuffix(p, "/attach") ||
			strings.HasSuffix(p, "/log") ||
			strings.HasSuffix(p, "/portforward") {
			return true
		}
		q := req.URL.Query()
		switch q.Get("follow") {
		case "true", "1":
			return true
		}
		switch q.Get("watch") {
		case "true", "1":
			return true
		}
	}

	return false
}
