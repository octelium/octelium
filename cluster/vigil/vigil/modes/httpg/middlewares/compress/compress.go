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
	"mime"
	"net/http"
	"slices"

	"github.com/klauspost/compress/gzhttp"
	"go.uber.org/zap"
)

type middleware struct {
	next http.Handler

	excludes []string
}

func New(ctx context.Context, next http.Handler) (http.Handler, error) {

	excludes := []string{"application/grpc"}

	return &middleware{
		next:     next,
		excludes: excludes,
	}, nil
}

func (c *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	if req.Method == http.MethodHead {
		c.next.ServeHTTP(rw, req)
		return
	}

	mediaType, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))

	if slices.Contains(c.excludes, mediaType) {
		c.next.ServeHTTP(rw, req)
		return
	}

	c.gzipHandler().ServeHTTP(rw, req)
}

func (c *middleware) gzipHandler() http.Handler {
	wrapper, err := gzhttp.NewWrapper(
		gzhttp.ExceptContentTypes(c.excludes),
		gzhttp.CompressionLevel(gzip.DefaultCompression),
		gzhttp.MinSize(gzhttp.DefaultMinSize))
	if err != nil {
		zap.L().Error("Could not create a gzhttp wrapper", zap.Error(err))
		return c.next
	}

	return wrapper(c.next)
}
