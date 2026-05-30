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

	"github.com/klauspost/compress/gzhttp"
	"go.uber.org/zap"
)

var excludedContentTypes = []string{
	"application/grpc",
	"text/event-stream",

	"application/zip",
	"application/gzip",
	"application/x-gzip",
	"application/zstd",
	"application/x-zstd",
}

type middleware struct {
	handler http.Handler
}

func New(ctx context.Context, next http.Handler) (http.Handler, error) {
	wrapper, err := gzhttp.NewWrapper(
		gzhttp.ExceptContentTypes(excludedContentTypes),
		gzhttp.CompressionLevel(gzip.DefaultCompression),
		gzhttp.MinSize(gzhttp.DefaultMinSize),
	)
	if err != nil {
		zap.L().Warn("Could not create gzhttp wrapper",
			zap.Error(err))
		return &middleware{handler: next}, nil
	}

	return &middleware{handler: wrapper(next)}, nil
}

func (c *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	c.handler.ServeHTTP(rw, req)
}
