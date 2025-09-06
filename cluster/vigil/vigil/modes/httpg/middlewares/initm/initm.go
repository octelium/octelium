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

package initm

import (
	"context"
	"net/http"

	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
	"go.uber.org/zap"
)

type middleware struct {
	next http.Handler
}

func New(ctx context.Context, next http.Handler) (http.Handler, error) {

	return &middleware{
		next: next,
	}, nil
}

func (c *middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)
	crw := commonplugin.NewResponseWriter(&commonplugin.NewResponseWriterOpts{
		ResponseWriter: w,
		ReqCtx:         reqCtx,
	})
	c.next.ServeHTTP(crw, req)
	if err := crw.Commit(); err != nil {
		zap.L().Debug("Could not commit rw", zap.Error(err))
	}
}
