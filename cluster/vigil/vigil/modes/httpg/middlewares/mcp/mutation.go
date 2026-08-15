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

package mcp

import (
	"context"
	"net/http"

	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"go.uber.org/zap"
)

type rebuild struct {
	next http.Handler
}

func NewRebuild(ctx context.Context, next http.Handler) (http.Handler, error) {
	return &rebuild{
		next: next,
	}, nil
}

func (m *rebuild) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	if !ucorev1.ToService(reqCtx.Service).IsMCP() {
		m.next.ServeHTTP(w, req)
		return
	}

	if reqCtx.IsBodyChanged() {
		zap.L().Debug("MCP request body was mutated by a PRE_AUTH plugin. Rebuilding the RequestContext")
		middlewares.SetMCPRequestContext(reqCtx, req)
		reqCtx.SetBodyDigest()
	}

	m.next.ServeHTTP(w, req)
}

type seal struct {
	next http.Handler
}

func NewSeal(ctx context.Context, next http.Handler) (http.Handler, error) {
	return &seal{
		next: next,
	}, nil
}

func (m *seal) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	if !ucorev1.ToService(reqCtx.Service).IsMCP() {
		m.next.ServeHTTP(w, req)
		return
	}

	if reqCtx.IsBodyChanged() {
		zap.L().Warn("Rejecting an MCP request whose body was mutated after authorization",
			zap.String("method", reqCtx.MCP.GetMethod()),
			zap.String("name", reqCtx.MCP.GetName()))

		WriteError(w, &WriteErrorOpts{
			HTTPStatus: http.StatusForbidden,
			Code:       ErrCodeMutationRejected,
			Message:    "Octelium: the MCP request body was modified after authorization",
			RequestID:  reqCtx.MCP.GetRequestID(),
		})
		return
	}

	m.next.ServeHTTP(w, req)
}
