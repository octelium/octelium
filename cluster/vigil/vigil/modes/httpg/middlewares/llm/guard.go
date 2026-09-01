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

package llm

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
)

type guard struct {
	next http.Handler
}

func NewGuard(ctx context.Context, next http.Handler) (http.Handler, error) {
	return &guard{
		next: next,
	}, nil
}

func (m *guard) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	if !ucorev1.ToService(reqCtx.Service).IsLLM() {
		m.next.ServeHTTP(w, req)
		return
	}

	if o := m.check(req, reqCtx); o != nil {
		o.Protocol = reqCtx.LLM.GetProtocol()
		WriteError(w, o)
		return
	}

	m.next.ServeHTTP(w, req)
}

func (m *guard) check(req *http.Request, reqCtx *middlewares.RequestContext) *WriteErrorOpts {
	cfg := ucorev1.ToServiceConfig(reqCtx.ServiceConfig).GetLLM()
	llmReq := reqCtx.LLM

	if llmReq == nil || !llmReq.IsKnownRoute {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusNotFound,
			Type:       ErrTypeNotFound,
			Code:       ErrCodeNotFound,
			Message: fmt.Sprintf("Octelium: unknown inference API route: %s %s",
				req.Method, req.URL.Path),
		}
	}

	if llmReq.IsModelTooLong {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Type:       ErrTypeInvalidRequest,
			Code:       ErrCodeInvalidRequest,
			Message:    "Octelium: the requested model name is too long",
		}
	}

	if !httputils.IsLLMOperationBodyParsed(llmReq.Operation) {
		return nil
	}

	if o := m.checkContentType(req); o != nil {
		return o
	}

	if !llmReq.IsBodyValid {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Type:       ErrTypeInvalidRequest,
			Code:       ErrCodeInvalidRequest,
			Message:    "Octelium: the request body is not a JSON object",
		}
	}

	if llmReq.Stream && !httputils.IsLLMOperationStreamable(llmReq.Operation) {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Type:       ErrTypeInvalidRequest,
			Code:       ErrCodeInvalidRequest,
			Message: fmt.Sprintf("Octelium: the operation cannot be streamed: %s",
				llmReq.Operation.String()),
		}
	}

	return m.checkLimits(llmReq, cfg)
}

func (m *guard) checkLimits(llmReq *httputils.LLMRequest,
	cfg *corev1.Service_Spec_Config_LLM) *WriteErrorOpts {

	limits := cfg.GetLimits()
	if limits == nil {
		return nil
	}

	if val := limits.GetMaxTools(); val > 0 && llmReq.ToolCount > val {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Type:       ErrTypeInvalidRequest,
			Code:       ErrCodeLimitExceeded,
			Message: fmt.Sprintf(
				"Octelium: the request declares more than %d tools", val),
		}
	}

	if val := limits.GetMaxToolSchemaBytes(); val > 0 && llmReq.MaxToolSchemaBytes > val {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Type:       ErrTypeInvalidRequest,
			Code:       ErrCodeLimitExceeded,
			Message: fmt.Sprintf(
				"Octelium: the request declares a tool whose schema is above %d bytes", val),
		}
	}

	if val := limits.GetMaxOutputTokens(); val > 0 && llmReq.MaxOutputTokens > val {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Type:       ErrTypeInvalidRequest,
			Code:       ErrCodeLimitExceeded,
			Message: fmt.Sprintf(
				"Octelium: the requested maximum output token count is above %d", val),
		}
	}

	if val := limits.GetMaxEstimatedInputTokens(); val > 0 &&
		llmReq.EstimatedInputTokens > val {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusRequestEntityTooLarge,
			Type:       ErrTypeInvalidRequest,
			Code:       ErrCodeLimitExceeded,
			Message: fmt.Sprintf(
				"Octelium: the estimated input token count is above %d", val),
		}
	}

	return nil
}

func (m *guard) checkContentType(req *http.Request) *WriteErrorOpts {
	invalid := &WriteErrorOpts{
		HTTPStatus: http.StatusUnsupportedMediaType,
		Type:       ErrTypeInvalidRequest,
		Code:       ErrCodeInvalidRequest,
		Message:    "Octelium: the inference API requires a JSON Content-Type",
	}

	ct := req.Header.Get("Content-Type")
	if ct == "" {
		return invalid
	}

	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return invalid
	}

	return nil
}
