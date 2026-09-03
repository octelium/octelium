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
	"encoding/json"
	"net/http"

	"github.com/octelium/octelium/apis/main/corev1"
)

const (
	ErrTypeInvalidRequest = "invalid_request_error"
	ErrTypeAuthentication = "authentication_error"
	ErrTypePermission     = "permission_error"
	ErrTypeNotFound       = "not_found_error"
	ErrTypeAPI            = "api_error"
)

const (
	ErrCodeUnauthenticated = "octelium_unauthenticated"
	ErrCodeUnauthorized    = "octelium_unauthorized"
	ErrCodeInvalidRequest  = "octelium_invalid_request"
	ErrCodeNotFound        = "octelium_not_found"
	ErrCodeOperationDenied = "octelium_operation_denied"
	ErrCodeLimitExceeded   = "octelium_limit_exceeded"
	ErrCodeUpstreamAuth    = "octelium_upstream_auth"
	ErrCodeModelRewrite    = "octelium_model_rewrite"
	ErrCodePromptDenied    = "octelium_prompt_denied"
	ErrCodeToolDenied      = "octelium_tool_denied"
	ErrCodeGuardrail       = "octelium_guardrail"
	ErrCodeReasoning       = "octelium_reasoning"
)

type openAIError struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    string  `json:"code,omitempty"`
}

type openAIErrorResponse struct {
	Error *openAIError `json:"error"`
}

type anthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type anthropicErrorResponse struct {
	Type  string          `json:"type"`
	Error *anthropicError `json:"error"`
}

type WriteErrorOpts struct {
	Protocol   corev1.Service_Spec_Config_LLM_Protocol
	HTTPStatus int
	Type       string
	Code       string
	Message    string
}

func WriteError(w http.ResponseWriter, o *WriteErrorOpts) {
	body, err := json.Marshal(getErrorResponse(o))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	hdr := w.Header()
	hdr.Set("Content-Type", "application/json")
	hdr.Set("Server", "octelium")
	hdr.Del("Content-Length")

	w.WriteHeader(o.HTTPStatus)
	w.Write(body)
}

func getErrorResponse(o *WriteErrorOpts) any {
	switch o.Protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return &anthropicErrorResponse{
			Type: "error",
			Error: &anthropicError{
				Type:    getAnthropicErrorType(o.HTTPStatus),
				Message: o.Message,
			},
		}
	default:
		return &openAIErrorResponse{
			Error: &openAIError{
				Message: o.Message,
				Type:    o.Type,
				Code:    o.Code,
			},
		}
	}
}

func getAnthropicErrorType(httpStatus int) string {
	switch httpStatus {
	case http.StatusUnauthorized:
		return "authentication_error"
	case http.StatusForbidden:
		return "permission_error"
	case http.StatusNotFound:
		return "not_found_error"
	case http.StatusMethodNotAllowed, http.StatusUnsupportedMediaType:
		return "invalid_request_error"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limit_error"
	default:
		return "invalid_request_error"
	}
}
