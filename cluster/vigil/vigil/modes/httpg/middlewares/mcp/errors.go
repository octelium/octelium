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
	"encoding/json"
	"net/http"
)

const (
	ErrCodeParse          = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601

	ErrCodeHeaderMismatch = -32020
	ErrCodeUnsupportedVer = -32022

	ErrCodeUnauthenticated = -40001
	ErrCodeUnauthorized    = -40002
	ErrCodeTransport       = -40003
)

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type jsonRPCErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Error   *jsonRPCError   `json:"error"`
}

type WriteErrorOpts struct {
	HTTPStatus int
	Code       int
	Message    string
	RequestID  json.RawMessage
	Data       any
}

func WriteError(w http.ResponseWriter, o *WriteErrorOpts) {
	resp := &jsonRPCErrorResponse{
		JSONRPC: "2.0",
		ID:      o.RequestID,
		Error: &jsonRPCError{
			Code:    o.Code,
			Message: o.Message,
			Data:    o.Data,
		},
	}

	body, err := json.Marshal(resp)
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
