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

	ErrCodeUnauthenticated  = -32001
	ErrCodeUnauthorized     = -32002
	ErrCodeOriginRejected   = -32003
	ErrCodeUnsupportedVer   = -32004
	ErrCodeTransport        = -32006
	ErrCodeMutationRejected = -32007
)

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type jsonRPCErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   *jsonRPCError   `json:"error"`
}

type WriteErrorOpts struct {
	HTTPStatus int
	Code       int
	Message    string
	RequestID  string
}

func WriteError(w http.ResponseWriter, o *WriteErrorOpts) {
	resp := &jsonRPCErrorResponse{
		JSONRPC: "2.0",
		ID:      getJSONRPCID(o.RequestID),
		Error: &jsonRPCError{
			Code:    o.Code,
			Message: o.Message,
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

func getJSONRPCID(arg string) json.RawMessage {
	if arg == "" {
		return json.RawMessage("null")
	}

	if isJSONNumber(arg) {
		return json.RawMessage(arg)
	}

	ret, err := json.Marshal(arg)
	if err != nil {
		return json.RawMessage("null")
	}
	return ret
}

func isJSONNumber(arg string) bool {
	if arg == "" {
		return false
	}

	var v json.Number
	if err := json.Unmarshal([]byte(arg), &v); err != nil {
		return false
	}
	return true
}
