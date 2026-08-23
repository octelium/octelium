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
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
)

type guard struct {
	next   http.Handler
	domain string
}

func NewGuard(ctx context.Context, next http.Handler, domain string) (http.Handler, error) {
	return &guard{
		next:   next,
		domain: domain,
	}, nil
}

func (m *guard) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	if !ucorev1.ToService(reqCtx.Service).IsMCP() {
		m.next.ServeHTTP(w, req)
		return
	}

	if m.serveWellKnown(w, req, reqCtx) {
		return
	}

	if o := m.check(req, reqCtx); o != nil {
		WriteError(w, o)
		return
	}

	m.next.ServeHTTP(w, req)
}

func (m *guard) check(req *http.Request, reqCtx *middlewares.RequestContext) *WriteErrorOpts {
	cfg := getMCPConfig(reqCtx.ServiceConfig)
	mcpReq := reqCtx.MCP
	reqID := mcpReq.GetRequestIDRaw()

	if o := m.checkOrigin(req, cfg, reqCtx.Service); o != nil {
		return o
	}

	if req.Method != http.MethodPost {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusMethodNotAllowed,
			Code:       ErrCodeTransport,
			Message:    fmt.Sprintf("Octelium: the MCP endpoint does not accept %s", req.Method),
			RequestID:  reqID,
		}
	}

	if o := m.checkEndpoint(req, cfg, reqID); o != nil {
		return o
	}

	if o := m.checkContentType(req, reqID); o != nil {
		return o
	}

	if o := m.checkSingletonHeaders(req, reqID); o != nil {
		return o
	}

	if mcpReq == nil {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeParse,
			Message:    "Octelium: could not parse the MCP request body",
		}
	}

	if mcpReq.IsBatch {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeInvalidRequest,
			Message:    "Octelium: JSON-RPC batch requests are not supported",
		}
	}

	if o := m.checkEnvelope(mcpReq, reqID); o != nil {
		return o
	}

	if o := m.checkProtocolVersion(mcpReq, cfg, reqID); o != nil {
		return o
	}

	if o := m.checkMirroredHeaders(mcpReq, reqID); o != nil {
		return o
	}

	if cfg.GetProtocol().GetRejectUnknownMethods() &&
		!httputils.IsMCPMethodKnown(mcpReq.Method) {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusNotFound,
			Code:       ErrCodeMethodNotFound,
			Message:    fmt.Sprintf("Octelium: unknown MCP method: %s", mcpReq.Method),
			RequestID:  reqID,
		}
	}

	return nil
}

func (m *guard) checkEnvelope(mcpReq *httputils.MCPRequest, reqID json.RawMessage) *WriteErrorOpts {
	if !mcpReq.IsJSONRPC {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeParse,
			Message:    "Octelium: the request body is not a JSON-RPC object",
		}
	}

	if mcpReq.JSONRPCVersion != "2.0" {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeInvalidRequest,
			Message:    `Octelium: the "jsonrpc" member must be "2.0"`,
			RequestID:  reqID,
		}
	}

	if mcpReq.HasInvalidRequestID {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeInvalidRequest,
			Message:    `Octelium: the "id" member must be either a string or a number`,
		}
	}

	switch {
	case mcpReq.Method == "":
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeInvalidRequest,
			Message:    `Octelium: the "method" member must be a non-empty string`,
			RequestID:  reqID,
		}
	case len(mcpReq.Method) > maxMethodLen:
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeInvalidRequest,
			Message:    `Octelium: the "method" member is too long`,
			RequestID:  reqID,
		}
	}

	if len(mcpReq.Name) > maxNameLen {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeInvalidRequest,
			Message:    "Octelium: the MCP request target is too long",
			RequestID:  reqID,
		}
	}

	return nil
}

func (m *guard) checkProtocolVersion(mcpReq *httputils.MCPRequest,
	cfg *corev1.Service_Spec_Config_MCP, reqID json.RawMessage) *WriteErrorOpts {

	if mcpReq.BodyProtocolVersion != "" && mcpReq.HeaderProtocolVersion != "" &&
		mcpReq.BodyProtocolVersion != mcpReq.HeaderProtocolVersion {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeHeaderMismatch,
			Message: fmt.Sprintf(
				"Octelium: the %s header does not match the protocol version of the request body",
				httputils.MCPHeaderProtocolVersion),
			RequestID: reqID,
		}
	}

	versions := cfg.GetProtocol().GetVersions()

	if mcpReq.ProtocolVersion == "" {
		if cfg.GetProtocol().GetRequireVersion() {
			return &WriteErrorOpts{
				HTTPStatus: http.StatusBadRequest,
				Code:       ErrCodeHeaderMismatch,
				Message: fmt.Sprintf(
					"Octelium: the MCP request declares no protocol version in either the %s header or the request body",
					httputils.MCPHeaderProtocolVersion),
				RequestID: reqID,
			}
		}
		return nil
	}

	if len(versions) == 0 || slices.Contains(versions, mcpReq.ProtocolVersion) {
		return nil
	}

	return &WriteErrorOpts{
		HTTPStatus: http.StatusBadRequest,
		Code:       ErrCodeUnsupportedVer,
		Message:    "Octelium: unsupported MCP protocol version",
		RequestID:  reqID,
		Data: &unsupportedVersionData{
			Supported: versions,
			Requested: mcpReq.ProtocolVersion,
		},
	}
}

type unsupportedVersionData struct {
	Supported []string `json:"supported"`
	Requested string   `json:"requested"`
}

func (m *guard) checkMirroredHeaders(mcpReq *httputils.MCPRequest, reqID json.RawMessage) *WriteErrorOpts {

	if mcpReq.HeaderMethod != "" && mcpReq.HeaderMethod != mcpReq.Method {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeHeaderMismatch,
			Message: fmt.Sprintf(
				"Octelium: the %s header does not match the method of the request body",
				httputils.MCPHeaderMethod),
			RequestID: reqID,
		}
	}

	if mcpReq.HasInvalidHeaderName {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeHeaderMismatch,
			Message: fmt.Sprintf(
				"Octelium: the %s header value is not a valid base64 sentinel encoded value",
				httputils.MCPHeaderName),
			RequestID: reqID,
		}
	}

	if mcpReq.HasHeaderName && mcpReq.HeaderName != mcpReq.Name {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusBadRequest,
			Code:       ErrCodeHeaderMismatch,
			Message: fmt.Sprintf(
				"Octelium: the %s header does not match the target of the request body",
				httputils.MCPHeaderName),
			RequestID: reqID,
		}
	}

	return nil
}

func (m *guard) checkEndpoint(req *http.Request,
	cfg *corev1.Service_Spec_Config_MCP, reqID json.RawMessage) *WriteErrorOpts {

	endpoint := cfg.GetEndpoint()
	if endpoint == "" || req.URL.Path == endpoint {
		return nil
	}

	return &WriteErrorOpts{
		HTTPStatus: http.StatusNotFound,
		Code:       ErrCodeTransport,
		Message:    "Octelium: not the MCP endpoint path",
		RequestID:  reqID,
	}
}

var mcpSingletonHeaders = []string{
	httputils.MCPHeaderProtocolVersion,
	httputils.MCPHeaderMethod,
	httputils.MCPHeaderName,
	httputils.MCPHeaderSessionID,
}

func (m *guard) checkSingletonHeaders(req *http.Request, reqID json.RawMessage) *WriteErrorOpts {
	for _, hdr := range mcpSingletonHeaders {
		if len(req.Header.Values(hdr)) > 1 {
			return &WriteErrorOpts{
				HTTPStatus: http.StatusBadRequest,
				Code:       ErrCodeHeaderMismatch,
				Message: fmt.Sprintf(
					"Octelium: the %s request header must not be set more than once", hdr),
				RequestID: reqID,
			}
		}
	}

	return nil
}

func (m *guard) checkOrigin(req *http.Request,
	cfg *corev1.Service_Spec_Config_MCP, svc *corev1.Service) *WriteErrorOpts {

	if cfg.GetDisableOriginCheck() {
		return nil
	}

	if len(req.Header.Values("Origin")) == 0 {
		return nil
	}

	if httputils.GetCORSOrigin(req, cfg.GetCors(), svc, m.domain) != "" {
		req.Header.Del("Origin")
		return nil
	}

	return &WriteErrorOpts{
		HTTPStatus: http.StatusForbidden,
		Code:       ErrCodeOriginRejected,
		Message:    "Octelium: the Origin request header is not allowed",
	}
}

func (m *guard) checkContentType(req *http.Request, reqID json.RawMessage) *WriteErrorOpts {
	ct := req.Header.Get("Content-Type")
	if ct == "" {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusUnsupportedMediaType,
			Code:       ErrCodeTransport,
			Message:    "Octelium: the MCP endpoint requires a JSON Content-Type",
			RequestID:  reqID,
		}
	}

	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return &WriteErrorOpts{
			HTTPStatus: http.StatusUnsupportedMediaType,
			Code:       ErrCodeTransport,
			Message:    "Octelium: the MCP endpoint requires a JSON Content-Type",
			RequestID:  reqID,
		}
	}

	return nil
}

const (
	maxMethodLen = 128
	maxNameLen   = 2048
)

func getMCPConfig(cfg *corev1.Service_Spec_Config) *corev1.Service_Spec_Config_MCP {
	if cfg == nil {
		return nil
	}
	return cfg.GetMcp()
}
