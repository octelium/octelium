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

package middlewares

import (
	"encoding/json"
	"net/http"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

func GetMCPRequestContext(mcpReq *httputils.MCPRequest,
	httpC *corev1.RequestContext_Request_HTTP) *corev1.RequestContext_Request_MCP {

	ret := &corev1.RequestContext_Request_MCP{
		Http:            httpC,
		ProtocolVersion: mcpReq.GetProtocolVersion(),
		Method:          mcpReq.GetMethod(),
		Name:            mcpReq.GetName(),
		RequestID:       mcpReq.GetRequestID(),
		IsNotification:  mcpReq.GetIsNotification(),
		Capabilities:    mcpReq.GetCapabilities(),
		SessionID:       mcpReq.GetSessionID(),
	}

	if client := mcpReq.GetClient(); client != nil {
		ret.Client = &corev1.RequestContext_Request_MCP_Client{
			Name:    client.GetName(),
			Version: client.GetVersion(),
			Title:   client.GetTitle(),
		}
	}

	return ret
}

func SetMCPRequestContext(reqCtx *RequestContext, req *http.Request) {
	mcpReq := httputils.ParseMCPRequest(req, reqCtx.Body)
	reqCtx.MCP = mcpReq

	reqCtx.BodyJSONMap = nil
	if len(reqCtx.Body) > 0 {
		bodyMap := make(map[string]any)
		if err := json.Unmarshal(reqCtx.Body, &bodyMap); err == nil {
			reqCtx.BodyJSONMap = bodyMap
		}
	}

	if reqCtx.DownstreamRequest == nil || reqCtx.DownstreamRequest.Request == nil {
		return
	}

	mcpC := reqCtx.DownstreamRequest.Request.GetMcp()
	if mcpC == nil {
		return
	}

	httpC := mcpC.Http
	if httpC != nil {
		httpC.Body = reqCtx.Body
		httpC.Size = int64(len(reqCtx.Body))
		if len(reqCtx.Body) > MaxReqCtxBodySize {
			httpC.Body = nil
		}
		httpC.BodyMap = nil
		if httpC.Body != nil && reqCtx.BodyJSONMap != nil {
			httpC.BodyMap, _ = pbutils.MapToStruct(reqCtx.BodyJSONMap)
		}
	}

	updated := GetMCPRequestContext(mcpReq, httpC)
	reqCtx.DownstreamRequest.Request.Type = &corev1.RequestContext_Request_Mcp{
		Mcp: updated,
	}

	if reqCtx.DownstreamInfo != nil && reqCtx.DownstreamInfo.Request != nil &&
		reqCtx.DownstreamInfo.Request != reqCtx.DownstreamRequest.Request {
		reqCtx.DownstreamInfo.Request.Type = &corev1.RequestContext_Request_Mcp{
			Mcp: updated,
		}
	}

	reqCtx.SetReqCtxMap()
}

const MaxReqCtxBodySize = 2 * 1024 * 1024
