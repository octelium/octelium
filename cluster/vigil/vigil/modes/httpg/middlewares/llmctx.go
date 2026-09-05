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
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
)

func GetLLMRequestContext(llmReq *httputils.LLMRequest,
	httpC *corev1.RequestContext_Request_HTTP) *corev1.RequestContext_Request_LLM {

	return &corev1.RequestContext_Request_LLM{
		Http:                 httpC,
		Protocol:             llmReq.GetProtocol(),
		Operation:            llmReq.GetOperation(),
		Route:                llmReq.GetRoute(),
		Model:                llmReq.GetModel(),
		Stream:               llmReq.GetStream(),
		EstimatedInputTokens: llmReq.GetEstimatedInputTokens(),
		EstimateQuality:      llmReq.GetEstimateQuality(),
		MaxOutputTokens:      llmReq.GetMaxOutputTokens(),
		HasTools:             llmReq.GetToolCount() > 0,
		ToolCount:            llmReq.GetToolCount(),
		ToolNames:            llmReq.GetToolNames(),
		InputItemCount:       llmReq.GetInputItemCount(),
		HasImageInput:        llmReq.GetHasImageInput(),
		HasAudioInput:        llmReq.GetHasAudioInput(),
	}
}

func SetLLMRequestContext(reqCtx *RequestContext, req *http.Request) {
	llmReq := httputils.ParseLLMRequest(req,
		ucorev1.ToServiceConfig(reqCtx.ServiceConfig).GetLLMProtocol(), reqCtx.Body)
	reqCtx.LLM = llmReq

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

	llmC := reqCtx.DownstreamRequest.Request.GetLlm()
	if llmC == nil {
		return
	}

	httpC := llmC.Http
	if httpC != nil {
		httpC.Method = req.Method
		httpC.Path = req.URL.Path
		httpC.Uri = req.URL.RequestURI()
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

	updated := GetLLMRequestContext(llmReq, httpC)
	reqCtx.DownstreamRequest.Request.Type = &corev1.RequestContext_Request_Llm{
		Llm: updated,
	}

	if reqCtx.DownstreamInfo != nil && reqCtx.DownstreamInfo.Request != nil &&
		reqCtx.DownstreamInfo.Request != reqCtx.DownstreamRequest.Request {
		reqCtx.DownstreamInfo.Request.Type = &corev1.RequestContext_Request_Llm{
			Llm: updated,
		}
	}

	reqCtx.SetReqCtxMap()
}
