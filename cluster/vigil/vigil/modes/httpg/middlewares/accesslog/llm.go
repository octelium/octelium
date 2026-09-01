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

package accesslog

import (
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
)

const defaultMaxLLMStreamEventBytes = 256 * 1024

const maxLLMStreamEventBytes = 4 * 1024 * 1024

const maxLLMResponseBodyBytes = 1024 * 1024

type llmObserver struct {
	mu sync.Mutex

	eventCount uint64

	responseID   string
	model        string
	finishReason string

	usage        httputils.LLMUsage
	firstTokenAt time.Time
}

func (o *llmObserver) onSSEEvent(event []byte) {
	data := httputils.GetSSEEventData(event)

	o.mu.Lock()
	defer o.mu.Unlock()

	o.eventCount++

	if len(data) == 0 || httputils.IsLLMStreamDone(data) {
		return
	}

	msg := httputils.ParseLLMResponse(data)
	if msg == nil {
		return
	}

	o.setResponse(msg)

	if msg.HasContentDelta && o.firstTokenAt.IsZero() {
		o.firstTokenAt = time.Now()
	}
}

func (o *llmObserver) onFinalBody(body []byte) {
	msg := httputils.ParseLLMResponse(body)
	if msg == nil {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	o.setResponse(msg)
}

func (o *llmObserver) setResponse(msg *httputils.LLMResponse) {
	if msg.ResponseID != "" {
		o.responseID = msg.ResponseID
	}
	if msg.Model != "" {
		o.model = msg.Model
	}
	if msg.FinishReason != "" {
		o.finishReason = msg.FinishReason
	}

	o.usage.Merge(msg.Usage)
}

func (m *middleware) serveLLM(w http.ResponseWriter, req *http.Request,
	reqCtx *middlewares.RequestContext) {

	obs := &llmObserver{}

	connID := vutils.GenerateLogID()

	crw := newResponseWriter(w, streamKindLLM)
	crw.maxSSEEvent = getMaxLLMStreamEventBytes(reqCtx)
	crw.maxBody = maxLLMResponseBodyBytes
	crw.onSSEEvent = obs.onSSEEvent

	crw.onFirstByte = func() {
		if reqCtx.DownstreamInfo == nil || !crw.isSSE {
			return
		}
		otelutils.EmitAccessLog(
			m.getLLMAccessLog(req, crw, reqCtx, obs, logPhaseStreamOpen, connID, 0))
	}

	m.next.ServeHTTP(crw, req)

	if !crw.isSSE {
		obs.onFinalBody(crw.body.Bytes())
		obs.setRequestContext(reqCtx, crw, logPhaseComplete)

		if reqCtx.DownstreamInfo == nil {
			return
		}
		otelutils.EmitAccessLog(
			m.getLLMAccessLog(req, crw, reqCtx, obs, logPhaseComplete, "", 0))
		return
	}

	obs.setRequestContext(reqCtx, crw, logPhaseStreamClose)

	if reqCtx.DownstreamInfo == nil {
		return
	}

	otelutils.EmitAccessLog(
		m.getLLMAccessLog(req, crw, reqCtx, obs, logPhaseStreamClose, connID, 1))
}

func (o *llmObserver) setRequestContext(reqCtx *middlewares.RequestContext,
	crw *responseWriter, phase logPhase) {

	o.mu.Lock()
	defer o.mu.Unlock()

	usage := getLLMUsage(reqCtx, crw, o, phase)

	ret := &middlewares.LLMResponseInfo{
		Model:        o.model,
		FinishReason: o.finishReason,
		EventCount:   o.eventCount,
		UsageSource:  usage.GetSource(),
		Usage: httputils.LLMUsage{
			InputTokens:              usage.GetInputTokens(),
			OutputTokens:             usage.GetOutputTokens(),
			TotalTokens:              usage.GetTotalTokens(),
			CacheReadInputTokens:     usage.GetCacheReadInputTokens(),
			CacheCreationInputTokens: usage.GetCacheCreationInputTokens(),
			ReasoningTokens:          usage.GetReasoningTokens(),
		},
	}

	if !o.firstTokenAt.IsZero() {
		if d := o.firstTokenAt.Sub(reqCtx.CreatedAt); d > 0 {
			ret.TimeToFirstToken = d
		}
	}

	reqCtx.LLMResponse = ret
}

func (m *middleware) getLLMAccessLog(
	req *http.Request,
	crw *responseWriter,
	reqCtx *middlewares.RequestContext,
	obs *llmObserver,
	phase logPhase,
	connID string,
	eventSeq int64) *corev1.AccessLog {

	logE := m.getAccessLog(req, crw, reqCtx, phase, connID, eventSeq)
	if logE == nil {
		return nil
	}

	llmC := logE.Entry.Info.GetLlm()
	if llmC == nil {
		return logE
	}

	llmC.Type = func() corev1.AccessLog_Entry_Info_LLM_Type {
		switch phase {
		case logPhaseStreamOpen:
			return corev1.AccessLog_Entry_Info_LLM_STREAM_START
		case logPhaseStreamClose:
			return corev1.AccessLog_Entry_Info_LLM_STREAM_END
		default:
			return corev1.AccessLog_Entry_Info_LLM_COMPLETE
		}
	}()

	llmC.Plugins = reqCtx.LLMPluginRecords

	if phase == logPhaseStreamOpen {
		return logE
	}

	obs.mu.Lock()
	defer obs.mu.Unlock()

	llmC.EventCount = obs.eventCount
	llmC.ResponseID = obs.responseID
	llmC.Model = obs.model
	llmC.FinishReason = obs.finishReason
	llmC.Usage = getLLMUsage(reqCtx, crw, obs, phase)

	if !obs.firstTokenAt.IsZero() {
		if ms := obs.firstTokenAt.Sub(reqCtx.CreatedAt).Milliseconds(); ms >= 0 &&
			ms <= math.MaxUint32 {
			llmC.TimeToFirstToken = &metav1.Duration{
				Type: &metav1.Duration_Milliseconds{
					Milliseconds: uint32(ms),
				},
			}
		}
	}

	return logE
}

func getLLMUsage(reqCtx *middlewares.RequestContext, crw *responseWriter,
	obs *llmObserver, phase logPhase) *corev1.AccessLog_Entry_Info_LLM_Usage {

	if !obs.usage.IsSet {
		if crw.statusCode >= http.StatusBadRequest ||
			reqCtx.LLM.GetEstimateQuality() ==
				corev1.RequestContext_Request_LLM_UNAVAILABLE {
			return &corev1.AccessLog_Entry_Info_LLM_Usage{
				Source: corev1.AccessLog_Entry_Info_LLM_Usage_SOURCE_UNSET,
			}
		}

		return &corev1.AccessLog_Entry_Info_LLM_Usage{
			Source:      corev1.AccessLog_Entry_Info_LLM_Usage_ESTIMATED,
			InputTokens: reqCtx.LLM.GetEstimatedInputTokens(),
			TotalTokens: reqCtx.LLM.GetEstimatedInputTokens(),
		}
	}

	source := corev1.AccessLog_Entry_Info_LLM_Usage_PROVIDER
	if phase == logPhaseStreamClose && (obs.finishReason == "" || crw.sseTruncated) {
		source = corev1.AccessLog_Entry_Info_LLM_Usage_PARTIAL
	}

	return &corev1.AccessLog_Entry_Info_LLM_Usage{
		Source:                   source,
		InputTokens:              obs.usage.InputTokens,
		OutputTokens:             obs.usage.OutputTokens,
		TotalTokens:              obs.usage.TotalTokens,
		CacheReadInputTokens:     obs.usage.CacheReadInputTokens,
		CacheCreationInputTokens: obs.usage.CacheCreationInputTokens,
		ReasoningTokens:          obs.usage.ReasoningTokens,
	}
}

func getMaxLLMStreamEventBytes(reqCtx *middlewares.RequestContext) int {
	cfg := reqCtx.ServiceConfig
	if cfg == nil {
		return defaultMaxLLMStreamEventBytes
	}

	configured := cfg.GetLlm().GetLimits().GetMaxStreamEventBytes()
	if configured == 0 || int(configured) > maxLLMStreamEventBytes {
		return defaultMaxLLMStreamEventBytes
	}

	return int(configured)
}

func setLLMAccessLogInfo(logE *corev1.AccessLog,
	httpC *corev1.AccessLog_Entry_Info_HTTP, reqCtx *middlewares.RequestContext) {

	llmC := &corev1.AccessLog_Entry_Info_LLM{
		Http: httpC,
	}
	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Llm{
		Llm: llmC,
	}

	llmI := reqCtx.DownstreamInfo.Request.GetLlm()
	if llmI == nil {
		return
	}

	llmC.Protocol = llmI.Protocol
	llmC.Operation = corev1.AccessLog_Entry_Info_LLM_Operation(llmI.Operation)
	llmC.RequestedModel = llmI.Model
	llmC.Stream = llmI.Stream
	llmC.EstimatedInputTokens = llmI.EstimatedInputTokens
}
