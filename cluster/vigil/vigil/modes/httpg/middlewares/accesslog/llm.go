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
	"slices"
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

const maxLLMCalledToolNames = 64

type llmObserver struct {
	mu sync.Mutex

	eventCount uint64

	responseID   string
	model        string
	finishReason string

	toolNames map[string]struct{}

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

func (o *llmObserver) onEventMessage(data []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.eventCount++

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

	for _, name := range msg.ToolNames {
		if len(o.toolNames) >= maxLLMCalledToolNames {
			break
		}
		if o.toolNames == nil {
			o.toolNames = make(map[string]struct{})
		}
		o.toolNames[name] = struct{}{}
	}

	o.usage.Merge(msg.Usage)
}

func (o *llmObserver) calledToolNames() []string {
	if len(o.toolNames) == 0 {
		return nil
	}

	ret := make([]string, 0, len(o.toolNames))
	for name := range o.toolNames {
		ret = append(ret, name)
	}
	slices.Sort(ret)

	return ret
}

func (m *middleware) serveLLM(w http.ResponseWriter, req *http.Request,
	reqCtx *middlewares.RequestContext) {

	obs := &llmObserver{}

	connID := vutils.GenerateLogID()

	crw := newResponseWriter(w, streamKindLLM)
	crw.maxSSEEvent = getMaxLLMStreamEventBytes(reqCtx)
	crw.maxBody = maxLLMResponseBodyBytes
	crw.onSSEEvent = obs.onSSEEvent
	crw.onEventMessage = obs.onEventMessage

	crw.onFirstByte = func() {
		if reqCtx.DownstreamInfo == nil || !crw.isStreaming() {
			return
		}
		otelutils.EmitAccessLog(
			m.getLLMAccessLog(req, crw, reqCtx, obs, logPhaseStreamOpen, connID, 0))
	}

	m.next.ServeHTTP(crw, req)

	if !crw.isStreaming() {
		obs.onFinalBody(crw.body.Bytes())
		obs.setRequestContext(reqCtx, crw, logPhaseComplete)
		reqCtx.RunOnResponse()

		if reqCtx.DownstreamInfo == nil {
			return
		}
		otelutils.EmitAccessLog(
			m.getLLMAccessLog(req, crw, reqCtx, obs, logPhaseComplete, "", 0))
		return
	}

	obs.setRequestContext(reqCtx, crw, logPhaseStreamClose)
	reqCtx.RunOnResponse()

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

	if phase == logPhaseStreamOpen {
		return logE
	}

	obs.mu.Lock()
	defer obs.mu.Unlock()

	llmC.EventCount = obs.eventCount
	llmC.ResponseID = obs.responseID
	llmC.FinishReason = obs.finishReason
	llmC.Usage = getLLMUsage(reqCtx, crw, obs, phase)
	llmC.Source = getLLMSource(reqCtx, crw)

	if llmC.Model == nil {
		llmC.Model = &corev1.AccessLog_Entry_Info_LLM_Model{}
	}
	llmC.Model.Reported = obs.model

	if names := obs.calledToolNames(); len(names) > 0 {
		if llmC.Tools == nil {
			llmC.Tools = &corev1.AccessLog_Entry_Info_LLM_Tools{}
		}
		llmC.Tools.CalledNames = names
	}

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

func getLLMSource(reqCtx *middlewares.RequestContext,
	crw *responseWriter) corev1.AccessLog_Entry_Info_LLM_Source {

	switch {
	case reqCtx.LLMSemanticCache.IsHit():
		return corev1.AccessLog_Entry_Info_LLM_SEMANTIC_CACHE
	case reqCtx.LLMResponseDenied:
		return corev1.AccessLog_Entry_Info_LLM_OCTELIUM
	case reqCtx.IsUpstreamResponse:
		return corev1.AccessLog_Entry_Info_LLM_UPSTREAM
	case crw.statusCode != 0:
		return corev1.AccessLog_Entry_Info_LLM_OCTELIUM
	default:
		return corev1.AccessLog_Entry_Info_LLM_SOURCE_UNSET
	}
}

func getLLMUsage(reqCtx *middlewares.RequestContext, crw *responseWriter,
	obs *llmObserver, phase logPhase) *corev1.AccessLog_Entry_Info_LLM_Usage {

	if reqCtx.LLMSemanticCache.IsHit() {
		return &corev1.AccessLog_Entry_Info_LLM_Usage{
			Source: corev1.AccessLog_Entry_Info_LLM_Usage_CACHED,
		}
	}

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
	llmC.Operation = getLLMOperation(llmI.Operation)
	llmC.Stream = llmI.Stream
	llmC.EstimatedInputTokens = llmI.EstimatedInputTokens
	llmC.EstimateQuality = llmI.EstimateQuality

	llmC.Model = &corev1.AccessLog_Entry_Info_LLM_Model{
		Requested: llmI.Model,
		Effective: llmI.Model,
	}
	if cur := reqCtx.LLMModel; cur != nil {
		llmC.Model.Effective = cur.Effective
		llmC.Model.Source = cur.Source
		llmC.Model.Plugin = cur.Plugin
	}

	if cur := reqCtx.LLMTools; cur != nil {
		llmC.Tools = &corev1.AccessLog_Entry_Info_LLM_Tools{
			Count:        cur.Count,
			Names:        cur.Names,
			RemovedCount: cur.RemovedCount,
		}
	} else if llmI.ToolCount > 0 {
		llmC.Tools = &corev1.AccessLog_Entry_Info_LLM_Tools{
			Count: llmI.ToolCount,
			Names: llmI.ToolNames,
		}
	}

	if cur := reqCtx.LLMReasoning; cur != nil {
		llmC.Reasoning = &corev1.AccessLog_Entry_Info_LLM_Reasoning{
			IsDisabled:  cur.IsDisabled,
			Effort:      cur.Effort,
			TokenBudget: cur.TokenBudget,
		}
	}

	if cur := reqCtx.LLMGuardrail; cur != nil {
		llmC.Guardrail = &corev1.AccessLog_Entry_Info_LLM_Guardrail{
			Result: cur.Result,
			Leg:    cur.Leg,
			Plugin: cur.Plugin,
		}
	}
}

func getLLMOperation(
	arg corev1.RequestContext_Request_LLM_Operation) corev1.AccessLog_Entry_Info_LLM_Operation {

	switch arg {
	case corev1.RequestContext_Request_LLM_CHAT_COMPLETIONS,
		corev1.RequestContext_Request_LLM_RESPONSES,
		corev1.RequestContext_Request_LLM_COMPLETIONS,
		corev1.RequestContext_Request_LLM_MESSAGES,
		corev1.RequestContext_Request_LLM_GENERATE_CONTENT,
		corev1.RequestContext_Request_LLM_CONVERSE:
		return corev1.AccessLog_Entry_Info_LLM_GENERATE
	case corev1.RequestContext_Request_LLM_EMBEDDINGS,
		corev1.RequestContext_Request_LLM_EMBED_CONTENT:
		return corev1.AccessLog_Entry_Info_LLM_EMBED
	case corev1.RequestContext_Request_LLM_MODERATIONS:
		return corev1.AccessLog_Entry_Info_LLM_MODERATE
	case corev1.RequestContext_Request_LLM_COUNT_TOKENS:
		return corev1.AccessLog_Entry_Info_LLM_COUNT_TOKENS
	case corev1.RequestContext_Request_LLM_MODELS_LIST:
		return corev1.AccessLog_Entry_Info_LLM_LIST_MODELS
	case corev1.RequestContext_Request_LLM_MODELS_GET:
		return corev1.AccessLog_Entry_Info_LLM_GET_MODEL
	case corev1.RequestContext_Request_LLM_INVOKE_MODEL:
		return corev1.AccessLog_Entry_Info_LLM_RAW_INFERENCE
	default:
		return corev1.AccessLog_Entry_Info_LLM_OPERATION_UNSET
	}
}
