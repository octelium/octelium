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

	toolNames            map[string]struct{}
	toolCallCount        uint32
	isToolNamesTruncated bool

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

	o.toolCallCount += msg.ToolCallCount
	if msg.IsToolNamesTruncated {
		o.isToolNamesTruncated = true
	}

	for _, name := range msg.ToolNames {
		if o.toolNames == nil {
			o.toolNames = make(map[string]struct{})
		}
		if _, ok := o.toolNames[name]; ok {
			continue
		}
		if len(o.toolNames) >= maxLLMCalledToolNames {
			o.isToolNamesTruncated = true
			break
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

	ret := &middlewares.LLMResponseInfo{
		Model:        o.model,
		FinishReason: o.finishReason,
		EventCount:   o.eventCount,
		UsageSource:  getLLMUsageSource(reqCtx, crw, o, phase),
		Usage:        o.usage,
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
	llmC.RawFinishReason = obs.finishReason
	llmC.FinishReason = httputils.GetLLMFinishReason(obs.finishReason)
	llmC.Usage = getLLMUsage(obs, getLLMUsageSource(reqCtx, crw, obs, phase))
	llmC.Source = getLLMSource(reqCtx, crw)
	llmC.IsUpstreamInvoked = reqCtx.IsUpstreamResponse

	if llmC.Model == nil {
		llmC.Model = &corev1.AccessLog_Entry_Info_LLM_Model{}
	}
	llmC.Model.Reported = obs.model

	names := obs.calledToolNames()
	if len(names) > 0 || obs.toolCallCount > 0 {
		if llmC.Tools == nil {
			llmC.Tools = &corev1.AccessLog_Entry_Info_LLM_Tools{}
		}
		llmC.Tools.CalledNames = names
		llmC.Tools.CallCount = obs.toolCallCount
		llmC.Tools.IsCalledNamesTruncated = obs.isToolNamesTruncated
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

func getLLMUsageSource(reqCtx *middlewares.RequestContext, crw *responseWriter,
	obs *llmObserver, phase logPhase) middlewares.LLMUsageSource {

	switch {
	case reqCtx.LLMSemanticCache.IsHit():
		return middlewares.LLMUsageSourceCached
	case !obs.usage.IsSet:
		if crw.statusCode >= http.StatusBadRequest ||
			reqCtx.LLM.GetEstimateQuality() ==
				corev1.RequestContext_Request_LLM_UNAVAILABLE {
			return middlewares.LLMUsageSourceUnset
		}
		return middlewares.LLMUsageSourceEstimated
	case phase == logPhaseStreamClose &&
		(obs.finishReason == "" || crw.sseTruncated):
		return middlewares.LLMUsageSourcePartial
	default:
		return middlewares.LLMUsageSourceProvider
	}
}

func getLLMUsage(obs *llmObserver,
	source middlewares.LLMUsageSource) *corev1.AccessLog_Entry_Info_LLM_Usage {

	var state corev1.AccessLog_Entry_Info_LLM_Usage_State
	switch source {
	case middlewares.LLMUsageSourceProvider:
		state = corev1.AccessLog_Entry_Info_LLM_Usage_COMPLETE
	case middlewares.LLMUsageSourcePartial:
		state = corev1.AccessLog_Entry_Info_LLM_Usage_PARTIAL
	default:
		return nil
	}

	return &corev1.AccessLog_Entry_Info_LLM_Usage{
		State:                 state,
		InputTokens:           obs.usage.InputTokens,
		OutputTokens:          obs.usage.OutputTokens,
		TotalTokens:           obs.usage.TotalTokens,
		CacheReadInputTokens:  obs.usage.CacheReadInputTokens,
		CacheWriteInputTokens: obs.usage.CacheCreationInputTokens,
		ReasoningOutputTokens: obs.usage.ReasoningTokens,
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
	llmC.Operation = llmI.Operation
	llmC.Stream = llmI.Stream
	llmC.EstimatedInputTokens = llmI.EstimatedInputTokens
	llmC.EstimateQuality = llmI.EstimateQuality

	llmC.Route = llmI.Route
	llmC.MaxOutputTokens = llmI.MaxOutputTokens
	llmC.InputItemCount = llmI.InputItemCount
	llmC.HasImageInput = llmI.HasImageInput
	llmC.HasAudioInput = llmI.HasAudioInput

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
			RemovedNames: cur.RemovedNames,
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

	for _, cur := range reqCtx.LLMGuardrails {
		llmC.Guardrails = append(llmC.Guardrails,
			&corev1.AccessLog_Entry_Info_LLM_Guardrail{
				Result: cur.Result,
				Leg:    cur.Leg,
				Plugin: cur.Plugin,
			})
	}

	if cur := reqCtx.LLMTokenRateLimit; cur != nil {
		llmC.TokenRateLimit = &corev1.AccessLog_Entry_Info_LLM_TokenRateLimit{
			Result: cur.Result,
			Plugin: cur.Plugin,
			Scope:  cur.Scope,
		}
	}

	if cur := reqCtx.LLMSemanticCache; cur != nil {
		llmC.SemanticCache = &corev1.AccessLog_Entry_Info_LLM_SemanticCache{
			Result:     getLLMSemanticCacheResult(cur.Result),
			Similarity: cur.Similarity,
			IsStored:   cur.IsStored,
			Plugin:     cur.Plugin,
		}
	}

	if cur := reqCtx.LLMSemanticRouter; cur != nil {
		llmC.SemanticRouter = &corev1.AccessLog_Entry_Info_LLM_SemanticRouter{
			Result:     getLLMSemanticRouterResult(cur.Result),
			Route:      cur.Route,
			Similarity: cur.Similarity,
			Model:      cur.Model,
			Plugin:     cur.Plugin,
		}
	}
}

func getLLMSemanticCacheResult(
	arg middlewares.LLMSemanticCacheResult) corev1.AccessLog_Entry_Info_LLM_SemanticCache_Result {

	switch arg {
	case middlewares.LLMSemanticCacheExactHit:
		return corev1.AccessLog_Entry_Info_LLM_SemanticCache_EXACT_HIT
	case middlewares.LLMSemanticCacheSemanticHit:
		return corev1.AccessLog_Entry_Info_LLM_SemanticCache_SEMANTIC_HIT
	case middlewares.LLMSemanticCacheMiss:
		return corev1.AccessLog_Entry_Info_LLM_SemanticCache_MISS
	case middlewares.LLMSemanticCacheBypass:
		return corev1.AccessLog_Entry_Info_LLM_SemanticCache_BYPASS
	case middlewares.LLMSemanticCacheError:
		return corev1.AccessLog_Entry_Info_LLM_SemanticCache_ERROR
	default:
		return corev1.AccessLog_Entry_Info_LLM_SemanticCache_RESULT_UNSET
	}
}

func getLLMSemanticRouterResult(
	arg middlewares.LLMSemanticRouterResult) corev1.AccessLog_Entry_Info_LLM_SemanticRouter_Result {

	switch arg {
	case middlewares.LLMSemanticRouterMatch:
		return corev1.AccessLog_Entry_Info_LLM_SemanticRouter_MATCH
	case middlewares.LLMSemanticRouterNoMatch:
		return corev1.AccessLog_Entry_Info_LLM_SemanticRouter_NO_MATCH
	case middlewares.LLMSemanticRouterBypass:
		return corev1.AccessLog_Entry_Info_LLM_SemanticRouter_BYPASS
	case middlewares.LLMSemanticRouterError:
		return corev1.AccessLog_Entry_Info_LLM_SemanticRouter_ERROR
	default:
		return corev1.AccessLog_Entry_Info_LLM_SemanticRouter_RESULT_UNSET
	}
}
