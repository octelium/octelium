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
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonguardrail"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"go.uber.org/zap"
)

const ErrCodeTranslation = "octelium_translation"

const defaultTransMaxOutputTokens = 4096

var transProtocolHeaders = map[corev1.Service_Spec_Config_LLM_Protocol][]string{
	corev1.Service_Spec_Config_LLM_OPENAI: {
		"Openai-Organization",
		"Openai-Project",
		"Openai-Beta",
	},
	corev1.Service_Spec_Config_LLM_ANTHROPIC: {
		anthropicVersionHeader,
		"Anthropic-Beta",
		"Anthropic-Dangerous-Direct-Browser-Access",
	},
	corev1.Service_Spec_Config_LLM_GEMINI: {
		geminiAPIKeyHeader,
		"X-Goog-User-Project",
		"X-Goog-Api-Client",
	},
	corev1.Service_Spec_Config_LLM_BEDROCK: {
		"X-Amzn-Bedrock-Accept",
		"X-Amzn-Bedrock-Save",
	},
}

type translation struct {
	next         http.Handler
	continuation *transContinuation
}

func NewTranslation(ctx context.Context, next http.Handler,
	octeliumC octeliumc.ClientInterface, svcUID string) (http.Handler, error) {
	return &translation{
		next:         next,
		continuation: newTransContinuation(octeliumC, svcUID),
	}, nil
}

type transPlan struct {
	from transCodec
	to   transCodec

	fromProtocol corev1.Service_Spec_Config_LLM_Protocol
	toProtocol   corev1.Service_Spec_Config_LLM_Protocol

	llm *corev1.Service_Spec_Config_LLM

	model  string
	stream bool

	streamUsage bool
}

func (m *translation) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	if !ucorev1.ToService(reqCtx.Service).IsLLM() {
		m.next.ServeHTTP(w, req)
		return
	}

	svcCfg := ucorev1.ToServiceConfig(reqCtx.ServiceConfig)
	if !svcCfg.IsLLMTranslated() {
		m.next.ServeHTTP(w, req)
		return
	}

	plan, err := m.getPlan(reqCtx)
	if err != nil {
		m.writeError(w, reqCtx, err)
		return
	}

	if err := m.translateRequest(ctx, req, reqCtx, plan); err != nil {
		zap.L().Debug("Could not translate the LLM request", zap.Error(err))
		m.writeError(w, reqCtx, err)
		return
	}

	reqCtx.LLMTranslation = &middlewares.LLMTranslationInfo{
		UpstreamProtocol: plan.toProtocol,
		UpstreamRoute:    plan.to.route(),
	}

	rw := newTransResponseWriter(ctx, w, reqCtx, plan)
	rw.continuation = m.continuation

	m.next.ServeHTTP(rw, req)
	rw.finish()
}

func (m *translation) getPlan(reqCtx *middlewares.RequestContext) (*transPlan, error) {
	svcCfg := ucorev1.ToServiceConfig(reqCtx.ServiceConfig)

	fromProtocol := reqCtx.LLM.GetProtocol()
	toProtocol := svcCfg.GetLLMUpstreamProtocol()
	route := reqCtx.LLM.GetRoute()

	from := getTransCodec(fromProtocol, route)
	to := getTransCodec(toProtocol, getTransRoute(toProtocol, reqCtx.LLM.GetOperation()))

	if from == nil || to == nil {
		return nil, transUnsupported(
			"the %s route of the %s protocol cannot be translated to the %s protocol",
			route.String(), fromProtocol.String(), toProtocol.String())
	}

	model := transEffectiveModel(reqCtx)

	if model == "" && httputils.IsLLMModelInPath(toProtocol) {
		return nil, transUnsupported(
			"a request that names no model cannot be translated to the %s protocol",
			toProtocol.String())
	}

	if err := checkModelName(toProtocol, model); err != nil {
		return nil, transUnsupported(
			"the requested model cannot be translated to the %s protocol: %s",
			toProtocol.String(), err.Error())
	}

	return &transPlan{
		from:         from,
		to:           to,
		fromProtocol: fromProtocol,
		toProtocol:   toProtocol,

		model:  model,
		stream: reqCtx.LLM.GetStream(),

		llm: svcCfg.GetLLM(),
	}, nil
}

func transEffectiveModel(reqCtx *middlewares.RequestContext) string {
	if cur := reqCtx.LLMModel; cur != nil && cur.Effective != "" {
		return cur.Effective
	}

	return reqCtx.LLM.GetModel()
}

func (p *transPlan) maxOutputTokens(ir *transRequest) uint64 {
	ret := p.llm.GetTranslation().GetDefaultMaxOutputTokens()
	if ret == 0 {
		ret = defaultTransMaxOutputTokens
	}

	if ir.reasoning != nil && ir.reasoning.budget > 0 {
		ret = ret + ir.reasoning.budget
	}

	if val := p.llm.GetLimits().GetMaxOutputTokens(); val > 0 && ret > val {
		ret = val
	}

	return ret
}

func (m *translation) translateRequest(ctx context.Context, req *http.Request,
	reqCtx *middlewares.RequestContext, plan *transPlan) error {

	if !reqCtx.LLM.IsBodyValid {
		return transUnsupported(
			"the request body could not be parsed in order to be translated")
	}

	ir, err := plan.from.decodeRequest(reqCtx.Body)
	if err != nil {
		return err
	}

	ir.model = plan.model
	ir.stream = plan.stream
	transResolveToolNames(ir)

	if plan.toProtocol == corev1.Service_Spec_Config_LLM_GEMINI {
		m.continuation.restore(ctx, reqCtx, plan, ir)
	}

	if err := m.setReasoning(reqCtx, plan, ir); err != nil {
		return err
	}

	root, err := plan.to.encodeRequest(ir, &transEncodeOpts{
		model:                  plan.model,
		defaultMaxOutputTokens: plan.maxOutputTokens(ir),
	})
	if err != nil {
		return err
	}

	d := &doc{
		protocol: plan.toProtocol,
		route:    plan.to.route(),
		root:     root,
	}

	if ir.reasoning != nil {
		if err := ir.reasoning.apply(d, ir.reasoningFormat); err != nil {
			return err
		}
	}

	body, err := d.bytes()
	if err != nil {
		return transInternal("could not serialize the translated request")
	}

	if len(body) > commonguardrail.MaxMutatedBytes {
		return transUnsupported("the translated request is too large: %d", len(body))
	}

	plan.streamUsage = ir.streamUsage

	setTransRequest(req, plan, body)
	reqCtx.UpstreamBody = body

	return nil
}

func (m *translation) setReasoning(reqCtx *middlewares.RequestContext,
	plan *transPlan, ir *transRequest) error {

	caps := getReasoningCaps(plan.toProtocol, plan.model)
	ir.reasoningFormat = caps.format

	if cur := reqCtx.LLMReasoning; cur != nil {
		ir.reasoning = &reasoningValue{
			isDisabled: cur.IsDisabled,
			effort:     cur.Effort,
			budget:     cur.TokenBudget,
		}
		return nil
	}

	if ir.reasoningTarget == nil {
		return nil
	}

	val, err := caps.resolve(ir.reasoningTarget)
	if err != nil {
		return transUnsupported(
			"the requested reasoning configuration cannot be translated "+
				"to the %s protocol: %s", plan.toProtocol.String(), err.Error())
	}

	ir.reasoning = val

	return nil
}

func setTransRequest(req *http.Request, plan *transPlan, body []byte) {
	if req.Body != nil {
		req.Body.Close()
	}

	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	path, rawPath, rawQuery := httputils.GetLLMRoutePath(plan.toProtocol,
		plan.to.route(), plan.model, plan.stream)

	req.URL.Path = path
	req.URL.RawPath = ""
	if rawPath != "" && rawPath != path {
		req.URL.RawPath = rawPath
	}
	req.URL.RawQuery = rawQuery
	req.RequestURI = req.URL.RequestURI()

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")

	for protocol, hdrs := range transProtocolHeaders {
		if protocol == plan.toProtocol {
			continue
		}
		for _, hdr := range hdrs {
			req.Header.Del(hdr)
		}
	}

	if plan.toProtocol == corev1.Service_Spec_Config_LLM_ANTHROPIC &&
		req.Header.Get(anthropicVersionHeader) == "" {
		req.Header.Set(anthropicVersionHeader, anthropicDefaultVersion)
	}
}

func (m *translation) writeError(w http.ResponseWriter,
	reqCtx *middlewares.RequestContext, err error) {

	cur := toTransError(err)

	WriteError(w, &WriteErrorOpts{
		Protocol:   reqCtx.LLM.GetProtocol(),
		HTTPStatus: cur.status,
		Type:       transErrorType(cur.status),
		Code:       ErrCodeTranslation,
		Message:    cur.text(),
	})
}

func transErrorType(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return ErrTypeAuthentication
	case status == http.StatusForbidden:
		return ErrTypePermission
	case status == http.StatusNotFound:
		return ErrTypeNotFound
	case status == http.StatusTooManyRequests:
		return ErrTypeRateLimit
	case status >= 500:
		return ErrTypeAPI
	default:
		return ErrTypeInvalidRequest
	}
}

type transObserver struct {
	responseID   string
	model        string
	finishReason string

	usage httputils.LLMUsage

	isSet bool
}

func (o *transObserver) observe(body []byte) {
	msg := httputils.ParseLLMResponse(body)
	if msg == nil {
		return
	}

	o.isSet = true

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

func (o *transObserver) apply(reqCtx *middlewares.RequestContext) {
	if !o.isSet {
		return
	}

	reqCtx.LLMUpstreamResponse = &middlewares.LLMResponseInfo{
		ResponseID:   o.responseID,
		Model:        o.model,
		FinishReason: o.finishReason,
		Usage:        o.usage,
	}
}
