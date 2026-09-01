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
	"context"
	"net/http"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type guardrail struct {
	next      http.Handler
	celEngine *celengine.CELEngine
}

func NewGuardrail(ctx context.Context, next http.Handler,
	celEngine *celengine.CELEngine) (http.Handler, error) {
	return &guardrail{
		next:      next,
		celEngine: celEngine,
	}, nil
}

type activeGuardrail struct {
	plugin *corev1.Service_Spec_Config_LLM_Plugin
	cfg    *corev1.Service_Spec_Config_LLM_Plugin_Guardrail
	set    *patternSet

	replacements map[string]string
}

func (a *activeGuardrail) name() string {
	return a.plugin.GetName()
}

func (m *guardrail) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	if !ucorev1.ToService(reqCtx.Service).IsLLM() {
		m.next.ServeHTTP(w, req)
		return
	}

	plugins := ucorev1.ToServiceConfig(reqCtx.ServiceConfig).GetLLMPlugins()
	if len(plugins) == 0 {
		m.next.ServeHTTP(w, req)
		return
	}

	var requestLeg []*activeGuardrail
	var responseLeg []*activeGuardrail

	for _, plugin := range plugins {
		cfg := plugin.GetGuardrail()
		if cfg == nil {
			continue
		}

		isEnforced, ok := shouldEnforcePlugin(ctx, &enforcePluginOpts{
			w:         w,
			reqCtx:    reqCtx,
			celEngine: m.celEngine,
			plugin:    plugin,
			typ:       corev1.AccessLog_Entry_Info_LLM_Plugin_GUARDRAIL,
			errCode:   ErrCodeGuardrail,
		})
		if !ok {
			return
		}
		if !isEnforced {
			continue
		}

		set, err := newPatternSet(cfg)
		if err != nil {
			zap.L().Warn("Could not build the LLM Guardrail patterns",
				zap.String("plugin", plugin.GetName()), zap.Error(err))
			m.writeFailed(w, reqCtx, cfg, plugin.GetName())
			return
		}

		active := &activeGuardrail{
			plugin:       plugin,
			cfg:          cfg,
			set:          set,
			replacements: make(map[string]string),
		}

		switch cfg.GetLeg() {
		case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_RESPONSE:
			responseLeg = append(responseLeg, active)
		case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_BOTH:
			requestLeg = append(requestLeg, active)
			responseLeg = append(responseLeg, active)
		default:
			requestLeg = append(requestLeg, active)
		}
	}

	for _, active := range requestLeg {
		if !m.applyRequest(ctx, w, req, reqCtx, active) {
			return
		}
	}

	if len(responseLeg) == 0 {
		m.next.ServeHTTP(w, req)
		return
	}

	crw := newGuardResponseWriter(w, reqCtx, responseLeg)
	m.next.ServeHTTP(crw, req)
	crw.finish()
}

func (m *guardrail) applyRequest(ctx context.Context, w http.ResponseWriter,
	req *http.Request, reqCtx *middlewares.RequestContext, active *activeGuardrail) bool {

	rec := &pluginRecord{
		name:    active.name(),
		typ:     corev1.AccessLog_Entry_Info_LLM_Plugin_GUARDRAIL,
		outcome: corev1.AccessLog_Entry_Info_LLM_Plugin_NO_MATCH,
	}

	if !isBodyParsedOperation(reqCtx.LLM.GetOperation()) || !reqCtx.LLM.IsBodyValid {
		appendPluginRecord(reqCtx, rec)
		return true
	}

	d, err := newDoc(reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetOperation(), reqCtx.Body)
	if err != nil {
		return m.onError(w, reqCtx, active, rec, err)
	}

	parts, err := d.textParts(active.cfg.GetScopes())
	if err != nil {
		return m.onError(w, reqCtx, active, rec, err)
	}

	var total int
	for _, part := range parts {
		total = total + len(part.text)
	}

	if total > guardrailMaxBytes(active.cfg.GetMaxBytes()) {
		rec.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_BLOCKED
		appendPluginRecord(reqCtx, rec)
		m.writeDenied(w, reqCtx, active.cfg)
		return false
	}

	var isChanged bool
	var isLogged bool

	for _, part := range parts {
		findings := active.set.inspect(part.text)
		if len(findings) == 0 {
			continue
		}

		rec.rules = append(rec.rules, findingRuleNames(findings)...)

		if f := deniedFinding(findings); f != nil {
			rec.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_BLOCKED
			rec.matchCount = rec.matchCount + 1
			appendPluginRecord(reqCtx, rec)
			m.writeDenied(w, reqCtx, active.cfg)
			return false
		}

		if err := m.setReplacements(ctx, reqCtx, active, findings); err != nil {
			return m.onError(w, reqCtx, active, rec, err)
		}

		updated, count := rewrite(part.text, findings, active.replacements)
		if count == 0 {
			isLogged = true
			rec.matchCount = rec.matchCount + uint32(len(findings))
			continue
		}

		if part.set == nil {
			rec.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_BLOCKED
			appendPluginRecord(reqCtx, rec)
			m.writeDenied(w, reqCtx, active.cfg)
			return false
		}

		if err := part.set(updated); err != nil {
			return m.onError(w, reqCtx, active, rec, err)
		}

		rec.matchCount = rec.matchCount + count
		isChanged = true
	}

	switch {
	case isChanged:
		if err := writeDoc(req, reqCtx, d); err != nil {
			return m.onError(w, reqCtx, active, rec, err)
		}
		rec.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_REDACTED
	case isLogged:
		rec.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_LOGGED
	}

	appendPluginRecord(reqCtx, rec)
	return true
}

func (m *guardrail) setReplacements(ctx context.Context,
	reqCtx *middlewares.RequestContext, active *activeGuardrail,
	findings []*finding) error {

	for _, f := range findings {
		if f.rule.action() !=
			corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_REPLACE {
			continue
		}
		if _, ok := active.replacements[f.rule.name]; ok {
			continue
		}

		ret, err := m.render(ctx, reqCtx, f.rule.cfg.GetReplace())
		if err != nil {
			return err
		}
		active.replacements[f.rule.name] = ret
	}

	return nil
}

func (m *guardrail) render(ctx context.Context, reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace) (string, error) {
	if cfg == nil {
		return "", nil
	}

	if reqCtx.ReqCtxMap == nil {
		reqCtx.SetReqCtxMap()
	}
	inputMap := map[string]any{
		"ctx": reqCtx.ReqCtxMap,
	}

	switch cfg.Type.(type) {
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace_Value:
		return cfg.GetValue(), nil
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace_Eval:
		return m.celEngine.EvalPolicyString(ctx, cfg.GetEval(), inputMap)
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace_Opa:
		return m.celEngine.EvalPolicyStringOPA(ctx, cfg.GetOpa(), inputMap)
	default:
		return "", errors.Errorf("The Guardrail Pattern replacement is not set")
	}
}

func (m *guardrail) onError(w http.ResponseWriter, reqCtx *middlewares.RequestContext,
	active *activeGuardrail, rec *pluginRecord, err error) bool {

	zap.L().Warn("The LLM Guardrail could not reach a verdict",
		zap.String("plugin", active.name()), zap.Error(err))

	rec.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_FAILED
	appendPluginRecord(reqCtx, rec)
	m.writeDenied(w, reqCtx, active.cfg)
	return false
}

func (m *guardrail) writeDenied(w http.ResponseWriter,
	reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail) {
	WriteError(w, &WriteErrorOpts{
		Protocol:   reqCtx.LLM.GetProtocol(),
		HTTPStatus: http.StatusForbidden,
		Type:       ErrTypePermission,
		Code:       ErrCodeGuardrail,
		Message:    guardrailDenyMessage(cfg),
	})
}

func (m *guardrail) writeFailed(w http.ResponseWriter,
	reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail, name string) {

	appendPluginRecord(reqCtx, &pluginRecord{
		name:    name,
		typ:     corev1.AccessLog_Entry_Info_LLM_Plugin_GUARDRAIL,
		outcome: corev1.AccessLog_Entry_Info_LLM_Plugin_FAILED,
	})

	m.writeDenied(w, reqCtx, cfg)
}
