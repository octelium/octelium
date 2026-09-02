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
	celEngine *celengine.CELEngine, svc *corev1.Service) (http.Handler, error) {

	if hasSecretsPattern(svc) {
		warmSecretScanner()
	}

	return &guardrail{
		next:      next,
		celEngine: celEngine,
	}, nil
}

type activeGuardrail struct {
	plugin *corev1.Service_Spec_Config_LLM_Plugin
	cfg    *corev1.Service_Spec_Config_LLM_Plugin_Guardrail
	set    *patternSet

	replacements map[int]string
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
			m.writeDenied(w, reqCtx, cfg)
			return
		}

		active := &activeGuardrail{
			plugin:       plugin,
			cfg:          cfg,
			set:          set,
			replacements: make(map[int]string),
		}

		if cfg.GetLeg() != corev1.Service_Spec_Config_LLM_Plugin_Guardrail_RESPONSE {
			if !m.applyRequest(ctx, w, req, reqCtx, active) {
				return
			}
		}

		switch cfg.GetLeg() {
		case corev1.Service_Spec_Config_LLM_Plugin_Guardrail_RESPONSE,
			corev1.Service_Spec_Config_LLM_Plugin_Guardrail_BOTH:
			responseLeg = append(responseLeg, active)
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

	if !isBodyParsedOperation(reqCtx.LLM.GetOperation()) || !reqCtx.LLM.IsBodyValid {
		return true
	}

	d, err := newDoc(reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetOperation(), reqCtx.Body)
	if err != nil {
		return m.onError(w, reqCtx, active, err)
	}

	parts, err := d.textParts(active.cfg.GetScopes())
	if err != nil {
		return m.onError(w, reqCtx, active, err)
	}

	var isChanged bool

	for _, part := range parts {
		findings, err := active.set.inspect(part.text)
		if err != nil {
			return m.onError(w, reqCtx, active, err)
		}
		if len(findings) == 0 {
			continue
		}

		if deniedFinding(findings) != nil {
			m.writeDenied(w, reqCtx, active.cfg)
			return false
		}

		if err := m.setReplacements(ctx, reqCtx, active, findings); err != nil {
			return m.onError(w, reqCtx, active, err)
		}

		updated, count, err := rewrite(part.text, findings, active.replacements)
		if err != nil {
			return m.onError(w, reqCtx, active, err)
		}
		if count == 0 {
			continue
		}

		if part.set == nil {
			m.writeDenied(w, reqCtx, active.cfg)
			return false
		}

		if err := part.set(updated); err != nil {
			return m.onError(w, reqCtx, active, err)
		}

		isChanged = true
	}

	if !isChanged {
		return true
	}

	if err := writeDoc(req, reqCtx, d); err != nil {
		return m.onError(w, reqCtx, active, err)
	}

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
		if _, ok := active.replacements[f.rule.idx]; ok {
			continue
		}

		ret, err := m.render(ctx, reqCtx, f.rule.cfg.GetReplace())
		if err != nil {
			return err
		}
		active.replacements[f.rule.idx] = ret
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

	var ret string
	var err error

	switch cfg.Type.(type) {
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace_Value:
		ret = cfg.GetValue()
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace_Eval:
		ret, err = m.celEngine.EvalPolicyString(ctx, cfg.GetEval(), inputMap)
	case *corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace_Opa:
		ret, err = m.celEngine.EvalPolicyStringOPA(ctx, cfg.GetOpa(), inputMap)
	default:
		return "", errors.Errorf("The Guardrail Pattern replacement is not set")
	}

	if err != nil {
		return "", err
	}

	if len(ret) > maxReplacementBytes {
		return "", errors.Errorf("The rendered replacement is too large: %d", len(ret))
	}

	return ret, nil
}

func (m *guardrail) onError(w http.ResponseWriter, reqCtx *middlewares.RequestContext,
	active *activeGuardrail, err error) bool {

	zap.L().Warn("The LLM Guardrail could not reach a verdict",
		zap.String("plugin", active.name()), zap.Error(err))

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
