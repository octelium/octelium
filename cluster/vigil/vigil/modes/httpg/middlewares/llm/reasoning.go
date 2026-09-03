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
	"strconv"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	minReasoningBudget    = 1024
	lowReasoningBudget    = 4096
	mediumReasoningBudget = 16384
	highReasoningBudget   = 32768

	maxReasoningValueLen = 64
)

type reasoning struct {
	next      http.Handler
	celEngine *celengine.CELEngine
}

func NewReasoning(ctx context.Context, next http.Handler,
	celEngine *celengine.CELEngine) (http.Handler, error) {
	return &reasoning{
		next:      next,
		celEngine: celEngine,
	}, nil
}

func (m *reasoning) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	if !ucorev1.ToService(reqCtx.Service).IsLLM() {
		m.next.ServeHTTP(w, req)
		return
	}

	cfg, ok := m.resolve(ctx, w, reqCtx)
	if !ok {
		return
	}

	if err := m.setReasoning(ctx, req, reqCtx, cfg); err != nil {
		zap.L().Warn("Could not set the LLM reasoning configuration", zap.Error(err))
		WriteError(w, &WriteErrorOpts{
			Protocol:   reqCtx.LLM.GetProtocol(),
			HTTPStatus: http.StatusInternalServerError,
			Type:       ErrTypeAPI,
			Code:       ErrCodeReasoning,
			Message:    "Octelium: could not set the reasoning configuration",
		})
		return
	}

	m.next.ServeHTTP(w, req)
}

func (m *reasoning) resolve(ctx context.Context, w http.ResponseWriter,
	reqCtx *middlewares.RequestContext) (*corev1.Service_Spec_Config_LLM_Reasoning, bool) {

	svcCfg := ucorev1.ToServiceConfig(reqCtx.ServiceConfig)
	ret := svcCfg.GetLLM().GetReasoning()

	for _, plugin := range svcCfg.GetLLMPlugins() {
		cfg := plugin.GetReasoning()
		if cfg == nil {
			continue
		}

		isEnforced, ok := shouldEnforcePlugin(ctx, &enforcePluginOpts{
			w:         w,
			reqCtx:    reqCtx,
			celEngine: m.celEngine,
			plugin:    plugin,
			errCode:   ErrCodeReasoning,
		})
		if !ok {
			return nil, false
		}
		if !isEnforced {
			continue
		}

		ret = cfg
	}

	return ret, true
}

func (m *reasoning) setReasoning(ctx context.Context, req *http.Request,
	reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Reasoning) error {

	if cfg == nil || cfg.Type == nil {
		return nil
	}

	if !isBodyParsedOperation(reqCtx.LLM.GetOperation()) || !reqCtx.LLM.IsBodyValid {
		return nil
	}

	d, err := newDoc(reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetOperation(), reqCtx.Body)
	if err != nil {
		return err
	}

	if !d.hasReasoningCarrier() {
		return nil
	}

	target, err := m.getTarget(ctx, reqCtx, cfg)
	if err != nil {
		return err
	}
	if target == nil {
		return nil
	}

	if err := target.apply(d); err != nil {
		return err
	}

	if !d.isChanged() {
		return nil
	}

	return writeDoc(req, reqCtx, d)
}

type reasoningTarget struct {
	level     corev1.Service_Spec_Config_LLM_Reasoning_Level
	maxTokens uint64
}

func (t *reasoningTarget) apply(d *doc) error {
	if !d.isReasoningBudget() {
		return d.setReasoningEffort(t.effort())
	}

	if t.level == corev1.Service_Spec_Config_LLM_Reasoning_NONE {
		return d.disableReasoning()
	}

	return d.setReasoningBudget(t.budget())
}

func (t *reasoningTarget) effort() string {
	if t.maxTokens == 0 {
		return strings.ToLower(t.level.String())
	}

	switch {
	case t.maxTokens >= highReasoningBudget:
		return strings.ToLower(
			corev1.Service_Spec_Config_LLM_Reasoning_HIGH.String())
	case t.maxTokens >= mediumReasoningBudget:
		return strings.ToLower(
			corev1.Service_Spec_Config_LLM_Reasoning_MEDIUM.String())
	case t.maxTokens >= lowReasoningBudget:
		return strings.ToLower(
			corev1.Service_Spec_Config_LLM_Reasoning_LOW.String())
	default:
		return strings.ToLower(
			corev1.Service_Spec_Config_LLM_Reasoning_MINIMAL.String())
	}
}

func (t *reasoningTarget) budget() uint64 {
	if t.maxTokens > 0 {
		if t.maxTokens < minReasoningBudget {
			return minReasoningBudget
		}
		return t.maxTokens
	}

	switch t.level {
	case corev1.Service_Spec_Config_LLM_Reasoning_MINIMAL:
		return minReasoningBudget
	case corev1.Service_Spec_Config_LLM_Reasoning_LOW:
		return lowReasoningBudget
	case corev1.Service_Spec_Config_LLM_Reasoning_MEDIUM:
		return mediumReasoningBudget
	default:
		return highReasoningBudget
	}
}

func (m *reasoning) getTarget(ctx context.Context,
	reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Reasoning) (*reasoningTarget, error) {

	switch cfg.Type.(type) {
	case *corev1.Service_Spec_Config_LLM_Reasoning_Level_:
		return newReasoningLevel(cfg.GetLevel()), nil
	case *corev1.Service_Spec_Config_LLM_Reasoning_MaxTokens:
		return newReasoningMaxTokens(cfg.GetMaxTokens()), nil
	case *corev1.Service_Spec_Config_LLM_Reasoning_Eval:
		ret, err := m.render(ctx, reqCtx, func(inputMap map[string]any) (string, error) {
			return m.celEngine.EvalPolicyString(ctx, cfg.GetEval(), inputMap)
		})
		if err != nil {
			return nil, err
		}
		return parseReasoningTarget(ret)
	case *corev1.Service_Spec_Config_LLM_Reasoning_Opa:
		ret, err := m.render(ctx, reqCtx, func(inputMap map[string]any) (string, error) {
			return m.celEngine.EvalPolicyStringOPA(ctx, cfg.GetOpa(), inputMap)
		})
		if err != nil {
			return nil, err
		}
		return parseReasoningTarget(ret)
	default:
		return nil, nil
	}
}

func (m *reasoning) render(ctx context.Context, reqCtx *middlewares.RequestContext,
	eval func(map[string]any) (string, error)) (string, error) {

	if reqCtx.ReqCtxMap == nil {
		reqCtx.SetReqCtxMap()
	}

	return eval(map[string]any{
		"ctx": reqCtx.ReqCtxMap,
	})
}

func newReasoningLevel(
	level corev1.Service_Spec_Config_LLM_Reasoning_Level) *reasoningTarget {
	if level == corev1.Service_Spec_Config_LLM_Reasoning_LEVEL_UNSET {
		return nil
	}
	return &reasoningTarget{level: level}
}

func newReasoningMaxTokens(maxTokens uint64) *reasoningTarget {
	if maxTokens == 0 {
		return nil
	}
	return &reasoningTarget{maxTokens: maxTokens}
}

func parseReasoningTarget(arg string) (*reasoningTarget, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return nil, nil
	}

	if len(arg) > maxReasoningValueLen {
		return nil, errors.Errorf("The rendered reasoning value is too large: %d", len(arg))
	}

	if level, ok := corev1.Service_Spec_Config_LLM_Reasoning_Level_value[strings.ToUpper(arg)]; ok {
		return newReasoningLevel(
			corev1.Service_Spec_Config_LLM_Reasoning_Level(level)), nil
	}

	maxTokens, err := strconv.ParseUint(arg, 10, 64)
	if err != nil {
		return nil, errors.Errorf("Invalid rendered reasoning value")
	}

	return newReasoningMaxTokens(maxTokens), nil
}
