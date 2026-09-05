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
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	anthropicMinReasoningBudget = 1024
	geminiMinReasoningBudget    = 128

	minimalReasoningBudget = 1024
	lowReasoningBudget     = 4096
	mediumReasoningBudget  = 16384
	highReasoningBudget    = 32768

	maxReasoningValueLen = 64
)

const (
	reasoningEffortNone    = "none"
	reasoningEffortMinimal = "minimal"
	reasoningEffortLow     = "low"
	reasoningEffortMedium  = "medium"
	reasoningEffortHigh    = "high"
)

const bedrockNovaModelPrefix = "amazon.nova"

var bedrockModelRegionPrefixes = []string{"us.", "us-gov.", "eu.", "apac.", "global."}

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

	errOpts, err := m.setReasoning(ctx, req, reqCtx, cfg)
	if err != nil {
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
	if errOpts != nil {
		WriteError(w, errOpts)
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
	cfg *corev1.Service_Spec_Config_LLM_Reasoning) (*WriteErrorOpts, error) {

	if cfg == nil || cfg.Type == nil {
		return nil, nil
	}

	if !isBodyParsedOperation(reqCtx.LLM.GetOperation()) || !reqCtx.LLM.IsBodyValid {
		return nil, nil
	}

	d, err := newDoc(reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetOperation(), reqCtx.Body)
	if err != nil {
		return nil, err
	}

	if !d.hasReasoningCarrier() {
		return nil, nil
	}

	target, err := m.getTarget(ctx, reqCtx, cfg)
	if err != nil {
		return nil, err
	}
	if target == nil {
		return nil, nil
	}

	caps := getReasoningCaps(reqCtx.LLM.GetProtocol(), getReasoningModel(req, reqCtx, d))

	val, err := caps.resolve(target)
	if err != nil {
		zap.L().Debug("Could not resolve the LLM reasoning configuration",
			zap.Error(err))
		return &WriteErrorOpts{
			Protocol:   reqCtx.LLM.GetProtocol(),
			HTTPStatus: http.StatusBadRequest,
			Type:       ErrTypeInvalidRequest,
			Code:       ErrCodeReasoning,
			Message:    fmt.Sprintf("Octelium: %s", err.Error()),
		}, nil
	}

	if err := val.apply(d, caps.format); err != nil {
		return nil, err
	}

	reqCtx.LLMReasoning = &middlewares.LLMReasoningInfo{
		IsDisabled:  val.isDisabled,
		Effort:      val.effort,
		TokenBudget: val.budget,
	}

	if !d.isChanged() {
		return nil, nil
	}

	return nil, writeDoc(req, reqCtx, d)
}

func getReasoningModel(req *http.Request, reqCtx *middlewares.RequestContext,
	d *doc) string {

	protocol := reqCtx.LLM.GetProtocol()

	if httputils.IsLLMModelInPath(protocol) {
		if ret := httputils.GetLLMModelPath(protocol, req.URL.Path); ret != "" {
			return ret
		}
	} else if ret := d.model(); ret != "" {
		return ret
	}

	return reqCtx.LLM.GetModel()
}

type reasoningFormat int

const (
	reasoningFormatEffort reasoningFormat = iota
	reasoningFormatAnthropicBudget
	reasoningFormatGeminiBudget
	reasoningFormatBedrockBudget
	reasoningFormatBedrockEffort
)

func (f reasoningFormat) isBudget() bool {
	switch f {
	case reasoningFormatAnthropicBudget,
		reasoningFormatGeminiBudget,
		reasoningFormatBedrockBudget:
		return true
	default:
		return false
	}
}

type reasoningStep struct {
	level  corev1.Service_Spec_Config_LLM_Reasoning_Level
	effort string
	budget uint64
}

var effortReasoningSteps = []*reasoningStep{
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_MINIMAL,
		effort: reasoningEffortMinimal,
	},
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_LOW,
		effort: reasoningEffortLow,
	},
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_MEDIUM,
		effort: reasoningEffortMedium,
	},
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_HIGH,
		effort: reasoningEffortHigh,
	},
}

var novaReasoningSteps = []*reasoningStep{
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_LOW,
		effort: reasoningEffortLow,
	},
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_MEDIUM,
		effort: reasoningEffortMedium,
	},
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_HIGH,
		effort: reasoningEffortHigh,
	},
}

var budgetReasoningSteps = []*reasoningStep{
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_MINIMAL,
		budget: minimalReasoningBudget,
	},
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_LOW,
		budget: lowReasoningBudget,
	},
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_MEDIUM,
		budget: mediumReasoningBudget,
	},
	{
		level:  corev1.Service_Spec_Config_LLM_Reasoning_HIGH,
		budget: highReasoningBudget,
	},
}

type reasoningCaps struct {
	model      string
	format     reasoningFormat
	canDisable bool
	minBudget  uint64
	maxBudget  uint64
	steps      []*reasoningStep
}

func getReasoningCaps(protocol corev1.Service_Spec_Config_LLM_Protocol,
	model string) *reasoningCaps {

	switch protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return &reasoningCaps{
			model:      model,
			format:     reasoningFormatAnthropicBudget,
			canDisable: true,
			minBudget:  anthropicMinReasoningBudget,
			steps:      budgetReasoningSteps,
		}
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return &reasoningCaps{
			model:      model,
			format:     reasoningFormatGeminiBudget,
			canDisable: true,
			minBudget:  geminiMinReasoningBudget,
			steps:      budgetReasoningSteps,
		}
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		if strings.HasPrefix(getBedrockModelName(model), bedrockNovaModelPrefix) {
			return &reasoningCaps{
				model:      model,
				format:     reasoningFormatBedrockEffort,
				canDisable: true,
				steps:      novaReasoningSteps,
			}
		}
		return &reasoningCaps{
			model:      model,
			format:     reasoningFormatBedrockBudget,
			canDisable: true,
			minBudget:  anthropicMinReasoningBudget,
			steps:      budgetReasoningSteps,
		}
	default:
		return &reasoningCaps{
			model:      model,
			format:     reasoningFormatEffort,
			canDisable: true,
			steps:      effortReasoningSteps,
		}
	}
}

func getBedrockModelName(model string) string {
	ret := strings.ToLower(model)
	for _, prefix := range bedrockModelRegionPrefixes {
		if rest, ok := strings.CutPrefix(ret, prefix); ok {
			return rest
		}
	}
	return ret
}

func (c *reasoningCaps) resolve(t *reasoningTarget) (*reasoningValue, error) {
	switch {
	case t.effort != "":
		if c.format.isBudget() {
			return nil, errors.Errorf(
				"the model does not accept a reasoning effort: %s", c.model)
		}
		return &reasoningValue{effort: t.effort}, nil
	case t.tokenBudget > 0:
		return c.resolveTokenBudget(t.tokenBudget)
	default:
		return c.resolveLevel(t.level)
	}
}

func (c *reasoningCaps) resolveTokenBudget(tokenBudget uint64) (*reasoningValue, error) {
	if !c.format.isBudget() {
		return nil, errors.Errorf(
			"the model does not accept a reasoning token budget: %s", c.model)
	}

	switch {
	case c.maxBudget > 0 && tokenBudget > c.maxBudget:
		return &reasoningValue{budget: c.maxBudget}, nil
	case tokenBudget < c.minBudget:
		return c.resolveDisabled()
	default:
		return &reasoningValue{budget: tokenBudget}, nil
	}
}

func (c *reasoningCaps) resolveLevel(
	level corev1.Service_Spec_Config_LLM_Reasoning_Level) (*reasoningValue, error) {

	var step *reasoningStep
	if level != corev1.Service_Spec_Config_LLM_Reasoning_NONE {
		for _, cur := range c.steps {
			if cur.level <= level {
				step = cur
			}
		}
	}

	if step == nil {
		return c.resolveDisabled()
	}

	if c.format.isBudget() {
		return &reasoningValue{budget: step.budget}, nil
	}

	return &reasoningValue{effort: step.effort}, nil
}

func (c *reasoningCaps) resolveDisabled() (*reasoningValue, error) {
	if !c.canDisable {
		return nil, errors.Errorf("the model cannot disable reasoning: %s", c.model)
	}

	return &reasoningValue{isDisabled: true}, nil
}

type reasoningTarget struct {
	level       corev1.Service_Spec_Config_LLM_Reasoning_Level
	tokenBudget uint64
	effort      string
}

type reasoningValue struct {
	isDisabled bool
	effort     string
	budget     uint64
}

func (v *reasoningValue) apply(d *doc, format reasoningFormat) error {
	switch {
	case v.isDisabled:
		return d.disableReasoning(format)
	case format.isBudget():
		return d.setReasoningBudget(format, v.budget)
	default:
		return d.setReasoningEffort(format, v.effort)
	}
}

func (m *reasoning) getTarget(ctx context.Context,
	reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Reasoning) (*reasoningTarget, error) {

	switch cfg.Type.(type) {
	case *corev1.Service_Spec_Config_LLM_Reasoning_Level_:
		return newReasoningLevel(cfg.GetLevel()), nil
	case *corev1.Service_Spec_Config_LLM_Reasoning_TokenBudget:
		return newReasoningTokenBudget(cfg.GetTokenBudget()), nil
	case *corev1.Service_Spec_Config_LLM_Reasoning_Effort:
		return newReasoningEffort(cfg.GetEffort())
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

func newReasoningTokenBudget(tokenBudget uint64) *reasoningTarget {
	if tokenBudget == 0 {
		return nil
	}
	return &reasoningTarget{tokenBudget: tokenBudget}
}

func newReasoningEffort(effort string) (*reasoningTarget, error) {
	if effort == "" {
		return nil, nil
	}

	if len(effort) > maxReasoningValueLen {
		return nil, errors.Errorf("The reasoning effort is too long: %d", len(effort))
	}

	for i := 0; i < len(effort); i++ {
		if effort[i] < 0x20 || effort[i] == 0x7f {
			return nil, errors.Errorf(
				"The reasoning effort contains an invalid control character")
		}
	}

	return &reasoningTarget{effort: effort}, nil
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

	if tokenBudget, err := strconv.ParseUint(arg, 10, 64); err == nil {
		return newReasoningTokenBudget(tokenBudget), nil
	}

	return newReasoningEffort(arg)
}
