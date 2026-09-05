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
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/glob"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const maxToolDefinitionBytes = 1024 * 1024

const maxLoggedToolNames = 64

type tools struct {
	next      http.Handler
	celEngine *celengine.CELEngine
}

func NewTools(ctx context.Context, next http.Handler,
	celEngine *celengine.CELEngine) (http.Handler, error) {
	return &tools{
		next:      next,
		celEngine: celEngine,
	}, nil
}

func (m *tools) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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

	for _, plugin := range plugins {
		cfg := plugin.GetTools()
		if cfg == nil {
			continue
		}

		isEnforced, ok := shouldEnforcePlugin(ctx, &enforcePluginOpts{
			w:         w,
			reqCtx:    reqCtx,
			celEngine: m.celEngine,
			plugin:    plugin,
			errCode:   ErrCodeToolDenied,
		})
		if !ok {
			return
		}
		if !isEnforced {
			continue
		}

		denied, err := m.apply(ctx, req, reqCtx, cfg)
		if err != nil {
			zap.L().Warn("Could not apply the LLM Tools Plugin",
				zap.String("plugin", plugin.GetName()), zap.Error(err))
			WriteError(w, &WriteErrorOpts{
				Protocol:   reqCtx.LLM.GetProtocol(),
				HTTPStatus: http.StatusInternalServerError,
				Type:       ErrTypeAPI,
				Code:       ErrCodeToolDenied,
				Message:    "Octelium: could not apply the tool policy of this Service",
			})
			return
		}

		if denied {
			WriteError(w, &WriteErrorOpts{
				Protocol:   reqCtx.LLM.GetProtocol(),
				HTTPStatus: http.StatusForbidden,
				Type:       ErrTypePermission,
				Code:       ErrCodeToolDenied,
				Message:    toolsDenyMessage(cfg),
			})
			return
		}
	}

	m.next.ServeHTTP(w, req)
}

func (m *tools) apply(ctx context.Context, req *http.Request,
	reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Tools) (bool, error) {

	if !isBodyParsedRoute(reqCtx.LLM.GetRoute()) || !reqCtx.LLM.IsBodyValid {
		return false, nil
	}

	d, err := newDoc(reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetRoute(), reqCtx.Body)
	if err != nil {
		return false, err
	}

	if !d.hasToolsCarrier() {
		return false, nil
	}

	declared, entries, err := d.tools()
	if err != nil {
		return false, err
	}

	kept := make([]json.RawMessage, 0, len(entries))
	keptNames := make([]string, 0, len(entries))
	var isFiltered bool
	var removedCount uint32

	for i, t := range declared {
		decision, filter := matchToolFilter(cfg.GetFilters(), t)

		switch decision {
		case corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_DENY:
			return true, nil

		case corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REPLACE:
			raw, err := m.render(ctx, reqCtx, filter.GetReplace())
			if err != nil {
				return false, err
			}
			kept = append(kept, raw)
			keptNames = append(keptNames, toolEntryName(raw))
			isFiltered = true

		case corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REMOVE:
			isFiltered = true
			removedCount++

		default:
			kept = append(kept, entries[i])
			keptNames = append(keptNames, t.name())
		}
	}

	var prepended []json.RawMessage
	var prependedNames []string

	for _, conf := range cfg.GetTools() {
		raw, err := m.render(ctx, reqCtx, conf)
		if err != nil {
			return false, err
		}

		if conf.GetPosition() == corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_PREPEND {
			prepended = append(prepended, raw)
			prependedNames = append(prependedNames, toolEntryName(raw))
		} else {
			kept = append(kept, raw)
			keptNames = append(keptNames, toolEntryName(raw))
		}
		isFiltered = true
	}

	if len(prepended) > 0 {
		kept = append(prepended, kept...)
		keptNames = append(prependedNames, keptNames...)
	}

	if isFiltered {
		if len(kept) == 0 {
			d.setToolsRaw(nil)
		} else {
			raw, err := json.Marshal(kept)
			if err != nil {
				return false, err
			}
			d.setToolsRaw(raw)
		}
	}

	m.applyChoice(d, cfg, keptNames)

	setToolsInfo(reqCtx, keptNames, removedCount)

	if !d.isChanged() {
		return false, nil
	}

	return false, writeDoc(req, reqCtx, d)
}

func setToolsInfo(reqCtx *middlewares.RequestContext, names []string,
	removedCount uint32) {

	ret := &middlewares.LLMToolsInfo{
		Count:        uint32(len(names)),
		RemovedCount: removedCount,
	}
	if reqCtx.LLMTools != nil {
		ret.RemovedCount += reqCtx.LLMTools.RemovedCount
	}

	ret.Names = slices.Clone(names)
	slices.Sort(ret.Names)
	ret.Names = slices.Compact(ret.Names)
	if len(ret.Names) > maxLoggedToolNames {
		ret.Names = ret.Names[:maxLoggedToolNames]
	}

	reqCtx.LLMTools = ret
}

func matchToolFilter(filters []*corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter,
	t *tool) (corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Decision,
	*corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter) {

	if len(filters) == 0 {
		return corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_ALLOW, nil
	}

	for _, filter := range filters {
		if !isToolFilterMatched(filter, t) {
			continue
		}
		if filter.GetDecision() ==
			corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_DECISION_UNSET {
			return corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REMOVE, filter
		}
		return filter.GetDecision(), filter
	}

	if t.kind() != functionToolKind {
		return corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REMOVE, nil
	}

	return corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_ALLOW, nil
}

func isToolFilterMatched(cfg *corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter,
	t *tool) bool {
	switch cfg.Match.(type) {
	case *corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Name:
		name := t.name()
		if name == "" {
			return false
		}
		return glob.Match(cfg.GetName(), name)
	case *corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Type:
		return glob.Match(cfg.GetType(), t.kind())
	default:
		return false
	}
}

type toolRenderer interface {
	GetValue() string
	GetEval() string
	GetOpa() string
}

func (m *tools) render(ctx context.Context, reqCtx *middlewares.RequestContext,
	cfg toolRenderer) (json.RawMessage, error) {

	if reqCtx.ReqCtxMap == nil {
		reqCtx.SetReqCtxMap()
	}
	inputMap := map[string]any{
		"ctx": reqCtx.ReqCtxMap,
	}

	var ret string
	var err error

	switch {
	case cfg.GetValue() != "":
		ret = cfg.GetValue()
	case cfg.GetEval() != "":
		ret, err = m.celEngine.EvalPolicyString(ctx, cfg.GetEval(), inputMap)
	case cfg.GetOpa() != "":
		ret, err = m.celEngine.EvalPolicyStringOPA(ctx, cfg.GetOpa(), inputMap)
	default:
		return nil, errors.Errorf("The tool definition is not set")
	}

	if err != nil {
		return nil, err
	}

	if len(ret) > maxToolDefinitionBytes {
		return nil, errors.Errorf("The rendered tool definition is too large")
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(ret), &obj); err != nil {
		return nil, errors.Errorf("The rendered tool definition is not a JSON object")
	}

	return json.RawMessage(ret), nil
}

func toolEntryName(raw json.RawMessage) string {
	t := &tool{}
	if err := json.Unmarshal(raw, t); err != nil {
		return ""
	}
	return t.name()
}

func (m *tools) applyChoice(d *doc,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Tools, keptNames []string) {

	current := d.toolChoice()

	if len(keptNames) == 0 {
		if len(current) > 0 {
			d.setToolChoice(nil)
		}
		return
	}

	if name := toolChoiceName(current); name != "" && !containsString(keptNames, name) {
		d.setToolChoice(d.newToolChoice(toolChoiceAuto))
		return
	}

	if raw, isReconciled := reconcileAllowedNames(current, keptNames); isReconciled {
		if len(raw) == 0 {
			d.setToolChoice(d.newToolChoice(toolChoiceAuto))
			return
		}
		d.setToolChoice(raw)
		current = raw
	}

	switch cfg.GetChoice() {
	case corev1.Service_Spec_Config_LLM_Plugin_Tools_NONE:
		raw := d.newToolChoice(toolChoiceNone)
		if len(raw) == 0 {
			d.setToolsRaw(nil)
			return
		}
		d.dropProviderTools()
		if string(raw) != string(current) {
			d.setToolChoice(raw)
		}
	case corev1.Service_Spec_Config_LLM_Plugin_Tools_AUTO:
		if len(current) == 0 || isAutoToolChoice(current) {
			return
		}
		d.setToolChoice(d.newToolChoice(toolChoiceAuto))
	}
}

func reconcileAllowedNames(raw json.RawMessage,
	keptNames []string) (json.RawMessage, bool) {

	if len(raw) == 0 || raw[0] != '{' {
		return nil, false
	}

	obj := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}

	cur, ok := obj[allowedFunctionNamesKey]
	if !ok {
		return nil, false
	}

	var names []string
	if err := json.Unmarshal(cur, &names); err != nil {
		return nil, false
	}

	ret := make([]string, 0, len(names))
	for _, name := range names {
		if containsString(keptNames, name) {
			ret = append(ret, name)
		}
	}

	if len(ret) == len(names) {
		return nil, false
	}

	if len(ret) == 0 {
		return nil, true
	}

	val, err := json.Marshal(ret)
	if err != nil {
		return nil, false
	}
	obj[allowedFunctionNamesKey] = val

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false
	}

	return out, true
}

func (d *doc) newToolChoice(mode string) json.RawMessage {
	switch d.protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		return json.RawMessage(`{"type":"` + mode + `"}`)
	case corev1.Service_Spec_Config_LLM_GEMINI:
		return json.RawMessage(`{"mode":"` + strings.ToUpper(mode) + `"}`)
	case corev1.Service_Spec_Config_LLM_BEDROCK:
		if mode == toolChoiceNone {
			return nil
		}
		return json.RawMessage(`{"` + mode + `":{}}`)
	default:
		return json.RawMessage(`"` + mode + `"`)
	}
}

func toolChoiceMode(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	switch raw[0] {
	case '"':
		var ret string
		if err := json.Unmarshal(raw, &ret); err != nil {
			return ""
		}
		return ret
	case '{':
		var obj struct {
			Type string `json:"type"`
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return ""
		}
		if obj.Type != "" {
			return obj.Type
		}
		return strings.ToLower(obj.Mode)
	default:
		return ""
	}
}

const (
	toolChoiceAuto = "auto"
	toolChoiceNone = "none"

	allowedFunctionNamesKey = "allowedFunctionNames"
)

func isAutoToolChoice(raw json.RawMessage) bool {
	switch toolChoiceMode(raw) {
	case toolChoiceAuto, toolChoiceNone:
		return true
	}

	var obj map[string]json.RawMessage
	if len(raw) == 0 || raw[0] != '{' ||
		json.Unmarshal(raw, &obj) != nil {
		return false
	}

	if _, ok := obj[toolChoiceAuto]; ok {
		return true
	}

	return false
}

func toolChoiceName(raw json.RawMessage) string {
	if len(raw) == 0 || raw[0] != '{' {
		return ""
	}

	var obj struct {
		Name     string `json:"name"`
		Function *struct {
			Name string `json:"name"`
		} `json:"function"`
		Tool *struct {
			Name string `json:"name"`
		} `json:"tool"`
		AllowedFunctionNames []string `json:"allowedFunctionNames"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}

	if obj.Function != nil && obj.Function.Name != "" {
		return obj.Function.Name
	}
	if obj.Tool != nil && obj.Tool.Name != "" {
		return obj.Tool.Name
	}
	if len(obj.AllowedFunctionNames) == 1 {
		return obj.AllowedFunctionNames[0]
	}
	return obj.Name
}

func containsString(args []string, arg string) bool {
	for _, cur := range args {
		if cur == arg {
			return true
		}
	}
	return false
}

func toolsDenyMessage(cfg *corev1.Service_Spec_Config_LLM_Plugin_Tools) string {
	if msg := cfg.GetDenyMessage(); msg != "" {
		return msg
	}
	return "Octelium: this tool is not allowed by this Service"
}
