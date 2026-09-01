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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/glob"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const maxToolDefinitionBytes = 1024 * 1024

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
			typ:       corev1.AccessLog_Entry_Info_LLM_Plugin_TOOLS,
			errCode:   ErrCodeToolDenied,
		})
		if !ok {
			return
		}
		if !isEnforced {
			continue
		}

		rec, denied, err := m.apply(ctx, req, reqCtx, plugin, cfg)
		if err != nil {
			zap.L().Warn("Could not apply the LLM Tools Plugin",
				zap.String("plugin", plugin.GetName()), zap.Error(err))
			appendPluginRecord(reqCtx, &pluginRecord{
				name:    plugin.GetName(),
				typ:     corev1.AccessLog_Entry_Info_LLM_Plugin_TOOLS,
				outcome: corev1.AccessLog_Entry_Info_LLM_Plugin_FAILED,
			})
			WriteError(w, &WriteErrorOpts{
				Protocol:   reqCtx.LLM.GetProtocol(),
				HTTPStatus: http.StatusInternalServerError,
				Type:       ErrTypeAPI,
				Code:       ErrCodeToolDenied,
				Message:    "Octelium: could not apply the tool policy of this Service",
			})
			return
		}

		appendPluginRecord(reqCtx, rec)

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
	plugin *corev1.Service_Spec_Config_LLM_Plugin,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Tools) (*pluginRecord, bool, error) {

	rec := &pluginRecord{
		name:    plugin.GetName(),
		typ:     corev1.AccessLog_Entry_Info_LLM_Plugin_TOOLS,
		outcome: corev1.AccessLog_Entry_Info_LLM_Plugin_NO_MATCH,
	}

	if !isBodyParsedOperation(reqCtx.LLM.GetOperation()) || !reqCtx.LLM.IsBodyValid {
		return rec, false, nil
	}

	d, err := newDoc(reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetOperation(), reqCtx.Body)
	if err != nil {
		return nil, false, err
	}

	declared, entries, err := d.tools()
	if err != nil {
		return nil, false, err
	}

	kept := make([]json.RawMessage, 0, len(entries))
	keptNames := make([]string, 0, len(entries))
	var isFiltered bool

	for i, t := range declared {
		decision, filter := matchToolFilter(cfg.GetFilters(), t)

		switch decision {
		case corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_DENY:
			rec.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_BLOCKED
			rec.rules = append(rec.rules, toolFilterLabel(filter))
			rec.removedTools = append(rec.removedTools, t.label())
			rec.matchCount = 1
			return rec, true, nil

		case corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REPLACE:
			raw, err := m.render(ctx, reqCtx, filter.GetReplace())
			if err != nil {
				return nil, false, err
			}
			kept = append(kept, raw)
			keptNames = append(keptNames, toolEntryName(raw))
			rec.rules = append(rec.rules, toolFilterLabel(filter))
			rec.removedTools = append(rec.removedTools, t.label())
			isFiltered = true

		case corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_REMOVE:
			if filter != nil {
				rec.rules = append(rec.rules, toolFilterLabel(filter))
			}
			rec.removedTools = append(rec.removedTools, t.label())
			isFiltered = true

		default:
			kept = append(kept, entries[i])
			keptNames = append(keptNames, t.name())
		}
	}

	for _, conf := range cfg.GetTools() {
		raw, err := m.render(ctx, reqCtx, conf)
		if err != nil {
			return nil, false, err
		}

		if conf.GetPosition() == corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_PREPEND {
			kept = append([]json.RawMessage{raw}, kept...)
			keptNames = append([]string{toolEntryName(raw)}, keptNames...)
		} else {
			kept = append(kept, raw)
			keptNames = append(keptNames, toolEntryName(raw))
		}
		isFiltered = true
	}

	if isFiltered {
		if len(kept) == 0 {
			d.setToolsRaw(nil)
		} else {
			raw, err := json.Marshal(kept)
			if err != nil {
				return nil, false, err
			}
			d.setToolsRaw(raw)
		}
	}

	m.applyChoice(d, cfg, keptNames)

	if !d.isChanged() {
		return rec, false, nil
	}

	if err := writeDoc(req, reqCtx, d); err != nil {
		return nil, false, err
	}

	rec.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_APPLIED
	rec.matchCount = uint32(len(rec.removedTools))
	return rec, false, nil
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

func toolFilterLabel(cfg *corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter) string {
	switch cfg.Match.(type) {
	case *corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Name:
		return cfg.GetName()
	case *corev1.Service_Spec_Config_LLM_Plugin_Tools_Filter_Type:
		return cfg.GetType()
	default:
		return ""
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
		d.setToolChoice(d.newToolChoice("auto"))
		return
	}

	switch cfg.GetChoice() {
	case corev1.Service_Spec_Config_LLM_Plugin_Tools_NONE:
		raw := d.newToolChoice("none")
		if string(raw) != string(current) {
			d.setToolChoice(raw)
		}
	case corev1.Service_Spec_Config_LLM_Plugin_Tools_AUTO:
		if len(current) == 0 || isAutoToolChoice(current) {
			return
		}
		d.setToolChoice(d.newToolChoice("auto"))
	}
}

func (d *doc) newToolChoice(mode string) json.RawMessage {
	if d.protocol == corev1.Service_Spec_Config_LLM_ANTHROPIC {
		return json.RawMessage(`{"type":"` + mode + `"}`)
	}
	return json.RawMessage(`"` + mode + `"`)
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
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return ""
		}
		return obj.Type
	default:
		return ""
	}
}

func isAutoToolChoice(raw json.RawMessage) bool {
	switch toolChoiceMode(raw) {
	case "auto", "none":
		return true
	default:
		return false
	}
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
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}

	if obj.Function != nil && obj.Function.Name != "" {
		return obj.Function.Name
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
