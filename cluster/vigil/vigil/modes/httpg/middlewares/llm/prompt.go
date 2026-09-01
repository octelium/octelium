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
	"encoding/json"
	"io"
	"net/http"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const maxPromptContentBytes = 256 * 1024

type prompt struct {
	next      http.Handler
	celEngine *celengine.CELEngine
}

func NewPrompt(ctx context.Context, next http.Handler,
	celEngine *celengine.CELEngine) (http.Handler, error) {
	return &prompt{
		next:      next,
		celEngine: celEngine,
	}, nil
}

func (m *prompt) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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
		cfg := plugin.GetPrompt()
		if cfg == nil {
			continue
		}

		isEnforced, ok := shouldEnforcePlugin(ctx, &enforcePluginOpts{
			w:         w,
			reqCtx:    reqCtx,
			celEngine: m.celEngine,
			plugin:    plugin,
			typ:       corev1.AccessLog_Entry_Info_LLM_Plugin_PROMPT,
			errCode:   ErrCodePromptDenied,
		})
		if !ok {
			return
		}
		if !isEnforced {
			continue
		}

		rec, denied, err := m.apply(ctx, req, reqCtx, plugin, cfg)
		if err != nil {
			zap.L().Warn("Could not apply the LLM Prompt Plugin",
				zap.String("plugin", plugin.GetName()), zap.Error(err))
			appendPluginRecord(reqCtx, &pluginRecord{
				name:    plugin.GetName(),
				typ:     corev1.AccessLog_Entry_Info_LLM_Plugin_PROMPT,
				outcome: corev1.AccessLog_Entry_Info_LLM_Plugin_FAILED,
			})
			WriteError(w, &WriteErrorOpts{
				Protocol:   reqCtx.LLM.GetProtocol(),
				HTTPStatus: http.StatusInternalServerError,
				Type:       ErrTypeAPI,
				Code:       ErrCodePromptDenied,
				Message:    "Octelium: could not apply the instructions of this Service",
			})
			return
		}

		appendPluginRecord(reqCtx, rec)

		if denied {
			WriteError(w, &WriteErrorOpts{
				Protocol:   reqCtx.LLM.GetProtocol(),
				HTTPStatus: http.StatusForbidden,
				Type:       ErrTypePermission,
				Code:       ErrCodePromptDenied,
				Message: "Octelium: this Service does not accept a request that carries " +
					"its own system instructions",
			})
			return
		}
	}

	m.next.ServeHTTP(w, req)
}

func (m *prompt) apply(ctx context.Context, req *http.Request,
	reqCtx *middlewares.RequestContext,
	plugin *corev1.Service_Spec_Config_LLM_Plugin,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Prompt) (*pluginRecord, bool, error) {

	ret := &pluginRecord{
		name:    plugin.GetName(),
		typ:     corev1.AccessLog_Entry_Info_LLM_Plugin_PROMPT,
		outcome: corev1.AccessLog_Entry_Info_LLM_Plugin_NO_MATCH,
	}

	if !isBodyParsedOperation(reqCtx.LLM.GetOperation()) || !reqCtx.LLM.IsBodyValid {
		return ret, false, nil
	}

	d, err := newDoc(reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetOperation(), reqCtx.Body)
	if err != nil {
		return nil, false, err
	}

	switch {
	case cfg.GetSystem() != nil:
		if !d.hasInstructionsCarrier() {
			return ret, false, nil
		}
		denied, err := m.applySystem(ctx, reqCtx, d, cfg.GetSystem(), ret)
		if err != nil {
			return nil, false, err
		}
		if denied {
			ret.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_BLOCKED
			return ret, true, nil
		}
	case cfg.GetMessage() != nil:
		if !d.hasMessagesCarrier() {
			return ret, false, nil
		}
		if err := m.applyMessage(ctx, reqCtx, d, cfg.GetMessage(), ret); err != nil {
			return nil, false, err
		}
	default:
		return ret, false, nil
	}

	if !d.isChanged() {
		return ret, false, nil
	}

	if err := writeDoc(req, reqCtx, d); err != nil {
		return nil, false, err
	}

	ret.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_APPLIED
	return ret, false, nil
}

func (m *prompt) applySystem(ctx context.Context, reqCtx *middlewares.RequestContext,
	d *doc, cfg *corev1.Service_Spec_Config_LLM_Plugin_Prompt_System,
	rec *pluginRecord) (bool, error) {

	current, err := d.instructions()
	if err != nil {
		return false, err
	}

	switch cfg.GetMode() {
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_STRIP:
		if current == "" {
			return false, nil
		}
		return false, d.setInstructions("")
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_REJECT:
		if current != "" {
			return true, nil
		}
	}

	content, err := m.render(ctx, reqCtx, cfg.GetContent())
	if err != nil {
		return false, err
	}
	if content == "" {
		return false, nil
	}

	var ret string
	switch cfg.GetMode() {
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_REPLACE,
		corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_REJECT:
		ret = content
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_APPEND:
		ret = joinInstructions(current, content)
	default:
		ret = joinInstructions(content, current)
	}

	rec.injectedBytes = uint32(len(content))
	return false, d.setInstructions(ret)
}

func joinInstructions(first, second string) string {
	switch {
	case first == "":
		return second
	case second == "":
		return first
	default:
		return first + "\n\n" + second
	}
}

func (m *prompt) applyMessage(ctx context.Context, reqCtx *middlewares.RequestContext,
	d *doc, cfg *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message,
	rec *pluginRecord) error {

	role := messageRole(cfg.GetRole())
	if role == "" {
		return nil
	}

	if role == roleAssistant && d.protocol != corev1.Service_Spec_Config_LLM_ANTHROPIC {
		return errors.Errorf(
			"Octelium: this protocol does not accept an assistant message that this Service inserts")
	}

	content, err := m.render(ctx, reqCtx, cfg.GetContent())
	if err != nil {
		return err
	}
	if content == "" {
		return nil
	}

	msgs, err := d.messages()
	if err != nil {
		return err
	}

	idxs := selectMessages(msgs, role, cfg.GetSelector())

	switch cfg.GetPosition() {
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_NEW_BEFORE,
		corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_NEW_AFTER:

		raw, err := newTextContent(content)
		if err != nil {
			return err
		}

		idx := len(msgs)
		if len(idxs) > 0 {
			idx = idxs[len(idxs)-1]
			if cfg.GetPosition() ==
				corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_NEW_AFTER {
				idx = idx + 1
			}
		}

		ret := make([]*message, 0, len(msgs)+1)
		ret = append(ret, msgs[:idx]...)
		ret = append(ret, &message{Role: role, Content: raw})
		ret = append(ret, msgs[idx:]...)

		rec.injectedBytes = uint32(len(content))
		return d.setMessages(ret)

	default:
		if len(idxs) == 0 {
			return nil
		}

		isPrepend := cfg.GetPosition() !=
			corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_APPEND

		var isChanged bool
		for _, idx := range idxs {
			raw, ok, err := d.insertIntoContent(role, msgs[idx].Content, content, isPrepend)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			msgs[idx].Content = raw
			isChanged = true
			rec.injectedBytes = rec.injectedBytes + uint32(len(content))
		}

		if !isChanged {
			return nil
		}

		return d.setMessages(msgs)
	}
}

func messageRole(arg corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_Role) string {
	switch arg {
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_USER:
		return roleUser
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_ASSISTANT:
		return roleAssistant
	default:
		return ""
	}
}

func selectMessages(msgs []*message, role string,
	selector corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_Selector) []int {
	var all []int
	for i, msg := range msgs {
		if msg.Role == role {
			all = append(all, i)
		}
	}

	if len(all) == 0 {
		return nil
	}

	switch selector {
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_ALL:
		return all
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_FIRST:
		return all[:1]
	default:
		return all[len(all)-1:]
	}
}

func (m *prompt) render(ctx context.Context, reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content) (string, error) {
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
	case *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content_Value:
		ret = cfg.GetValue()
	case *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content_Eval:
		ret, err = m.celEngine.EvalPolicyString(ctx, cfg.GetEval(), inputMap)
	case *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content_Opa:
		ret, err = m.celEngine.EvalPolicyStringOPA(ctx, cfg.GetOpa(), inputMap)
	default:
		return "", nil
	}

	if err != nil {
		zap.L().Warn("Could not render the Prompt Plugin content", zap.Error(err))
		return "", errors.Errorf("Octelium: could not render the instructions of this Service")
	}

	if len(ret) > maxPromptContentBytes {
		return "", errors.Errorf(
			"Octelium: the rendered instructions of this Service are too large")
	}

	return ret, nil
}

func writeDoc(req *http.Request, reqCtx *middlewares.RequestContext, d *doc) error {
	body, err := d.bytes()
	if err != nil {
		return err
	}

	if req.Body != nil {
		req.Body.Close()
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil

	reqCtx.Body = body
	reqCtx.BodyJSONMap = nil
	if len(body) > 0 {
		bodyMap := make(map[string]any)
		if err := json.Unmarshal(body, &bodyMap); err == nil {
			reqCtx.BodyJSONMap = bodyMap
		}
	}

	return nil
}
