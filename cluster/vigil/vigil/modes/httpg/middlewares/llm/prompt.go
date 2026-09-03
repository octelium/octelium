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
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonguardrail"
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

	var hasDownstreamInstructions bool
	var isInstructionsRead bool

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
			errCode:   ErrCodePromptDenied,
		})
		if !ok {
			return
		}
		if !isEnforced {
			continue
		}

		if !isInstructionsRead {
			ret, err := m.hasInstructions(reqCtx)
			if err != nil {
				zap.L().Warn("Could not read the LLM request instructions",
					zap.Error(err))
				m.writeFailed(w, reqCtx)
				return
			}
			hasDownstreamInstructions = ret
			isInstructionsRead = true
		}

		denied, err := m.apply(ctx, req, reqCtx, cfg, hasDownstreamInstructions)
		if err != nil {
			zap.L().Warn("Could not apply the LLM Prompt Plugin",
				zap.String("plugin", plugin.GetName()), zap.Error(err))
			m.writeFailed(w, reqCtx)
			return
		}

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

func (m *prompt) hasInstructions(reqCtx *middlewares.RequestContext) (bool, error) {
	if !isBodyParsedOperation(reqCtx.LLM.GetOperation()) || !reqCtx.LLM.IsBodyValid {
		return false, nil
	}

	d, err := newDoc(reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetOperation(), reqCtx.Body)
	if err != nil {
		return false, err
	}

	ret, err := d.instructions()
	if err != nil {
		return false, err
	}

	return ret != "", nil
}

func (m *prompt) writeFailed(w http.ResponseWriter, reqCtx *middlewares.RequestContext) {
	WriteError(w, &WriteErrorOpts{
		Protocol:   reqCtx.LLM.GetProtocol(),
		HTTPStatus: http.StatusInternalServerError,
		Type:       ErrTypeAPI,
		Code:       ErrCodePromptDenied,
		Message:    "Octelium: could not apply the instructions of this Service",
	})
}

func (m *prompt) apply(ctx context.Context, req *http.Request,
	reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_Prompt,
	hasDownstreamInstructions bool) (bool, error) {

	if !isBodyParsedOperation(reqCtx.LLM.GetOperation()) || !reqCtx.LLM.IsBodyValid {
		return false, nil
	}

	d, err := newDoc(reqCtx.LLM.GetProtocol(), reqCtx.LLM.GetOperation(), reqCtx.Body)
	if err != nil {
		return false, err
	}

	switch {
	case cfg.GetSystem() != nil:
		if !d.hasInstructionsCarrier() {
			return false, nil
		}
		denied, err := m.applySystem(ctx, reqCtx, d, cfg.GetSystem(),
			hasDownstreamInstructions)
		if err != nil {
			return false, err
		}
		if denied {
			return true, nil
		}
	case cfg.GetMessage() != nil:
		if !d.hasMessagesCarrier() {
			return false, nil
		}
		if err := m.applyMessage(ctx, reqCtx, d, cfg.GetMessage()); err != nil {
			return false, err
		}
	default:
		return false, nil
	}

	if !d.isChanged() {
		return false, nil
	}

	return false, writeDoc(req, reqCtx, d)
}

func (m *prompt) applySystem(ctx context.Context, reqCtx *middlewares.RequestContext,
	d *doc, cfg *corev1.Service_Spec_Config_LLM_Plugin_Prompt_System,
	hasDownstreamInstructions bool) (bool, error) {

	switch cfg.GetMode() {
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_STRIP:
		return false, d.replaceInstructions("")
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_REJECT:
		if hasDownstreamInstructions {
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

	switch cfg.GetMode() {
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_REPLACE,
		corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_REJECT:
		return false, d.replaceInstructions(content)
	case corev1.Service_Spec_Config_LLM_Plugin_Prompt_System_APPEND:
		return false, d.insertInstructions(content, false)
	default:
		return false, d.insertInstructions(content, true)
	}
}

func (m *prompt) applyMessage(ctx context.Context, reqCtx *middlewares.RequestContext,
	d *doc, cfg *corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message) error {

	role := messageRole(cfg.GetRole())
	if role == "" {
		return nil
	}
	role = d.roleName(role)

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

		idx := len(msgs)
		if len(idxs) > 0 {
			idx = idxs[len(idxs)-1]
			if cfg.GetPosition() ==
				corev1.Service_Spec_Config_LLM_Plugin_Prompt_Message_NEW_AFTER {
				idx = idx + 1
			}
		}

		if err := checkPrefill(d, role, idx == len(msgs)); err != nil {
			return err
		}

		raw, err := d.newTextContent(role, content)
		if err != nil {
			return err
		}

		ret := make([]*message, 0, len(msgs)+1)
		ret = append(ret, msgs[:idx]...)
		ret = append(ret, &message{
			Role:       role,
			Content:    raw,
			contentKey: d.contentKey(),
		})
		ret = append(ret, msgs[idx:]...)

		return d.setMessages(ret)

	default:
		if len(idxs) == 0 {
			return nil
		}

		if err := checkPrefill(d, role,
			idxs[len(idxs)-1] == len(msgs)-1); err != nil {
			return err
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
		}

		if !isChanged {
			return nil
		}

		return d.setMessages(msgs)
	}
}

func checkPrefill(d *doc, role string, isTrailing bool) error {
	if role != d.roleName(roleAssistant) || !isTrailing {
		return nil
	}

	switch d.protocol {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC,
		corev1.Service_Spec_Config_LLM_BEDROCK:
		return nil
	}

	return errors.Errorf("This protocol does not accept a trailing assistant message")
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
		return "", err
	}

	if len(ret) > maxPromptContentBytes {
		return "", errors.Errorf("The rendered instructions are too large: %d", len(ret))
	}

	return ret, nil
}

func writeDoc(req *http.Request, reqCtx *middlewares.RequestContext, d *doc) error {
	body, err := d.bytes()
	if err != nil {
		return err
	}

	if len(body) > commonguardrail.MaxMutatedBytes {
		return errors.Errorf("The mutated request is too large: %d", len(body))
	}

	if req.Body != nil {
		req.Body.Close()
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil

	reqCtx.Body = body
	middlewares.SetLLMRequestContext(reqCtx, req)
	reqCtx.SetReqCtxMap()
	reqCtx.SetBodyDigest()

	return nil
}
