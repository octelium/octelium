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
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const maxLLMModelLen = 256

type model struct {
	next      http.Handler
	celEngine *celengine.CELEngine
}

func NewModel(ctx context.Context, next http.Handler,
	celEngine *celengine.CELEngine) (http.Handler, error) {
	return &model{
		next:      next,
		celEngine: celEngine,
	}, nil
}

func (m *model) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	if !ucorev1.ToService(reqCtx.Service).IsLLM() {
		m.next.ServeHTTP(w, req)
		return
	}

	target, ok := m.resolve(ctx, w, reqCtx)
	if !ok {
		return
	}

	if err := m.setModel(req, reqCtx, target); err != nil {
		zap.L().Warn("Could not set the LLM upstream model", zap.Error(err))
		WriteError(w, &WriteErrorOpts{
			Protocol:   reqCtx.LLM.GetProtocol(),
			HTTPStatus: http.StatusInternalServerError,
			Type:       ErrTypeAPI,
			Code:       ErrCodeModelRewrite,
			Message:    "Octelium: could not set the upstream model",
		})
		return
	}

	m.next.ServeHTTP(w, req)
}

type modelTarget struct {
	cfg    *corev1.Service_Spec_Config_LLM_Model
	source corev1.AccessLog_Entry_Info_LLM_Model_Source
	plugin string
}

func (m *model) resolve(ctx context.Context, w http.ResponseWriter,
	reqCtx *middlewares.RequestContext) (*modelTarget, bool) {

	svcCfg := ucorev1.ToServiceConfig(reqCtx.ServiceConfig)

	ret := &modelTarget{
		cfg:    svcCfg.GetLLM().GetModel(),
		source: corev1.AccessLog_Entry_Info_LLM_Model_CONFIG,
	}

	if val := reqCtx.LLMSemanticRouter.GetModel(); val != "" {
		ret = &modelTarget{
			cfg: &corev1.Service_Spec_Config_LLM_Model{
				Type: &corev1.Service_Spec_Config_LLM_Model_Value{
					Value: val,
				},
			},
			source: corev1.AccessLog_Entry_Info_LLM_Model_SEMANTIC_ROUTER,
			plugin: reqCtx.LLMSemanticRouter.Plugin,
		}
	}

	for _, plugin := range svcCfg.GetLLMPlugins() {
		cfg := plugin.GetModel()
		if cfg == nil {
			continue
		}

		isEnforced, ok := shouldEnforcePlugin(ctx, &enforcePluginOpts{
			w:         w,
			reqCtx:    reqCtx,
			celEngine: m.celEngine,
			plugin:    plugin,
			errCode:   ErrCodeModelRewrite,
		})
		if !ok {
			return nil, false
		}
		if !isEnforced {
			continue
		}

		ret = &modelTarget{
			cfg:    cfg,
			source: corev1.AccessLog_Entry_Info_LLM_Model_PLUGIN,
			plugin: plugin.GetName(),
		}
	}

	return ret, true
}

func (m *model) setModel(req *http.Request, reqCtx *middlewares.RequestContext,
	target *modelTarget) error {
	if target.cfg == nil || target.cfg.Type == nil {
		return nil
	}

	protocol := reqCtx.LLM.GetProtocol()
	isModelInPath := httputils.IsLLMModelInPath(protocol)

	if !isModelInPath && (!httputils.IsLLMRouteBodyParsed(reqCtx.LLM.GetRoute()) ||
		!reqCtx.LLM.IsBodyValid) {
		return nil
	}

	name, err := m.getModel(req.Context(), target.cfg, reqCtx)
	if err != nil {
		return err
	}

	if name == "" || name == reqCtx.LLM.GetModel() {
		return nil
	}

	if err := checkModelName(protocol, name); err != nil {
		return err
	}

	reqCtx.LLMModel = &middlewares.LLMModelInfo{
		Effective: name,
		Source:    target.source,
		Plugin:    target.plugin,
	}

	if isModelInPath {
		setModelPath(req, protocol, name)
		return nil
	}

	bodyMap := make(map[string]json.RawMessage)
	if err := json.Unmarshal(reqCtx.Body, &bodyMap); err != nil {
		return err
	}

	nameRaw, err := json.Marshal(name)
	if err != nil {
		return err
	}
	bodyMap["model"] = nameRaw

	body, err := json.Marshal(bodyMap)
	if err != nil {
		return err
	}

	req.Body = io.NopCloser(bytes.NewBuffer(body))
	req.ContentLength = int64(len(body))

	reqCtx.Body = body
	if reqCtx.BodyJSONMap != nil {
		json.Unmarshal(body, &reqCtx.BodyJSONMap)
	}
	reqCtx.SetBodyDigest()

	return nil
}

func setModelPath(req *http.Request,
	protocol corev1.Service_Spec_Config_LLM_Protocol, target string) {

	path, rawPath := httputils.SetLLMModelPath(protocol, req.URL.Path, target)
	if path == "" {
		return
	}

	req.URL.Path = path
	if rawPath != path {
		req.URL.RawPath = rawPath
	} else {
		req.URL.RawPath = ""
	}
}

func checkModelName(protocol corev1.Service_Spec_Config_LLM_Protocol, arg string) error {
	if len(arg) > maxLLMModelLen {
		return errors.Errorf("The model name is too long: %d", len(arg))
	}

	for i := 0; i < len(arg); i++ {
		if arg[i] < 0x20 || arg[i] == 0x7f {
			return errors.Errorf("The model name contains an invalid control character")
		}
	}

	if protocol == corev1.Service_Spec_Config_LLM_GEMINI &&
		strings.ContainsAny(arg, "/:") {
		return errors.Errorf("The model name contains an invalid character")
	}

	return nil
}

func (m *model) getModel(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Model,
	reqCtx *middlewares.RequestContext) (string, error) {

	switch cfg.Type.(type) {
	case *corev1.Service_Spec_Config_LLM_Model_Value:
		return cfg.GetValue(), nil
	case *corev1.Service_Spec_Config_LLM_Model_Eval:
		return m.celEngine.EvalPolicyString(ctx, cfg.GetEval(), map[string]any{
			"ctx": reqCtx.ReqCtxMap,
		})
	case *corev1.Service_Spec_Config_LLM_Model_Opa:
		return m.celEngine.EvalPolicyStringOPA(ctx, cfg.GetOpa(), map[string]any{
			"ctx": reqCtx.ReqCtxMap,
		})
	default:
		return "", nil
	}
}
