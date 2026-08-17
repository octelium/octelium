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
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"go.uber.org/zap"
)

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

	if err := m.setModel(req, reqCtx); err != nil {
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

func (m *model) setModel(req *http.Request, reqCtx *middlewares.RequestContext) error {
	cfg := ucorev1.ToServiceConfig(reqCtx.ServiceConfig).GetLLM().GetModel()
	if cfg == nil || cfg.Type == nil {
		return nil
	}

	if !httputils.IsLLMOperationBodyParsed(reqCtx.LLM.GetOperation()) ||
		!reqCtx.LLM.IsBodyValid {
		return nil
	}

	target, err := m.getModel(req.Context(), cfg, reqCtx)
	if err != nil {
		return err
	}

	if target == "" || target == reqCtx.LLM.GetModel() {
		return nil
	}

	bodyMap := make(map[string]json.RawMessage)
	if err := json.Unmarshal(reqCtx.Body, &bodyMap); err != nil {
		return err
	}

	targetRaw, err := json.Marshal(target)
	if err != nil {
		return err
	}
	bodyMap["model"] = targetRaw

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

func (m *model) getModel(ctx context.Context,
	cfg *corev1.Service_Spec_Config_LLM_Model,
	reqCtx *middlewares.RequestContext) (string, error) {

	switch cfg.Type.(type) {
	case *corev1.Service_Spec_Config_LLM_Model_Value:
		return cfg.GetValue(), nil
	case *corev1.Service_Spec_Config_LLM_Model_Eval:
		return m.celEngine.EvalPolicyString(ctx, cfg.GetEval(), reqCtx.ReqCtxMap)
	default:
		return "", nil
	}
}
