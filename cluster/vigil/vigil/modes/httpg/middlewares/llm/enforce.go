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
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
	"go.uber.org/zap"
)

type enforcePluginOpts struct {
	w         http.ResponseWriter
	reqCtx    *middlewares.RequestContext
	celEngine *celengine.CELEngine
	plugin    *corev1.Service_Spec_Config_LLM_Plugin
	errCode   string
}

func shouldEnforcePlugin(ctx context.Context, o *enforcePluginOpts) (bool, bool) {
	isEnforced, err := commonplugin.ShouldEnforcePluginErr(ctx,
		&commonplugin.ShouldEnforcePluginOpts{
			Plugin:    o.plugin,
			CELEngine: o.celEngine,
			Phase:     corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH,
		})
	if err == nil {
		return isEnforced, true
	}

	zap.L().Warn("Could not evaluate the LLM Plugin Condition",
		zap.String("plugin", o.plugin.GetName()), zap.Error(err))

	WriteError(o.w, &WriteErrorOpts{
		Protocol:   o.reqCtx.LLM.GetProtocol(),
		HTTPStatus: http.StatusInternalServerError,
		Type:       ErrTypeAPI,
		Code:       o.errCode,
		Message:    "Octelium: could not evaluate the Plugins of this Service",
	})

	return false, false
}
