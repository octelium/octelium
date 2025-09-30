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

package commonplugin

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
)

type ShouldEnforcePluginOpts struct {
	Plugin    *corev1.Service_Spec_Config_HTTP_Plugin
	CELEngine *celengine.CELEngine
	Phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
}

func ShouldEnforcePlugin(ctx context.Context, o *ShouldEnforcePluginOpts) bool {
	plugin := o.Plugin
	if plugin == nil {
		return false
	}

	if plugin.IsDisabled {
		return false
	}

	if !matchesPhase(plugin, o.Phase) {
		return false
	}

	cond := o.Plugin.Condition
	if cond == nil {
		return false
	}

	reqCtx := middlewares.GetCtxRequestContext(ctx)

	var reqCtxMap map[string]any
	if reqCtx.ReqCtxMap == nil {
		reqCtx.ReqCtxMap = pbutils.MustConvertToMap(reqCtx.DownstreamInfo)
	}

	reqCtxMap = reqCtx.ReqCtxMap

	inputMap := map[string]any{
		"ctx": reqCtxMap,
	}

	isMatched, _ := o.CELEngine.EvalCondition(ctx, cond, inputMap)

	return isMatched
}

func matchesPhase(plugin *corev1.Service_Spec_Config_HTTP_Plugin, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) bool {
	switch phase {
	case corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH:
		return plugin.Phase == corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH
	case corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH:
		switch plugin.Phase {
		case corev1.Service_Spec_Config_HTTP_Plugin_PHASE_UNSET, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH:
			return true
		default:
			return false
		}
	default:
		zap.L().Warn("Middleware Phase is unset. This should not happen in production")
		return false
	}
}
