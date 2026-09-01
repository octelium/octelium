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
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
)

type ShouldEnforcePluginOpts struct {
	Plugin    ucorev1.HTTPPlugin
	CELEngine *celengine.CELEngine
	Phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
}

func ShouldEnforcePlugin(ctx context.Context, o *ShouldEnforcePluginOpts) bool {
	isMatched, err := ShouldEnforcePluginErr(ctx, o)
	if err != nil {
		return false
	}
	return isMatched
}

func ShouldEnforcePluginErr(ctx context.Context, o *ShouldEnforcePluginOpts) (bool, error) {
	plugin := o.Plugin
	if plugin == nil {
		return false, nil
	}

	if plugin.GetIsDisabled() {
		return false, nil
	}

	if !matchesPhase(plugin, o.Phase) {
		return false, nil
	}

	cond := plugin.GetCondition()
	if cond == nil {
		return false, nil
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

	isMatched, err := o.CELEngine.EvalCondition(ctx, cond, inputMap)
	if err != nil {
		zap.L().Error("Could not eval plugin condition", zap.Any("condition", cond))
		return false, err
	}

	return isMatched, nil
}

func matchesPhase(plugin ucorev1.HTTPPlugin, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) bool {
	switch phase {
	case corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH:
		return plugin.GetPhase() == corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH
	case corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH:
		switch plugin.GetPhase() {
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
