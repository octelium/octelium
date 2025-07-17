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
)

type ShouldEnforcePluginOpts struct {
	Plugin    *corev1.Service_Spec_Config_HTTP_Plugin
	CELEngine *celengine.CELEngine
}

func ShouldEnforcePlugin(ctx context.Context, o *ShouldEnforcePluginOpts) bool {
	rules := o.Plugin.Rules

	if len(rules) == 0 {
		return true
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

	for _, rule := range rules {
		isMatched, err := o.CELEngine.EvalCondition(ctx, rule.Condition, inputMap)
		if err != nil {
			continue
		}

		if isMatched {
			switch rule.Effect {
			case corev1.Service_Spec_Config_HTTP_Plugin_Rule_IGNORE:
				return false
			case corev1.Service_Spec_Config_HTTP_Plugin_Rule_ENFORCE:
				return true
			}
		}
	}

	return true
}

func MatchesPhase(plugin *corev1.Service_Spec_Config_HTTP_Plugin, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) bool {
	switch phase {
	case corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH:
		if plugin.Phase != corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH {
			return false
		}
	case corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH:
		switch plugin.Phase {
		case corev1.Service_Spec_Config_HTTP_Plugin_PHASE_UNSET, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH:
		default:
			return false
		}
	}
	return true
}
