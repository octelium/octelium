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
	"math"
	"net/http"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
	"go.uber.org/zap"
)

const (
	maxPluginRecords     = 32
	maxPluginRecordRules = 16
	maxPluginRecordTools = 32
)

type pluginRecord struct {
	name    string
	typ     corev1.AccessLog_Entry_Info_LLM_Plugin_Type
	outcome corev1.AccessLog_Entry_Info_LLM_Plugin_Outcome

	rules      []string
	matchCount uint32

	injectedBytes uint32
	removedTools  []string

	duration time.Duration
}

func appendPluginRecord(reqCtx *middlewares.RequestContext, rec *pluginRecord) {
	if rec == nil || reqCtx == nil {
		return
	}

	if len(reqCtx.LLMPluginRecords) >= maxPluginRecords {
		return
	}

	ret := &corev1.AccessLog_Entry_Info_LLM_Plugin{
		Name:          rec.name,
		Type:          rec.typ,
		Outcome:       rec.outcome,
		MatchCount:    rec.matchCount,
		InjectedBytes: rec.injectedBytes,
	}

	if len(rec.rules) > 0 {
		ret.Rules = boundStrings(rec.rules, maxPluginRecordRules)
	}
	if len(rec.removedTools) > 0 {
		ret.RemovedTools = boundStrings(rec.removedTools, maxPluginRecordTools)
	}
	if ms := rec.duration.Milliseconds(); ms > 0 && ms <= math.MaxUint32 {
		ret.Duration = &metav1.Duration{
			Type: &metav1.Duration_Milliseconds{
				Milliseconds: uint32(ms),
			},
		}
	}

	reqCtx.LLMPluginRecords = append(reqCtx.LLMPluginRecords, ret)
}

type enforcePluginOpts struct {
	w         http.ResponseWriter
	reqCtx    *middlewares.RequestContext
	celEngine *celengine.CELEngine
	plugin    *corev1.Service_Spec_Config_LLM_Plugin
	typ       corev1.AccessLog_Entry_Info_LLM_Plugin_Type
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

	appendPluginRecord(o.reqCtx, &pluginRecord{
		name:    o.plugin.GetName(),
		typ:     o.typ,
		outcome: corev1.AccessLog_Entry_Info_LLM_Plugin_FAILED,
	})

	WriteError(o.w, &WriteErrorOpts{
		Protocol:   o.reqCtx.LLM.GetProtocol(),
		HTTPStatus: http.StatusInternalServerError,
		Type:       ErrTypeAPI,
		Code:       o.errCode,
		Message:    "Octelium: could not evaluate the Plugins of this Service",
	})

	return false, false
}

func boundStrings(args []string, maxLen int) []string {
	if len(args) <= maxLen {
		return args
	}
	return args[:maxLen]
}
