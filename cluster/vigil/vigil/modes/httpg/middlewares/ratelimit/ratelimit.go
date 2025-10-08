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

package ratelimit

import (
	"context"
	"fmt"
	"net/http"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rratelimitv1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
)

type middleware struct {
	next      http.Handler
	phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
	celEngine *celengine.CELEngine
	octeliumC octeliumc.ClientInterface
}

func New(ctx context.Context,
	next http.Handler, celEngine *celengine.CELEngine,
	octeliumC octeliumc.ClientInterface,
	phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) (http.Handler, error) {
	return &middleware{
		next:      next,
		phase:     phase,
		celEngine: celEngine,
		octeliumC: octeliumC,
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	ctx := req.Context()

	reqCtx := middlewares.GetCtxRequestContext(ctx)
	cfg := reqCtx.ServiceConfig

	if cfg == nil || cfg.GetHttp() == nil || len(cfg.GetHttp().Plugins) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	for _, plugin := range cfg.GetHttp().Plugins {
		switch plugin.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_:

			if !commonplugin.ShouldEnforcePlugin(ctx, &commonplugin.ShouldEnforcePluginOpts{
				Plugin:    plugin,
				CELEngine: m.celEngine,
				Phase:     m.phase,
			}) {
				continue
			}

			rateLimit := plugin.GetRateLimit()

			key := m.getKey(ctx, plugin.Name, rateLimit, reqCtx)
			if key == "" {
				continue
			}

			resp, err := m.octeliumC.RateLimitC().CheckSlidingWindow(ctx,
				&rratelimitv1.CheckSlidingWindowRequest{
					Key:    vutils.Sha256Sum([]byte(key)),
					Window: rateLimit.Window,
					Limit:  rateLimit.Limit,
				})
			if err != nil {
				if grpcerr.IsInternal(err) {
					zap.L().Warn("CheckSlidingWindow error", zap.Error(err))
				}
				continue
			}

			if resp.IsAllowed {
				continue
			}

			for k, v := range rateLimit.Headers {
				rw.Header().Set(k, v)
			}
			rw.Header().Set("Server", "octelium")

			if rateLimit.StatusCode >= 200 && rateLimit.StatusCode < 600 {
				rw.WriteHeader(int(rateLimit.StatusCode))
			} else {
				rw.WriteHeader(http.StatusTooManyRequests)
			}

			body := rateLimit.Body

			if body != nil {
				switch body.Type.(type) {
				case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Body_Inline:
					rw.Write([]byte(body.GetInline()))
				case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Body_InlineBytes:
					rw.Write(body.GetInlineBytes())
				}
			}
			return
		default:
			continue
		}
	}

	m.next.ServeHTTP(rw, req)
}

func (m *middleware) getKey(ctx context.Context, name string,
	rateLimit *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit,
	reqCtx *middlewares.RequestContext) string {
	var sessionUID string
	if reqCtx.DownstreamInfo != nil && reqCtx.DownstreamInfo.Session != nil {
		sessionUID = reqCtx.DownstreamInfo.Session.Metadata.Uid
	}

	if rateLimit.Key == nil {
		return sessionUID
	}

	defaultKey := fmt.Sprintf("%s:%s", name, sessionUID)

	switch rateLimit.Key.Type.(type) {
	case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_Eval:
		key, err := m.celEngine.EvalPolicyString(ctx, rateLimit.Key.GetEval(), reqCtx.ReqCtxMap)
		if err == nil && key != "" {
			return key
		}
	case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_PerSession:
	case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_PerUser:
		if reqCtx.DownstreamInfo != nil && reqCtx.DownstreamInfo.User != nil {
			return reqCtx.DownstreamInfo.User.Metadata.Uid
		}
	}

	return defaultKey
}
