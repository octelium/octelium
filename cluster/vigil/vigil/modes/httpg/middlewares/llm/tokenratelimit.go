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
	"fmt"
	"net/http"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rratelimitv1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
)

const (
	reservationIDBytes   = 16
	maxReservationTokens = 1 << 48
	reconcileTimeout     = 10 * time.Second
)

type tokenRateLimit struct {
	next      http.Handler
	celEngine *celengine.CELEngine
	octeliumC octeliumc.ClientInterface
	svcUID    string
}

func NewTokenRateLimit(ctx context.Context, next http.Handler,
	celEngine *celengine.CELEngine, octeliumC octeliumc.ClientInterface,
	svcUID string) (http.Handler, error) {
	return &tokenRateLimit{
		next:      next,
		celEngine: celEngine,
		octeliumC: octeliumC,
		svcUID:    svcUID,
	}, nil
}

type reservation struct {
	cfg    *corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit
	key    []byte
	id     []byte
	amount int64
}

func (m *tokenRateLimit) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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

	var reservations []*reservation

	for _, plugin := range plugins {
		cfg := plugin.GetTokenRateLimit()
		if cfg == nil {
			continue
		}

		isEnforced, ok := shouldEnforcePlugin(ctx, &enforcePluginOpts{
			w:         w,
			reqCtx:    reqCtx,
			celEngine: m.celEngine,
			plugin:    plugin,
			errCode:   ErrCodeTokenRateLimit,
		})
		if !ok {
			m.release(ctx, reservations)
			return
		}
		if !isEnforced {
			continue
		}

		res, isAllowed := m.reserve(ctx, reqCtx, plugin.GetName(), cfg)
		if !isAllowed {
			m.release(ctx, reservations)
			m.writeDenied(w, reqCtx, cfg)
			return
		}
		if res != nil {
			reservations = append(reservations, res)
		}
	}

	if len(reservations) > 0 {
		reqCtx.AddOnResponse(func() {
			m.reconcile(ctx, reqCtx, reservations)
		})
	}

	m.next.ServeHTTP(w, req)
}

func (m *tokenRateLimit) reserve(ctx context.Context,
	reqCtx *middlewares.RequestContext, name string,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit) (*reservation, bool) {

	ret := &reservation{
		cfg:    cfg,
		key:    m.getKey(ctx, name, cfg.GetKey(), reqCtx),
		id:     utilrand.GetRandomBytesMust(reservationIDBytes),
		amount: getReservedTokens(reqCtx, cfg),
	}

	resp, err := m.octeliumC.RateLimitC().ReserveSlidingWindow(ctx,
		&rratelimitv1.ReserveSlidingWindowRequest{
			Key:    ret.key,
			Window: cfg.GetWindow(),
			Limit:  cfg.GetLimit(),
			Id:     ret.id,
			Amount: ret.amount,
		})
	if err != nil {
		if grpcerr.IsInternal(err) {
			zap.L().Warn("ReserveSlidingWindow error", zap.Error(err))
		}
		return nil, true
	}

	if !resp.IsAllowed {
		return nil, false
	}

	return ret, true
}

func (m *tokenRateLimit) reconcile(ctx context.Context,
	reqCtx *middlewares.RequestContext, reservations []*reservation) {

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reconcileTimeout)
	defer cancel()

	for _, res := range reservations {
		amount, ok := getReconciledTokens(reqCtx, res)
		if !ok {
			continue
		}

		m.setReservation(ctx, res, amount)
	}
}

func (m *tokenRateLimit) release(ctx context.Context, reservations []*reservation) {
	for _, res := range reservations {
		m.setReservation(ctx, res, 0)
	}
}

func (m *tokenRateLimit) setReservation(ctx context.Context,
	res *reservation, amount int64) {

	if _, err := m.octeliumC.RateLimitC().ReconcileSlidingWindow(ctx,
		&rratelimitv1.ReconcileSlidingWindowRequest{
			Key:    res.key,
			Window: res.cfg.GetWindow(),
			Id:     res.id,
			Amount: amount,
		}); err != nil {
		if grpcerr.IsInternal(err) {
			zap.L().Warn("ReconcileSlidingWindow error", zap.Error(err))
		}
	}
}

func (m *tokenRateLimit) getKey(ctx context.Context, name string,
	key *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key,
	reqCtx *middlewares.RequestContext) []byte {

	var ret string
	if reqCtx.DownstreamInfo != nil && reqCtx.DownstreamInfo.Session != nil {
		ret = reqCtx.DownstreamInfo.Session.Metadata.Uid
	}

	if key != nil {
		switch key.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_Eval:
			if reqCtx.ReqCtxMap == nil {
				reqCtx.SetReqCtxMap()
			}
			res, err := m.celEngine.EvalPolicyString(ctx, key.GetEval(), map[string]any{
				"ctx": reqCtx.ReqCtxMap,
			})
			if err == nil && res != "" {
				ret = res
			}
		case *corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_PerUser:
			if reqCtx.DownstreamInfo != nil && reqCtx.DownstreamInfo.User != nil {
				ret = reqCtx.DownstreamInfo.User.Metadata.Uid
			}
		}
	}

	return vutils.Sha256Sum([]byte(fmt.Sprintf("%s:%s:%s", m.svcUID, name, ret)))
}

func (m *tokenRateLimit) writeDenied(w http.ResponseWriter,
	reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit) {

	for _, hdr := range cfg.GetHeaders() {
		w.Header().Set(hdr.Key, hdr.Value)
	}

	WriteError(w, &WriteErrorOpts{
		Protocol:   reqCtx.LLM.GetProtocol(),
		HTTPStatus: http.StatusTooManyRequests,
		Type:       ErrTypeRateLimit,
		Code:       ErrCodeTokenRateLimit,
		Message:    tokenRateLimitDenyMessage(cfg),
	})
}

func getReservedTokens(reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit) int64 {

	switch cfg.GetScope() {
	case corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_INPUT:
		return toTokenAmount(reqCtx.LLM.GetEstimatedInputTokens())
	case corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_OUTPUT:
		return toTokenAmount(getReservedOutputTokens(reqCtx, cfg))
	default:
		return toTokenAmount(reqCtx.LLM.GetEstimatedInputTokens()) +
			toTokenAmount(getReservedOutputTokens(reqCtx, cfg))
	}
}

func getReservedOutputTokens(reqCtx *middlewares.RequestContext,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit) uint64 {

	if ret := reqCtx.LLM.GetMaxOutputTokens(); ret > 0 {
		return ret
	}

	return cfg.GetDefaultOutputTokens()
}

func getReconciledTokens(reqCtx *middlewares.RequestContext,
	res *reservation) (int64, bool) {

	if reqCtx.LLMResponse == nil {
		return 0, false
	}

	switch reqCtx.LLMResponse.UsageSource {
	case corev1.AccessLog_Entry_Info_LLM_Usage_PROVIDER:
		return getUsageTokens(reqCtx.LLMResponse, res.cfg), true
	case corev1.AccessLog_Entry_Info_LLM_Usage_PARTIAL:
		return max(res.amount, getUsageTokens(reqCtx.LLMResponse, res.cfg)), true
	case corev1.AccessLog_Entry_Info_LLM_Usage_SOURCE_UNSET:
		return 0, true
	default:
		return 0, false
	}
}

func getUsageTokens(resp *middlewares.LLMResponseInfo,
	cfg *corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit) int64 {

	switch cfg.GetScope() {
	case corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_INPUT:
		if resp.Usage.TotalTokens < resp.Usage.OutputTokens {
			return 0
		}
		return toTokenAmount(resp.Usage.TotalTokens - resp.Usage.OutputTokens)
	case corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit_OUTPUT:
		return toTokenAmount(resp.Usage.OutputTokens)
	default:
		return toTokenAmount(resp.Usage.TotalTokens)
	}
}

func toTokenAmount(arg uint64) int64 {
	if arg > maxReservationTokens {
		return maxReservationTokens
	}
	return int64(arg)
}

func tokenRateLimitDenyMessage(
	cfg *corev1.Service_Spec_Config_LLM_Plugin_TokenRateLimit) string {
	if msg := cfg.GetDenyMessage(); msg != "" {
		return msg
	}
	return "Octelium: the token rate limit of this Service is exceeded"
}
