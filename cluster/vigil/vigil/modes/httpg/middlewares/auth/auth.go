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

package auth

import (
	"context"
	"net/http"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/vigilutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
)

type middleware struct {
	octeliumC  octeliumc.ClientInterface
	octovigilC *octovigilc.Client
	next       http.Handler
	domain     string
	celEngine  *celengine.CELEngine
}

func New(ctx context.Context, next http.Handler, octeliumC octeliumc.ClientInterface, octovigilC *octovigilc.Client, domain string) (http.Handler, error) {

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	if err != nil {
		return nil, err
	}

	return &middleware{
		next:       next,
		octeliumC:  octeliumC,
		octovigilC: octovigilC,
		domain:     domain,
		celEngine:  celEngine,
	}, nil
}

func (m *middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	var err error

	if httputils.IsAnonymousMode(req) {
		if reqCtx.AuthResponse == nil {
			// AuthResponse is already set by preauth
			reqCtx.AuthResponse = &coctovigilv1.AuthenticateAndAuthorizeResponse{
				IsAuthorized: true,
			}
		}
		m.setServiceConfig(ctx, reqCtx)
		// reqCtx.ServiceConfig = vigilutils.GetServiceConfig(ctx, reqCtx.AuthResponse)
		// Already set by preauth
		// reqCtx.IsAuthorized = true
		m.next.ServeHTTP(w, req)
		return
	}

	auth, err := m.octovigilC.AuthenticateAndAuthorize(ctx, &octovigilc.AuthenticateAndAuthorizeRequest{
		Request: reqCtx.DownstreamRequest,
	})
	if err != nil {
		if grpcerr.IsCanceled(err) ||
			grpcerr.IsDeadlineExceeded(err) ||
			grpcerr.IsResourceChanged(err) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		zap.L().Error("Could not do AuthenticateAndAuthorize", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	reqCtx.IsAuthenticated = auth.IsAuthenticated
	reqCtx.IsAuthorized = auth.IsAuthorized
	reqCtx.DownstreamInfo = auth.RequestContext
	reqCtx.DecisionReason = auth.AuthorizationDecisionReason
	reqCtx.AuthResponse = auth
	reqCtx.ServiceConfig = vigilutils.GetServiceConfig(ctx, auth)

	reqCtx.ReqCtxMap = pbutils.MustConvertToMap(reqCtx.DownstreamInfo)

	if !reqCtx.IsAuthorized {
		m.handleUnauthorized(w, req, reqCtx)
		return
	}

	m.next.ServeHTTP(w, req)
}

/*
type additionalInfo struct {
	Body       []byte
	IsBodyJSON bool
	bodyMap    map[string]any
}

func (m *middleware) getDownstreamReq(req *http.Request,
	reqCtx *middlewares.RequestContext,
	additional *additionalInfo) (*coctovigilv1.DownstreamRequest, error) {

	c := reqCtx.Conn
	svc := reqCtx.Service

	httpC := &corev1.RequestContext_Request_HTTP{
		Headers: httputils.GetHeaders(req.Header),
		Host:    req.Host,
		Method:  req.Method,
		Scheme:  req.URL.Scheme,
		Size:    req.ContentLength,
		Path:    req.URL.Path,
		Uri:     req.URL.RequestURI(),
		Body:    additional.Body,
	}

	if additional.bodyMap != nil {
		httpC.BodyMap, _ = pbutils.MapToStruct(additional.bodyMap)
	}

	if qry := req.URL.Query(); len(qry) > 0 {
		httpC.QueryParams = make(map[string]string)
		for k, v := range qry {
			if len(v) > 0 {
				httpC.QueryParams[k] = v[0]
			}
		}
	}

	switch {
	case ucorev1.ToService(svc).IsKubernetes():
		k8sReq, err := httputils.ParseKubernetesRequest(req)
		if err != nil {
			return nil, err
		}

		return &coctovigilv1.DownstreamRequest{
			Source: vigilutils.GetDownstreamRequestSource(c),
			Request: &corev1.RequestContext_Request{
				Type: &corev1.RequestContext_Request_Kubernetes_{
					Kubernetes: &corev1.RequestContext_Request_Kubernetes{
						Http:        httpC,
						Verb:        k8sReq.Verb,
						ApiPrefix:   k8sReq.APIPrefix,
						ApiGroup:    k8sReq.APIGroup,
						ApiVersion:  k8sReq.APIVersion,
						Namespace:   k8sReq.Namespace,
						Resource:    k8sReq.Resource,
						Subresource: k8sReq.Subresource,
						Name:        k8sReq.Name,
					},
				},
			},
		}, nil
	case ucorev1.ToService(svc).IsGRPC():
		info, err := httputils.GetGRPCInfo(req.URL.Path)
		if err != nil {
			return nil, err
		}
		return &coctovigilv1.DownstreamRequest{
			Source: vigilutils.GetDownstreamRequestSource(c),
			Request: &corev1.RequestContext_Request{
				Type: &corev1.RequestContext_Request_Grpc{
					Grpc: &corev1.RequestContext_Request_GRPC{
						Http:            httpC,
						Service:         info.Service,
						ServiceFullName: info.FullServiceName,
						Method:          info.Method,
						Package:         info.Package,
					},
				},
			},
		}, nil
	default:
		return &coctovigilv1.DownstreamRequest{
			Source: vigilutils.GetDownstreamRequestSource(c),
			Request: &corev1.RequestContext_Request{
				Type: &corev1.RequestContext_Request_Http{
					Http: httpC,
				},
			},
		}, nil
	}
}

*/

func (s *middleware) setServiceConfig(ctx context.Context, req *middlewares.RequestContext) {

	reqCtx := req.DownstreamInfo
	svc := reqCtx.Service
	if svc.Spec.DynamicConfig == nil || len(svc.Spec.DynamicConfig.Rules) < 1 {
		return
	}

	reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
	if err != nil {
		return
	}

	inputMap := map[string]any{
		"ctx": reqCtxMap,
	}

	for _, rule := range svc.Spec.DynamicConfig.Rules {
		isMatch, err := s.celEngine.EvalCondition(ctx, rule.Condition, inputMap)
		if err != nil {
			continue
		}
		if isMatch {
			switch rule.Type.(type) {
			case *corev1.Service_Spec_DynamicConfig_Rule_ConfigName:
				req.AuthResponse.ServiceConfigName = rule.GetConfigName()
				vigilutils.GetServiceConfig(ctx, req.AuthResponse)
				return
			case *corev1.Service_Spec_DynamicConfig_Rule_Eval:
				if cfgMap, err := s.celEngine.EvalPolicyMapStrAny(ctx, rule.GetEval(), inputMap); err == nil {
					cfg := &corev1.Service_Spec_Config{}
					if err := pbutils.UnmarshalFromMap(cfgMap, cfg); err == nil {
						req.AuthResponse.ServiceConfigName = rule.GetConfigName()
						vigilutils.GetServiceConfig(ctx, req.AuthResponse)
						return
					}
				}
			}
		}
	}
}
