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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/vigilutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
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
	svc := reqCtx.Service

	var err error

	additional := &additionalInfo{}

	if svc.Spec.Config != nil && svc.Spec.Config.GetHttp() != nil && svc.Spec.Config.GetHttp().EnableRequestBuffering {
		additional.Body, err = io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		req.Body.Close()

		reqCtx.Body = additional.Body

		if svc.Spec.Config != nil && svc.Spec.Config.GetHttp() != nil && svc.Spec.Config.GetHttp().Body != nil {
			buffer := svc.Spec.Config.GetHttp().Body

			if buffer.MaxRequestSize > 0 && len(additional.Body) > int(buffer.MaxRequestSize) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}

			switch buffer.Mode {
			case corev1.Service_Spec_Config_HTTP_Body_JSON:
				additional.bodyMap = make(map[string]any)
				if err := json.Unmarshal(additional.Body, &additional.bodyMap); err != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				reqCtx.BodyJSONMap = additional.bodyMap
			}
		}

		req.Body = io.NopCloser(bytes.NewReader(additional.Body))
	}

	reqCtx = middlewares.GetCtxRequestContext(ctx)

	downstreamReq, err := m.getDownstreamReq(req, reqCtx, additional)
	if err != nil {
		zap.L().Debug("Could not get downstreamReq", zap.Error(err))
		if ucorev1.ToService(reqCtx.Service).IsGRPC() {
			w.Header().Set("Grpc-Status", fmt.Sprintf("%d", codes.Unimplemented))
			w.Header().Set("Grpc-Message", "Octelium: unimplemented")
			w.Header().Set("Content-Type", "application/grpc")
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}

		return
	}

	if httputils.IsAnonymousMode(req) {
		reqCtx.DownstreamInfo = &corev1.RequestContext{
			Request: downstreamReq.Request,
			Service: svc,
		}
		reqCtx.AuthResponse = &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext:    reqCtx.DownstreamInfo,
			IsAuthorized:      true,
			ServiceConfigName: m.getServiceConfigName(ctx, reqCtx.DownstreamInfo),
		}
		reqCtx.IsAuthorized = true
		reqCtx.ServiceConfig = vigilutils.GetServiceConfig(ctx, reqCtx.AuthResponse)

		m.next.ServeHTTP(w, req)
		return
	}

	auth, err := m.octovigilC.AuthenticateAndAuthorize(ctx, &octovigilc.AuthenticateAndAuthorizeRequest{
		Request: downstreamReq,
	})
	if err != nil {
		zap.L().Error("Could not do AuthenticateAndAuthorize", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// zap.L().Debug("Auth response", zap.Any("resp", auth))

	reqCtx.IsAuthenticated = auth.IsAuthenticated
	reqCtx.IsAuthorized = auth.IsAuthorized
	reqCtx.DownstreamInfo = auth.RequestContext
	reqCtx.DecisionReason = auth.AuthorizationDecisionReason
	reqCtx.AuthResponse = auth
	reqCtx.ServiceConfig = vigilutils.GetServiceConfig(ctx, auth)

	// zap.L().Debug("New request", zap.Any("reqCtx", reqCtx))

	if !reqCtx.IsAuthorized {
		m.handleUnauthorized(w, req, reqCtx)
		return
	}

	m.next.ServeHTTP(w, req)
}

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

func (s *middleware) getServiceConfigName(ctx context.Context, reqCtx *corev1.RequestContext) string {
	svc := reqCtx.Service
	if svc.Spec.DynamicConfig == nil || len(svc.Spec.DynamicConfig.Rules) < 1 {
		return ""
	}

	reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
	if err != nil {
		return ""
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
			return rule.ConfigName
		}
	}

	return ""
}
