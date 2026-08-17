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

package headers

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/llm"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
)

type middleware struct {
	next      http.Handler
	secretMan *secretman.SecretManager
	celEngine *celengine.CELEngine
}

func New(ctx context.Context,
	next http.Handler, celEngine *celengine.CELEngine, secretMan *secretman.SecretManager) (http.Handler, error) {
	return &middleware{
		next:      next,
		secretMan: secretMan,
		celEngine: celEngine,
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqCtx := middlewares.GetCtxRequestContext(req.Context())
	if isPreflight := m.processCORSHeaders(rw, req, reqCtx); isPreflight {
		return
	}

	if err := m.setRequestHeaders(req, reqCtx); err != nil {
		zap.L().Warn("Could not setRequestHeaders", zap.Error(err))
		llm.WriteError(rw, &llm.WriteErrorOpts{
			Protocol:   reqCtx.LLM.GetProtocol(),
			HTTPStatus: http.StatusBadGateway,
			Type:       llm.ErrTypeAPI,
			Code:       llm.ErrCodeUpstreamAuth,
			Message:    "Octelium: could not set the upstream provider credentials",
		})
		return
	}

	crw := &responseWriter{
		ResponseWriter: rw,
		modify: func(hdr http.Header) {
			m.modifyResponseHeaders(hdr, req, reqCtx)
		},
	}

	m.next.ServeHTTP(crw, req)

	if !crw.wroteHeader && !crw.hijacked {
		m.modifyResponseHeaders(rw.Header(), req, reqCtx)
	}
}

type responseWriter struct {
	http.ResponseWriter
	modify      func(http.Header)
	wroteHeader bool
	hijacked    bool
}

func (w *responseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.modify(w.ResponseWriter.Header())
	}

	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	return w.ResponseWriter.Write(b)
}

func (w *responseWriter) Flush() {
	if !w.wroteHeader && !w.hijacked {
		w.WriteHeader(http.StatusOK)
	}

	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}

	conn, brw, err := hj.Hijack()
	if err == nil {
		w.hijacked = true
	}

	return conn, brw, err
}

func (w *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}

	return http.ErrNotSupported
}

func (m *middleware) setRequestHeaders(req *http.Request, reqCtx *middlewares.RequestContext) error {
	ctx := req.Context()

	svc := reqCtx.Service
	svcCfg := reqCtx.ServiceConfig
	isManagedSvc := ucorev1.ToService(svc).IsManagedService()
	isAnonymous := svc.Spec.IsAnonymous
	isLLM := ucorev1.ToService(svc).IsLLM()

	req.Header.Del("X-Request-Id")

	scrubOcteliumRequestHeaders(req, isManagedSvc)

	if isLLM {
		scrubLLMCredentialHeaders(req)
	}

	inputMap := reqCtx.ReqCtxMap

	if cfg := ucorev1.ToServiceConfig(svcCfg).GetHTTPHeader(); cfg != nil {

		switch cfg.AuthorizationMode {
		case corev1.Service_Spec_Config_HTTP_Header_AUTHORIZATION_MODE_UNSET:
			switch {
			case isAnonymous || isManagedSvc:
			default:
				req.Header.Del("Authorization")
			}
		case corev1.Service_Spec_Config_HTTP_Header_PASS:
		case corev1.Service_Spec_Config_HTTP_Header_DELETE:
			req.Header.Del("Authorization")
		}

		for _, hdr := range cfg.AddRequestHeaders {
			if hdr.Append {
				switch hdr.Type.(type) {
				case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value:
					req.Header.Add(hdr.Key, hdr.GetValue())
				case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Eval:
					val, _ := m.celEngine.EvalPolicyString(ctx, hdr.GetEval(), inputMap)
					req.Header.Add(hdr.Key, val)
				}

			} else {
				switch hdr.Type.(type) {
				case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value:
					req.Header.Set(hdr.Key, hdr.GetValue())
				case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Eval:
					val, _ := m.celEngine.EvalPolicyString(ctx, hdr.GetEval(), inputMap)
					req.Header.Set(hdr.Key, val)
				}
			}
		}

		for _, hdr := range cfg.RemoveRequestHeaders {
			req.Header.Del(hdr)
		}
	} else {
		switch {
		case isAnonymous || isManagedSvc:
		default:
			req.Header.Del("Authorization")
		}
	}

	if svcCfg != nil &&
		ucorev1.ToServiceConfig(svcCfg).GetHTTPAuth() != nil {
		authS := ucorev1.ToServiceConfig(svcCfg).GetHTTPAuth()

		if authS.GetBearer() != nil &&
			authS.GetBearer().GetFromSecret() != "" {
			secret, err := m.secretMan.GetByName(ctx, authS.GetBearer().GetFromSecret())
			if err == nil {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ucorev1.ToSecret(secret).GetValueStr()))
			} else {
				zap.L().Warn("Could not get Bearer Secret",
					zap.String("secretName", authS.GetBearer().GetFromSecret()), zap.Error(err))
				if isLLM {
					return err
				}
			}
		} else if authS.GetBasic() != nil &&
			authS.GetBasic().GetPassword() != nil && authS.GetBasic().GetPassword().GetFromSecret() != "" {
			secret, err := m.secretMan.GetByName(ctx, authS.GetBasic().GetPassword().GetFromSecret())
			if err == nil {
				authVal := base64.StdEncoding.EncodeToString(
					[]byte(fmt.Sprintf("%s:%s",
						authS.GetBasic().Username, ucorev1.ToSecret(secret).GetValueStr())))
				req.Header.Set("Authorization", fmt.Sprintf("Basic %s", authVal))
			} else {
				zap.L().Warn("Could not get Basic Secret",
					zap.String("secretName", authS.GetBasic().GetPassword().GetFromSecret()), zap.Error(err))
				if isLLM {
					return err
				}
			}
		} else if authS.GetCustom() != nil &&
			authS.GetCustom().GetValue() != nil && authS.GetCustom().GetValue().GetFromSecret() != "" {
			secret, err := m.secretMan.GetByName(ctx, authS.GetCustom().GetValue().GetFromSecret())
			if err == nil {
				req.Header.Set(authS.GetCustom().Header, ucorev1.ToSecret(secret).GetValueStr())
			} else {
				zap.L().Warn("Could not get Custom Auth Secret",
					zap.String("secretName", authS.GetCustom().GetValue().GetFromSecret()), zap.Error(err))
				if isLLM {
					return err
				}
			}
		} else if authS.GetOauth2ClientCredentials() != nil &&
			authS.GetOauth2ClientCredentials().GetClientSecret() != nil &&
			authS.GetOauth2ClientCredentials().GetClientSecret().GetFromSecret() != "" {
			cc := authS.GetOauth2ClientCredentials()
			accessToken, err := m.secretMan.GetOAuth2CCToken(ctx, &secretman.GetOAuth2CCTokenReq{
				ClientID:   cc.ClientID,
				SecretName: cc.GetClientSecret().GetFromSecret(),
				TokenURL:   cc.TokenURL,
				Scopes:     cc.Scopes,
			})
			if err == nil {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
			} else {
				zap.L().Warn("Could not get oauth2 client credentials access token", zap.Error(err))
				if isLLM {
					return err
				}
			}
		}
	}

	if !isAnonymous && isManagedSvc &&
		reqCtx.DownstreamInfo != nil && reqCtx.DownstreamInfo.Session != nil {
		if sessionRefBytes, err := pbutils.MarshalJSON(umetav1.GetObjectReference(reqCtx.DownstreamInfo.Session), false); err == nil {
			req.Header.Set("X-Octelium-Session-Ref", string(sessionRefBytes))
		}

		req.Header.Set("X-Octelium-Session-Uid", reqCtx.DownstreamInfo.Session.Metadata.Uid)
		req.Header.Set("X-Octelium-Req-Path", req.URL.Path)
	}

	if isManagedSvc {
		if val := req.Header.Get("Origin"); val != "" {
			req.Header.Set("X-Octelium-Origin", val)
		}
	}

	if ucorev1.ToService(svc).IsKubernetes() && svcCfg != nil && svcCfg.GetKubernetes() != nil {
		kCfg := svcCfg.GetKubernetes()
		switch {
		case kCfg.GetBearerToken() != nil && kCfg.GetBearerToken().GetFromSecret() != "":
			if tknSecret, err := m.secretMan.GetByName(ctx,
				kCfg.GetBearerToken().GetFromSecret()); err == nil {
				req.Header.Set("Authorization",
					fmt.Sprintf("Bearer %s", ucorev1.ToSecret(tknSecret).GetValueStr()))
			}
		case kCfg.GetKubeconfig() != nil && kCfg.GetKubeconfig().GetFromSecret() != "":
			if kubeConfigSecret, err := m.secretMan.GetByName(ctx, kCfg.GetKubeconfig().GetFromSecret()); err == nil {
				if kubeconfig, err := k8sutils.UnmarshalKubeConfigFromYAML(
					ucorev1.ToSecret(kubeConfigSecret).GetValueBytes()); err == nil {
					if usr := kubeconfig.GetUser(
						kCfg.GetKubeconfig().Context); usr != nil && usr.User.Token != "" {
						req.Header.Set("Authorization",
							fmt.Sprintf("Bearer %s", usr.User.Token))
					}
				}
			}
		}
	}

	return nil
}

var llmCredentialHeaders = []string{
	"Authorization",
	"X-Api-Key",
	"Api-Key",
}

func scrubLLMCredentialHeaders(req *http.Request) {
	for _, hdr := range llmCredentialHeaders {
		req.Header.Del(hdr)
	}
}

func (m *middleware) processCORSHeaders(rw http.ResponseWriter, req *http.Request, reqCtx *middlewares.RequestContext) bool {
	svcCfg := reqCtx.ServiceConfig

	cors := ucorev1.ToServiceConfig(svcCfg).GetHTTPCors()
	if cors == nil {
		return false
	}

	reqAcMethod := req.Header.Get("Access-Control-Request-Method")
	originHeader := req.Header.Get("Origin")

	if reqAcMethod != "" && originHeader != "" && req.Method == http.MethodOptions {
		if cors.AllowCredentials {
			rw.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if cors.AllowHeaders != "" {
			rw.Header().Set("Access-Control-Allow-Headers", cors.AllowHeaders)
		}

		if cors.AllowMethods != "" {
			rw.Header().Set("Access-Control-Allow-Methods", cors.AllowMethods)
		}

		allowed, match := m.isOriginAllowed(originHeader, cors.AllowOriginStringMatch)
		if allowed {
			rw.Header().Set("Access-Control-Allow-Origin", match)
		}

		if cors.MaxAge != "" {
			rw.Header().Set("Access-Control-Max-Age", cors.MaxAge)
		}

		return true
	}

	return false
}

func (m *middleware) modifyResponseHeaders(rwHdr http.Header, req *http.Request, reqCtx *middlewares.RequestContext) {
	svcCfg := reqCtx.ServiceConfig

	ctx := req.Context()
	inputMap := reqCtx.ReqCtxMap

	if cfg := ucorev1.ToServiceConfig(svcCfg).GetHTTPHeader(); cfg != nil {
		for _, hdr := range cfg.AddResponseHeaders {
			if hdr.Append {
				switch hdr.Type.(type) {
				case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value:
					rwHdr.Add(hdr.Key, hdr.GetValue())
				case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Eval:
					val, _ := m.celEngine.EvalPolicyString(ctx, hdr.GetEval(), inputMap)
					rwHdr.Add(hdr.Key, val)
				}
			} else {
				switch hdr.Type.(type) {
				case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value:
					rwHdr.Set(hdr.Key, hdr.GetValue())
				case *corev1.Service_Spec_Config_HTTP_Header_KeyValue_Eval:
					val, _ := m.celEngine.EvalPolicyString(ctx, hdr.GetEval(), inputMap)
					rwHdr.Set(hdr.Key, val)
				}
			}
		}

		for _, hdr := range cfg.RemoveResponseHeaders {
			rwHdr.Del(hdr)
		}

	}
	if cors := ucorev1.ToServiceConfig(svcCfg).GetHTTPCors(); cors != nil {

		originHeader := req.Header.Get("Origin")
		allowed, match := m.isOriginAllowed(originHeader, cors.AllowOriginStringMatch)

		if allowed {
			rwHdr.Set("Access-Control-Allow-Origin", match)
		}

		if cors.AllowCredentials {
			rwHdr.Set("Access-Control-Allow-Credentials", "true")
		}
		if cors.AllowHeaders != "" {
			rwHdr.Set("Access-Control-Expose-Headers", cors.AllowHeaders)
		}

	}

	rwHdr.Set("Server", "octelium")
}

func (m *middleware) isOriginAllowed(origin string, allowOriginList []string) (bool, string) {
	for _, item := range allowOriginList {
		if item == "*" || item == origin {
			return true, item
		}
	}

	return false, ""
}

const octeliumHeaderPrefix = "x-octelium-"

var managedServiceAllowedHeaders = map[string]struct{}{
	"X-Octelium-Auth":          {},
	"X-Octelium-Refresh-Token": {},

	http.CanonicalHeaderKey(vutils.GetDownstreamIPHeaderCanonical()): {},
}

func scrubOcteliumRequestHeaders(req *http.Request, isManagedSvc bool) {
	for name := range req.Header {
		if !isOcteliumHeader(name) {
			continue
		}

		if isManagedSvc {
			if _, ok := managedServiceAllowedHeaders[http.CanonicalHeaderKey(name)]; ok {
				continue
			}
		}

		delete(req.Header, name)
	}

	if !isManagedSvc {
		removeOcteliumCookie(req)
	}
}

func isOcteliumHeader(name string) bool {
	return len(name) >= len(octeliumHeaderPrefix) &&
		strings.EqualFold(name[:len(octeliumHeaderPrefix)], octeliumHeaderPrefix)
}

func removeOcteliumCookie(req *http.Request) {
	values, ok := req.Header["Cookie"]
	if !ok {
		return
	}

	var ret []string
	for _, value := range values {
		if filtered := filterOcteliumCookies(value); filtered != "" {
			ret = append(ret, filtered)
		}
	}

	if len(ret) == 0 {
		req.Header.Del("Cookie")
		return
	}

	req.Header["Cookie"] = ret
}

func filterOcteliumCookies(value string) string {
	var ret []string

	for _, pair := range strings.Split(value, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		name := pair
		if idx := strings.Index(pair, "="); idx >= 0 {
			name = pair[:idx]
		}

		switch strings.TrimSpace(name) {
		case "octelium_auth", "octelium_rt":
			continue
		}

		ret = append(ret, pair)
	}

	return strings.Join(ret, "; ")
}
