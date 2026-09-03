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

package httpg

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sigv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"
)

type directResponseHandler struct {
	direct *corev1.Service_Spec_Config_HTTP_Response_Direct
}

func (h *directResponseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Server", "octelium")
	resp := h.direct
	if resp == nil {
		return
	}

	if resp.ContentType != "" {
		w.Header().Set("Content-Type", resp.ContentType)
	}

	switch resp.Type.(type) {
	case *corev1.Service_Spec_Config_HTTP_Response_Direct_Inline:
		body := []byte(resp.GetInline())

		if len(body) > 0 {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		}

		if resp.StatusCode >= 200 && resp.StatusCode <= 599 {
			w.WriteHeader(int(resp.StatusCode))
		}

		if len(body) > 0 {
			w.Write(body)
		}

	case *corev1.Service_Spec_Config_HTTP_Response_Direct_InlineBytes:
		body := resp.GetInlineBytes()

		if len(body) > 0 {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		}

		if resp.StatusCode >= 200 && resp.StatusCode <= 599 {
			w.WriteHeader(int(resp.StatusCode))
		}

		if len(body) > 0 {
			w.Write(body)
		}
	default:
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func getUpstreamPath(svc *corev1.Service, upstreamPath, reqPath string) string {
	if upstreamPath == "" {
		return reqPath
	}

	switch {
	case ucorev1.ToService(svc).IsLLM():
		return upstreamPath + strings.TrimPrefix(reqPath,
			httputils.GetLLMVersionPrefix(
				ucorev1.ToServiceConfig(svc.Spec.Config).GetLLMProtocol()))
	case ucorev1.ToService(svc).IsMCP():
		return upstreamPath
	default:
		return reqPath
	}
}

func (s *Server) getProxy(ctx context.Context) (http.Handler, error) {
	reqCtx := middlewares.GetCtxRequestContext(ctx)
	svc := reqCtx.Service

	isManagedSvc := ucorev1.ToService(svc).IsManagedService()

	cfg := reqCtx.ServiceConfig
	httpCfg := cfg.GetHttp()
	headerCfg := ucorev1.ToServiceConfig(cfg).GetHTTPHeader()
	authCfg := ucorev1.ToServiceConfig(cfg).GetHTTPAuth()

	if httpCfg != nil && httpCfg.Response != nil && httpCfg.Response.GetDirect() != nil {
		return &directResponseHandler{
			direct: httpCfg.Response.GetDirect(),
		}, nil
	}

	upstream, err := s.lbManager.GetUpstream(ctx, reqCtx.AuthResponse)
	if err != nil {
		return nil, err
	}

	roundTripper, err := s.getRoundTripper(upstream)
	if err != nil {
		return nil, err
	}

	ret := &httputil.ReverseProxy{
		BufferPool: sharedBufferPool,
		Transport:  roundTripper,
		ErrorLog:   s.reverseProxyErrLogger,
		Rewrite: func(pr *httputil.ProxyRequest) {
			inReq := pr.In
			outReq := pr.Out

			forwardedScheme := getForwardedScheme(inReq, svc)

			switch upstream.URL.Scheme {
			case "https", "http":
				outReq.URL.Scheme = upstream.URL.Scheme
			case "ws":
				outReq.URL.Scheme = "http"
			case "grpc", "h2c":
				outReq.URL.Scheme = "http"
			case "wss":
				outReq.URL.Scheme = "https"
			default:
				if cfg != nil &&
					(cfg.ClientCertificate != nil ||
						(cfg.Tls != nil && cfg.Tls.ClientCertificate != nil)) {
					outReq.URL.Scheme = "https"
				} else {
					outReq.URL.Scheme = "http"
				}
			}

			if headerCfg != nil && headerCfg.Host != nil {
				hostCfg := headerCfg.Host

				switch {
				case hostCfg.GetPreserve():
					outReq.Host = vutils.GetServicePublicFQDN(svc, s.domain)

				case hostCfg.GetValue() != "":
					outReq.Host = hostCfg.GetValue()

				case hostCfg.GetEval() != "":
					res, err := s.celEngine.EvalPolicyString(
						inReq.Context(),
						hostCfg.GetEval(),
						reqCtx.ReqCtxMap,
					)
					if err == nil && res != "" {
						outReq.Host = res
					} else {
						outReq.Host = upstream.URL.Host
					}

				default:
					outReq.Host = upstream.URL.Host
				}
			} else {
				outReq.Host = upstream.URL.Host
			}

			if upstream.IsUser {
				outReq.URL.Host = upstream.HostPort
			} else {
				outReq.URL.Host = upstream.URL.Host
			}

			if pth := getUpstreamPath(svc, upstream.GetPath(),
				outReq.URL.Path); pth != outReq.URL.Path {
				outReq.URL.Path = pth
				outReq.URL.RawPath = ""
			}

			outReq.URL.RawQuery = strings.ReplaceAll(outReq.URL.RawQuery, ";", "&")
			outReq.RequestURI = ""

			if _, ok := outReq.Header["User-Agent"]; !ok {
				outReq.Header.Set("User-Agent", "octelium")
			}

			if isWebSocketUpgrade(inReq) {
				fixWebSocketHeaderCasing(outReq)
			}

			if isHTTP2RequestUpstream(outReq, svc, cfg) {
				outReq.Proto = "HTTP/2"
				outReq.ProtoMajor = 2
				outReq.ProtoMinor = 0
			} else {
				outReq.Proto = "HTTP/1.1"
				outReq.ProtoMajor = 1
				outReq.ProtoMinor = 1
			}

			applyForwardedHeaders(
				pr,
				svc,
				headerCfg,
				isManagedSvc,
				forwardedScheme,
				s.domain,
				s.forwardedObfuscatedID,
			)

			if authCfg.GetSigv4() != nil {

				sigv4Opts := authCfg.GetSigv4()

				secret, err := s.secretMan.GetByName(inReq.Context(),
					sigv4Opts.GetSecretAccessKey().GetFromSecret())
				if err != nil {
					zap.L().Warn("Could not get sigv4 Secret", zap.Error(err))
					return
				}

				signer := sigv4.NewSigner()

				payloadHash := fmt.Sprintf(
					"%x",
					sha256.Sum256([]byte(reqCtx.Body)),
				)
				outReq.Header.Set(
					"X-Amz-Content-Sha256",
					payloadHash,
				)

				if err := signer.SignHTTP(
					inReq.Context(),
					aws.Credentials{
						AccessKeyID:     sigv4Opts.AccessKeyID,
						SecretAccessKey: ucorev1.ToSecret(secret).GetValueStr(),
					},
					outReq,
					payloadHash,
					sigv4Opts.Service,
					sigv4Opts.Region,
					time.Now(),
				); err != nil {
					zap.L().Warn(
						"Could not signHTTP for sigv4",
						zap.Error(err),
					)
					return
				}
			}
		},

		FlushInterval: time.Duration(100 * time.Millisecond),
		ModifyResponse: func(r *http.Response) error {
			r.Header.Set("Server", "octelium")
			return nil
		},

		ErrorHandler: func(w http.ResponseWriter, request *http.Request, err error) {
			statusCode := http.StatusInternalServerError
			switch {
			case errors.Is(err, io.EOF):
				statusCode = http.StatusBadGateway
			case errors.Is(err, context.Canceled):
				statusCode = 499
			default:
				zap.L().Warn("Could not proxy request to upstream", zap.Error(err))
				var netErr net.Error
				if errors.As(err, &netErr) {
					if netErr.Timeout() {
						statusCode = http.StatusGatewayTimeout
					} else {
						statusCode = http.StatusBadGateway
					}
				}
			}

			w.Header().Set("Server", "octelium")
			w.WriteHeader(statusCode)
			w.Write([]byte(http.StatusText(statusCode)))
		},
	}
	return ret, nil
}

func isWebSocketUpgrade(req *http.Request) bool {
	if !httpguts.HeaderValuesContainsToken(req.Header["Connection"], "Upgrade") {
		return false
	}

	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
}

func fixWebSocketHeaderCasing(outReq *http.Request) {
	if outReq == nil {
		return
	}

	copyCanonicalHeader := func(canonicalName string, legacyName string) {
		values, ok := outReq.Header[legacyName]
		if !ok {
			return
		}

		outReq.Header[canonicalName] = slices.Clone(values)
		delete(outReq.Header, legacyName)
	}

	copyCanonicalHeader("Sec-WebSocket-Key", "Sec-Websocket-Key")
	copyCanonicalHeader("Sec-WebSocket-Extensions", "Sec-Websocket-Extensions")
	copyCanonicalHeader("Sec-WebSocket-Accept", "Sec-Websocket-Accept")
	copyCanonicalHeader("Sec-WebSocket-Protocol", "Sec-Websocket-Protocol")
	copyCanonicalHeader("Sec-WebSocket-Version", "Sec-Websocket-Version")
}

type zapWriter struct {
	log *zap.Logger
}

func (w zapWriter) Write(p []byte) (n int, err error) {
	w.log.Warn("httputil reverseProxy err", zap.String("msg", string(p)))
	return len(p), nil
}

var forwardedHeaderNames = []string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Forwarded-Server",
	"X-Forwarded-Prefix",
	"X-Forwarded-Uri",
	"X-Forwarded-Scheme",
	"X-Real-IP",
}

var alwaysRemovedRequestHeaders = []string{
	"X-Forwarded-Client-Cert",
}

const envoyHeaderPrefix = "x-envoy-"

func getForwardedScheme(req *http.Request, svc *corev1.Service) string {

	if svc != nil && svc.Spec.IsPublic {
		return "https"
	}

	if req != nil && req.TLS != nil {
		return "https"
	}

	return "http"
}

func applyForwardedHeaders(
	pr *httputil.ProxyRequest,
	svc *corev1.Service,
	headerCfg *corev1.Service_Spec_Config_HTTP_Header,
	isManagedSvc bool,
	forwardedScheme string,
	domain string,
	obfuscatedID string,
) {
	inReq := pr.In
	outReq := pr.Out

	removeAllForwardedHeaders(outReq)
	removeInfraRequestHeaders(outReq)

	if isManagedSvc {
		copyForwardedHeaders(outReq.Header, inReq.Header)
		return
	}

	var mode corev1.Service_Spec_Config_HTTP_Header_ForwardedMode
	if headerCfg != nil {
		mode = headerCfg.ForwardedMode
	}

	switch mode {
	case corev1.Service_Spec_Config_HTTP_Header_TRANSPARENT:
		copyForwardedHeaders(outReq.Header, inReq.Header)
	case corev1.Service_Spec_Config_HTTP_Header_OBFUSCATE:
		forwardedHost := vutils.GetServicePublicFQDN(svc, domain)

		forwardedValue := fmt.Sprintf(
			"for=_octelium-%s;by=%s;proto=%s;host=%s",
			utilrand.GetRandomStringLowercase(8),
			obfuscatedID,
			forwardedScheme,
			forwardedHost,
		)

		outReq.Header.Set("Forwarded", forwardedValue)
		outReq.Header.Set("X-Forwarded-Proto", forwardedScheme)
		outReq.Header.Set("X-Forwarded-Host", forwardedHost)
		outReq.Header.Set("X-Forwarded-For", "10.0.0.1")
		outReq.Header.Set("X-Real-IP", "10.0.0.1")

	case corev1.Service_Spec_Config_HTTP_Header_DROP,
		corev1.Service_Spec_Config_HTTP_Header_UNSET:
	default:
	}
}

func removeAllForwardedHeaders(req *http.Request) {
	if req == nil {
		return
	}

	for _, name := range forwardedHeaderNames {
		req.Header.Del(name)
	}
}

func removeInfraRequestHeaders(req *http.Request) {
	if req == nil {
		return
	}

	for _, name := range alwaysRemovedRequestHeaders {
		req.Header.Del(name)
	}

	for name := range req.Header {
		if len(name) >= len(envoyHeaderPrefix) &&
			strings.EqualFold(name[:len(envoyHeaderPrefix)], envoyHeaderPrefix) {
			delete(req.Header, name)
		}
	}
}

func copyForwardedHeaders(dst http.Header, src http.Header) {
	for _, name := range forwardedHeaderNames {
		key := http.CanonicalHeaderKey(name)

		values, ok := src[key]
		if !ok {
			continue
		}

		dst[key] = slices.Clone(values)
	}
}
