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
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sigv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
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

func (s *Server) getProxy(ctx context.Context) (http.Handler, error) {
	reqCtx := middlewares.GetCtxRequestContext(ctx)

	isManagedSvc := ucorev1.ToService(reqCtx.Service).IsManagedService()

	cfg := reqCtx.ServiceConfig
	var httpCfg *corev1.Service_Spec_Config_HTTP
	if cfg != nil && cfg.GetHttp() != nil {
		httpCfg = cfg.GetHttp()
	}

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
		BufferPool: newBufferPool(),
		Transport:  roundTripper,
		ErrorLog:   s.reverseProxyErrLogger,
		Director: func(outReq *http.Request) {
			svc := reqCtx.Service
			scheme := outReq.URL.Scheme
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
				if cfg != nil && (cfg.ClientCertificate != nil ||
					(cfg.Tls != nil && cfg.Tls.ClientCertificate != nil)) {
					outReq.URL.Scheme = "https"
				} else {
					outReq.URL.Scheme = "http"
				}
			}

			outReq.Host = upstream.URL.Host

			if upstream.IsUser {
				outReq.URL.Host = upstream.HostPort
			} else {
				outReq.URL.Host = upstream.URL.Host
			}

			outReq.URL.RawQuery = strings.ReplaceAll(outReq.URL.RawQuery, ";", "&")
			outReq.RequestURI = ""

			if _, ok := outReq.Header["User-Agent"]; !ok {
				outReq.Header.Set("User-Agent", "octelium")
			}

			fixWebSocketHeaders(outReq)

			if isHTTP2RequestUpstream(outReq, svc) {
				outReq.Proto = "HTTP/2"
				outReq.ProtoMajor = 2
				outReq.ProtoMinor = 0
			} else {
				outReq.Proto = "HTTP/1.1"
				outReq.ProtoMajor = 1
				outReq.ProtoMinor = 1
			}

			if !isManagedSvc {

				outReq.Header.Del("X-Forwarded-For")
				outReq.Header.Del("X-Forwarded-Host")
				outReq.Header.Del("X-Forwarded-Proto")

				if httpCfg != nil && httpCfg.Header != nil {
					switch httpCfg.Header.ForwardedMode {
					case corev1.Service_Spec_Config_HTTP_Header_DROP,
						corev1.Service_Spec_Config_HTTP_Header_UNSET:
						outReq.Header.Del("Forwarded")
					case corev1.Service_Spec_Config_HTTP_Header_TRANSPARENT:
					case corev1.Service_Spec_Config_HTTP_Header_OBFUSCATE:
						forwardedVal := fmt.Sprintf("for=_octelium-%s;by=%s;proto=%s;host=%s",
							utilrand.GetRandomStringLowercase(8),
							s.forwardedObfuscatedID,
							scheme,
							vutils.GetServicePublicFQDN(svc, s.domain))
						outReq.Header.Set("Forwarded", forwardedVal)
					}
				} else {
					outReq.Header.Del("Forwarded")
				}
			}

			/*
				if outReq.Header.Get("Origin") != "" {
					outReq.Header.Set("Origin", upstream.URL.String())
				}
			*/

			if httpCfg != nil && httpCfg.GetAuth() != nil &&
				httpCfg.GetAuth().GetSigv4() != nil {

				sigv4Opts := httpCfg.GetAuth().GetSigv4()
				secret, err := s.secretMan.GetByName(ctx, sigv4Opts.GetSecretAccessKey().GetFromSecret())
				if err == nil {
					signer := sigv4.NewSigner()

					payloadHash := fmt.Sprintf("%x", sha256.Sum256([]byte(reqCtx.Body)))
					outReq.Header.Set("X-Amz-Content-Sha256", payloadHash)

					if err := signer.SignHTTP(ctx,
						aws.Credentials{
							AccessKeyID:     sigv4Opts.AccessKeyID,
							SecretAccessKey: ucorev1.ToSecret(secret).GetValueStr(),
						},
						outReq,
						payloadHash,
						sigv4Opts.Service, sigv4Opts.Region,
						time.Now(),
					); err != nil {
						zap.L().Warn("Could not signHTTP for sigv4", zap.Error(err))
						return
					}
				} else {
					zap.L().Warn("Could not get sigv4 Secret", zap.Error(err))
				}

			}

			/*
				if ldflags.IsDev() {
					zap.L().Debug("Outgoing req",
						zap.Any("headers", outReq.Header),
						zap.String("url", outReq.URL.String()))
				}
			*/
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

func fixWebSocketHeaders(outReq *http.Request) {
	if !isWebSocketUpgrade(outReq) {
		return
	}

	outReq.Header["Sec-WebSocket-Key"] = outReq.Header["Sec-Websocket-Key"]
	outReq.Header["Sec-WebSocket-Extensions"] = outReq.Header["Sec-Websocket-Extensions"]
	outReq.Header["Sec-WebSocket-Accept"] = outReq.Header["Sec-Websocket-Accept"]
	outReq.Header["Sec-WebSocket-Protocol"] = outReq.Header["Sec-Websocket-Protocol"]
	outReq.Header["Sec-WebSocket-Version"] = outReq.Header["Sec-Websocket-Version"]
	delete(outReq.Header, "Sec-Websocket-Key")
	delete(outReq.Header, "Sec-Websocket-Extensions")
	delete(outReq.Header, "Sec-Websocket-Accept")
	delete(outReq.Header, "Sec-Websocket-Protocol")
	delete(outReq.Header, "Sec-Websocket-Version")
}

type zapWriter struct {
	log *zap.Logger
}

func (w zapWriter) Write(p []byte) (n int, err error) {
	w.log.Warn("httputil reverseProxy err", zap.String("msg", string(p)))
	return len(p), nil
}
