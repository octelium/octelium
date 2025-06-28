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
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
)

type middleware struct {
	next      http.Handler
	secretMan *secretman.SecretManager
}

func New(ctx context.Context, next http.Handler, secretMan *secretman.SecretManager) (http.Handler, error) {
	return &middleware{
		next:      next,
		secretMan: secretMan,
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqCtx := middlewares.GetCtxRequestContext(req.Context())
	if isPreflight := m.processCORSHeaders(rw, req, reqCtx); isPreflight {
		return
	}

	m.setRequestHeaders(req, reqCtx)

	if m.next != nil {
		m.next.ServeHTTP(newResponseModifier(rw, req, m.postRequestModifyResponseHeaders), req)
	}
}

func (m *middleware) setRequestHeaders(req *http.Request, reqCtx *middlewares.RequestContext) {
	ctx := req.Context()

	svc := reqCtx.Service
	svcCfg := reqCtx.ServiceConfig
	isManagedSvc := ucorev1.ToService(svc).IsManagedService()
	isAnonymous := svc.Spec.IsAnonymous

	if !isAnonymous || !isManagedSvc {
		req.Header.Del("Authorization")
	}

	if svcCfg != nil && svcCfg.GetHttp() != nil && svcCfg.GetHttp().Header != nil {
		cfg := svcCfg.GetHttp().Header
		for _, hdr := range cfg.AddRequestHeaders {
			if hdr.Append {
				req.Header.Add(hdr.Key, hdr.Value)
			} else {
				req.Header.Set(hdr.Key, hdr.Value)
			}
		}

		for _, hdr := range cfg.RemoveRequestHeaders {
			req.Header.Del(hdr)
		}
	}

	if svcCfg != nil &&
		svcCfg.GetHttp() != nil && svcCfg.GetHttp().GetAuth() != nil {
		authS := svcCfg.GetHttp().GetAuth()

		if authS.GetBearer() != nil &&
			authS.GetBearer().GetFromSecret() != "" {
			secret, err := m.secretMan.GetByName(ctx, authS.GetBearer().GetFromSecret())
			if err == nil {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ucorev1.ToSecret(secret).GetValueStr()))
			} else {
				zap.S().Warnf("Could not get Bearer Secret: %s: %+v", svc.Spec.Config.GetHttp().GetAuth().GetBearer().GetFromSecret(), err)
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
				zap.S().Warnf("Could not get Basic Secret: %s: %+v", svc.Spec.Config.GetHttp().GetAuth().GetBearer().GetFromSecret(), err)
			}
		} else if authS.GetCustom() != nil &&
			authS.GetCustom().GetValue() != nil && authS.GetCustom().GetValue().GetFromSecret() != "" {
			secret, err := m.secretMan.GetByName(ctx, authS.GetCustom().GetValue().GetFromSecret())
			if err == nil {
				req.Header.Set(authS.GetCustom().Header, ucorev1.ToSecret(secret).GetValueStr())
			} else {
				zap.S().Warnf("Could not get Basic Secret: %s: %+v", svc.Spec.Config.GetHttp().GetAuth().GetBearer().GetFromSecret(), err)
			}
		} else if authS.GetOauth2ClientCredentials() != nil &&
			authS.GetOauth2ClientCredentials().GetClientSecret() != nil &&
			authS.GetOauth2ClientCredentials().GetClientSecret().GetFromSecret() != "" {
			accessToken, err := m.secretMan.GetOAuth2CCToken(ctx, &secretman.GetOAuth2CCTokenReq{
				ClientID:   authS.GetOauth2ClientCredentials().ClientID,
				SecretName: authS.GetOauth2ClientCredentials().GetClientSecret().GetFromSecret(),
				TokenURL:   authS.GetOauth2ClientCredentials().TokenURL,
			})
			if err == nil {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
			} else {
				zap.L().Warn("Could not get oauth2 client credentials access token", zap.Error(err))
			}
		}

		/*
			else if authS.GetSigv4() != nil &&
				authS.GetSigv4().GetSecretAccessKey() != nil &&
				authS.GetSigv4().GetSecretAccessKey().GetFromSecret() != "" {
				sigv4Opts := authS.GetSigv4()
				secret, err := m.secretMan.GetByName(ctx, sigv4Opts.GetSecretAccessKey().GetFromSecret())
				if err == nil {
					signer := sigv4.NewSigner()
					if err := signer.SignHTTP(ctx,
						aws.Credentials{
							AccessKeyID:     sigv4Opts.AccessKeyID,
							SecretAccessKey: ucorev1.ToSecret(secret).GetValueStr(),
						},
						req,
						fmt.Sprintf("%x", sha256.Sum256([]byte(reqCtx.Body))),
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
		*/
	}

	if !isManagedSvc {
		req.Header.Del("X-Octelium-Auth")

		for name, _ := range req.Header {
			if strings.HasPrefix(name, "X-Octelium") {
				req.Header.Del(name)
			}
		}

		removeOcteliumCookie(req)
	}

	if !isAnonymous && isManagedSvc &&
		reqCtx.DownstreamInfo != nil && reqCtx.DownstreamInfo.Session != nil {
		if sessionRefBytes, err := pbutils.MarshalJSON(umetav1.GetObjectReference(reqCtx.DownstreamInfo.Session), false); err == nil {
			req.Header.Set("X-Octelium-Session-Ref", string(sessionRefBytes))
		}

		req.Header.Set("X-Octelium-Session-Uid", reqCtx.DownstreamInfo.Session.Metadata.Uid)
		req.Header.Set("X-Octelium-Req-Path", req.URL.Path)
	}

	if ucorev1.ToService(svc).IsKubernetes() && svcCfg != nil && svcCfg.GetKubernetes() != nil &&
		svcCfg.GetKubernetes().GetBearerToken() != nil &&
		svcCfg.GetKubernetes().GetBearerToken().GetFromSecret() != "" {
		tknSecret, err := m.secretMan.GetByName(ctx,
			svcCfg.GetKubernetes().GetBearerToken().GetFromSecret())
		if err != nil {
			zap.L().Debug("Could not get k8s token secret", zap.Error(err))
		} else {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ucorev1.ToSecret(tknSecret).GetValueStr()))
		}
	} else if ucorev1.ToService(svc).IsKubernetes() && svcCfg != nil && svcCfg.GetKubernetes() != nil &&
		svc.Metadata.SpecLabels["k8s-kubeconfig-has-token"] == "true" &&
		svcCfg.GetKubernetes().GetKubeconfig() != nil &&
		svcCfg.GetKubernetes().GetKubeconfig().GetFromSecret() != "" {
		kubeConfigSecret, err := m.secretMan.GetByName(ctx,
			svcCfg.GetKubernetes().GetKubeconfig().GetFromSecret())
		if err != nil {
			zap.L().Debug("Could not get kubeconfig secret", zap.Error(err))
		} else {
			kubeconfig, err := k8sutils.UnmarshalKubeConfigFromYAML(ucorev1.ToSecret(kubeConfigSecret).GetValueBytes())
			if err != nil {
				zap.L().Warn("Could not unmarshal kubeconfig", zap.Error(err))
			} else {
				if usr := kubeconfig.GetUser(svcCfg.GetKubernetes().GetKubeconfig().Context); usr != nil {
					req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", usr.User.Token))
				}
			}
		}
	}
}

func (m *middleware) processCORSHeaders(rw http.ResponseWriter, req *http.Request, reqCtx *middlewares.RequestContext) bool {
	svcCfg := reqCtx.ServiceConfig

	if svcCfg == nil || svcCfg.GetHttp() == nil || svcCfg.GetHttp().Cors == nil {
		return false
	}
	cors := svcCfg.GetHttp().Cors

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

func (m *middleware) postRequestModifyResponseHeaders(res *http.Response) error {

	reqCtx := middlewares.GetCtxRequestContext(res.Request.Context())
	svcCfg := reqCtx.ServiceConfig

	if svcCfg != nil && svcCfg.GetHttp() != nil && svcCfg.GetHttp().Header != nil {
		cfg := svcCfg.GetHttp().Header
		for _, hdr := range cfg.AddResponseHeaders {
			if hdr.Append {
				res.Header.Add(hdr.Key, hdr.Value)
			} else {
				res.Header.Set(hdr.Key, hdr.Value)
			}
		}

		for _, hdr := range cfg.RemoveResponseHeaders {
			res.Header.Del(hdr)
		}

	}
	if svcCfg != nil && svcCfg.GetHttp() != nil && svcCfg.GetHttp().Cors != nil {
		cors := svcCfg.GetHttp().Cors
		if res != nil && res.Request != nil {
			originHeader := res.Request.Header.Get("Origin")
			allowed, match := m.isOriginAllowed(originHeader, cors.AllowOriginStringMatch)

			if allowed {
				res.Header.Set("Access-Control-Allow-Origin", match)
			}
		}

		if cors.AllowCredentials {
			res.Header.Set("Access-Control-Allow-Credentials", "true")
		}
		if cors.AllowHeaders != "" {
			res.Header.Set("Access-Control-Expose-Headers", cors.AllowHeaders)
		}

	}

	res.Header.Set("Server", "octelium")

	return nil
}

func (m *middleware) isOriginAllowed(origin string, allowOriginList []string) (bool, string) {
	for _, item := range allowOriginList {
		if item == "*" || item == origin {
			return true, item
		}
	}

	return false, ""
}

func removeOcteliumCookie(req *http.Request) {

	var cookieHdr string

	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}

	for _, cookie := range cookies {
		switch cookie.Name {
		case "octelium_auth", "octelium_rt":
			continue
		}
		if cookieHdr == "" {
			cookieHdr = fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
		} else {
			cookieHdr = fmt.Sprintf("%s; %s=%s", cookieHdr, cookie.Name, cookie.Value)
		}
	}

	req.Header.Set("Cookie", cookieHdr)
}
