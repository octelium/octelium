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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (m *middleware) handleUnauthorized(w http.ResponseWriter, req *http.Request, reqCtx *middlewares.RequestContext) {
	w.Header().Set("X-Octelium-Unauthorized", "true")
	svc := reqCtx.Service

	httpStatusCode := func() int {
		if !reqCtx.IsAuthenticated {
			return http.StatusUnauthorized
		}
		return http.StatusForbidden
	}()

	switch {
	case ucorev1.ToService(svc).IsGRPC():
		w.Header().Set("Content-Type", "application/grpc")
		if !reqCtx.IsAuthenticated {
			w.Header().Set("Grpc-Status", fmt.Sprintf("%d", codes.Unauthenticated))
			w.Header().Set("Grpc-Message", "Octelium: Unauthenticated")
		} else {
			w.Header().Set("Grpc-Status", fmt.Sprintf("%d", codes.PermissionDenied))
			w.Header().Set("Grpc-Message", "Octelium: Unauthorized")
		}

		return
	case ucorev1.ToService(svc).IsKubernetes():
		w.WriteHeader(httpStatusCode)
		reason := k8smetav1.StatusReasonForbidden
		if !reqCtx.IsAuthenticated {
			reason = k8smetav1.StatusReasonUnauthorized
		}

		status := k8smetav1.Status{
			Reason:  reason,
			Message: "Octelium: Unauthorized request",
			Code:    int32(httpStatusCode),
		}
		resBytes, _ := json.Marshal(status)
		w.Write(resBytes)
		return
	}

	if httputils.IsHTMLPage(req) {
		// w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// w.Write([]byte(deniedPage))

		if reqCtx.IsAuthenticated &&
			reqCtx.DownstreamInfo != nil &&
			reqCtx.DownstreamInfo.User != nil &&
			reqCtx.DownstreamInfo.User.Spec.Type == corev1.User_Spec_HUMAN {
			/*
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write([]byte(deniedPage))
			*/
			http.Redirect(w, req, fmt.Sprintf("https://%s/denied", m.domain), http.StatusSeeOther)
			return
		}

		if !reqCtx.IsAuthenticated {

			if err := apivalidation.ValidateBrowserUserAgent(req.UserAgent()); err == nil {
				loginURL, err := url.Parse(fmt.Sprintf("https://%s/login", m.domain))
				if err != nil {
					w.WriteHeader(httpStatusCode)
					return
				}

				if svc.Spec.IsPublic {
					q := loginURL.Query()

					if ucorev1.ToService(svc).IsManagedService() &&
						svc.Status.ManagedService != nil &&
						svc.Status.ManagedService.ForwardHost &&
						strings.HasSuffix(req.Header.Get("X-Forwarded-Host"), m.domain) {

						u := fmt.Sprintf("https://%s%s",
							req.Header.Get("X-Forwarded-Host"),
							getDecodedPathWithQuery(req.URL))
						zap.L().Debug("Adding redirect URL to login", zap.String("redirectURL", u))
						q.Set("redirect", u)
						loginURL.RawQuery = q.Encode()
					} else {
						u := fmt.Sprintf("https://%s%s",
							vutils.GetServicePublicFQDN(svc, m.domain),
							getDecodedPathWithQuery(req.URL))
						zap.L().Debug("Adding redirect URL to login", zap.String("redirectURL", u))
						q.Set("redirect", u)
						loginURL.RawQuery = q.Encode()
					}

				}

				lgnURL := loginURL.String()
				zap.L().Debug("Redirecting to login URL", zap.String("loginURL", lgnURL))
				http.Redirect(w, req, lgnURL, http.StatusSeeOther)
				return
			}
		}
	}

	w.WriteHeader(httpStatusCode)

}

func getDecodedPathWithQuery(u *url.URL) string {
	if u.RawQuery == "" {
		return u.Path
	}
	return fmt.Sprintf("%s?%s", u.Path, u.RawQuery)
}
