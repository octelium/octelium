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

package authserver

import (
	"context"
	"net/http"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {

	if err := s.checkXOcteliumOrigin(r); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	sess, err := s.getWebSessionFromHTTPRefreshCookie(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	ctx := r.Context()

	_, err = s.octeliumC.CoreC().DeleteSession(ctx,
		apivalidation.ObjectToRDeleteOptions(sess))
	if err == nil || grpcerr.IsNotFound(err) {
		s.setLogoutCookies(w)
		w.WriteHeader(http.StatusOK)
		return
	}

	if grpcerr.IsCanceled(err) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusInternalServerError)
}

func (s *server) doLogout(ctx context.Context, _ *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {

	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	if _, err := s.octeliumC.CoreC().DeleteSession(ctx,
		apivalidation.ObjectToRDeleteOptions(sess)); err != nil {
		if !grpcerr.IsNotFound(err) {
			return nil, grpcutils.InternalWithErr(err)
		}
	}

	if sess.Status.Type == corev1.Session_Status_CLIENTLESS &&
		sess.Status.IsBrowser {
		md := make(metadata.MD)
		logoutCookies := s.getLogoutCookies()

		md["set-cookie"] = []string{}

		for _, cookie := range logoutCookies {
			md["set-cookie"] = append(md["set-cookie"], cookie.String())
		}

		if err := grpc.SetHeader(ctx, md); err != nil {
			zap.L().Warn("Could not set logout cookies in gRPC header", zap.Error(err))
		}
	}

	return &authv1.LogoutResponse{}, nil
}
