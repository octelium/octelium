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
	"runtime/debug"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/browserorigin"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type authMainSvc struct {
	authv1.UnimplementedMainServiceServer
	s *server
}

func (s *server) unaryServerInterceptor(ctx context.Context, req any,
	info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {

	defer func() {
		if r := recover(); r != nil {
			zap.L().Error("Recovered from a panic in a gRPC handler",
				zap.String("method", info.FullMethod),
				zap.Any("panic", r),
				zap.ByteString("stack", debug.Stack()))
			resp = nil
			err = s.errInternal("Panic in the gRPC handler: %v", r)
		}
	}()

	if err := s.checkGRPCCookieOrigin(ctx); err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

const systemServiceHostsCacheKey = "system-service-browser-hosts"

func (s *server) checkGRPCCookieOrigin(ctx context.Context) error {
	if grpcutils.GetHeaderValueMust(ctx, "x-octelium-refresh-token") != "" {
		return nil
	}

	cookieValues := grpcutils.GetHeaderValueAll(ctx, "cookie")
	if len(cookieValues) == 0 {
		return nil
	}

	req := &http.Request{Header: make(http.Header)}
	for _, value := range cookieValues {
		req.Header.Add("Cookie", value)
	}
	cookie, err := req.Cookie("octelium_rt")
	if err != nil || cookie.Value == "" {
		return nil
	}

	origins := grpcutils.GetHeaderValueAll(ctx, "x-octelium-origin")
	if len(origins) != 1 {
		return s.errPermissionDenied("Invalid browser origin")
	}

	hosts, err := s.getSystemServiceBrowserHosts(ctx)
	if err != nil {
		return s.errInternalErr(err)
	}
	if !browserorigin.IsAllowed(origins[0], hosts) {
		return s.errPermissionDenied("Invalid browser origin")
	}

	return nil
}

func (s *server) getSystemServiceBrowserHosts(ctx context.Context) ([]browserorigin.Host, error) {
	if val, found := s.genCache.Get(systemServiceHostsCacheKey); found {
		return val.([]browserorigin.Host), nil
	}

	services, err := s.octeliumC.CoreC().ListService(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterFieldBooleanTrue("metadata.isSystem"),
			urscsrv.FilterFieldBooleanTrue("spec.isPublic"),
		},
	})
	if err != nil {
		return nil, err
	}

	hosts := browserorigin.SystemServiceHosts(s.domain, services.Items)
	s.genCache.Set(systemServiceHostsCacheKey, hosts, 5*time.Second)

	return hosts, nil
}

func (s *authMainSvc) AuthenticateWithAuthenticationToken(ctx context.Context,
	req *authv1.AuthenticateWithAuthenticationTokenRequest) (*authv1.SessionToken, error) {
	return s.s.doAuthenticateWithAuthenticationToken(ctx, req)
}

func (s *authMainSvc) AuthenticateWithAssertion(ctx context.Context,
	req *authv1.AuthenticateWithAssertionRequest) (*authv1.SessionToken, error) {
	return s.s.doAuthenticateWithAssertion(ctx, req)
}

func (s *authMainSvc) AuthenticateWithRefreshToken(ctx context.Context,
	req *authv1.AuthenticateWithRefreshTokenRequest) (*authv1.SessionToken, error) {
	return s.s.doAuthenticateWithRefreshToken(ctx, req)
}

func (s *authMainSvc) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	return s.s.doLogout(ctx, req)
}

func (s *authMainSvc) RegisterDeviceBegin(ctx context.Context,
	req *authv1.RegisterDeviceBeginRequest) (*authv1.RegisterDeviceBeginResponse, error) {
	return s.s.doRegisterDeviceBegin(ctx, req)
}

func (s *authMainSvc) RegisterDeviceFinish(ctx context.Context,
	req *authv1.RegisterDeviceFinishRequest) (*authv1.RegisterDeviceFinishResponse, error) {
	return s.s.doRegisterDeviceFinish(ctx, req)
}

func (s *authMainSvc) AuthenticateWithAuthenticator(ctx context.Context,
	req *authv1.AuthenticateWithAuthenticatorRequest) (*authv1.SessionToken, error) {

	return s.s.doAuthenticateWithAuthenticator(ctx, req)
}

func (s *authMainSvc) CreateAuthenticator(ctx context.Context,
	req *authv1.CreateAuthenticatorRequest) (*authv1.Authenticator, error) {

	return s.s.doCreateAuthenticator(ctx, req)
}

func (s *authMainSvc) ListAuthenticator(ctx context.Context,
	req *authv1.ListAuthenticatorOptions) (*authv1.AuthenticatorList, error) {

	return s.s.doListAuthenticator(ctx, req)
}

func (s *authMainSvc) GetAuthenticator(ctx context.Context,
	req *metav1.GetOptions) (*authv1.Authenticator, error) {

	return s.s.doGetAuthenticator(ctx, req)
}

func (s *authMainSvc) DeleteAuthenticator(ctx context.Context,
	req *metav1.DeleteOptions) (*metav1.OperationResult, error) {

	return s.s.doDeleteAuthenticator(ctx, req)
}

func (s *authMainSvc) UpdateAuthenticator(ctx context.Context,
	req *authv1.Authenticator) (*authv1.Authenticator, error) {

	return s.s.doUpdateAuthenticator(ctx, req)
}

func (s *authMainSvc) AuthenticateAuthenticatorBegin(ctx context.Context,
	req *authv1.AuthenticateAuthenticatorBeginRequest) (*authv1.AuthenticateAuthenticatorBeginResponse, error) {

	return s.s.doAuthenticateAuthenticatorBegin(ctx, req)
}

func (s *authMainSvc) RegisterAuthenticatorBegin(ctx context.Context,
	req *authv1.RegisterAuthenticatorBeginRequest) (*authv1.RegisterAuthenticatorBeginResponse, error) {

	return s.s.doRegisterAuthenticatorBegin(ctx, req)
}

func (s *authMainSvc) RegisterAuthenticatorFinish(ctx context.Context,
	req *authv1.RegisterAuthenticatorFinishRequest) (*authv1.RegisterAuthenticatorFinishResponse, error) {

	return s.s.doRegisterAuthenticatorFinish(ctx, req)
}

func (s *authMainSvc) GetAvailableAuthenticator(ctx context.Context,
	req *authv1.GetAvailableAuthenticatorRequest) (*authv1.GetAvailableAuthenticatorResponse, error) {

	return s.s.doGetAvailableAuthenticator(ctx, req)
}

func (s *authMainSvc) AuthenticateWithPasskeyBegin(ctx context.Context,
	req *authv1.AuthenticateWithPasskeyBeginRequest) (*authv1.AuthenticateWithPasskeyBeginResponse, error) {

	return s.s.doAuthenticateWithPasskeyBegin(ctx, req)
}

func (s *authMainSvc) AuthenticateWithPasskey(ctx context.Context,
	req *authv1.AuthenticateWithPasskeyRequest) (*authv1.SessionToken, error) {

	return s.s.doAuthenticateWithPasskey(ctx, req)
}

func (s *authMainSvc) RunDeviceProbeBegin(ctx context.Context,
	req *authv1.RunDeviceProbeBeginRequest) (*authv1.RunDeviceProbeBeginResponse, error) {

	return s.s.doRunDeviceProbeBegin(ctx, req)
}

func (s *authMainSvc) RunDeviceProbeFinish(ctx context.Context,
	req *authv1.RunDeviceProbeFinishRequest) (*authv1.RunDeviceProbeFinishResponse, error) {

	return s.s.doRunDeviceProbeFinish(ctx, req)
}
