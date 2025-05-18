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

	"github.com/octelium/octelium/apis/main/authv1"
)

type authMainSvc struct {
	authv1.UnimplementedMainServiceServer
	s *server
}

func (s *authMainSvc) AuthenticateWithAuthenticationToken(ctx context.Context, req *authv1.AuthenticateWithAuthenticationTokenRequest) (*authv1.SessionToken, error) {
	return s.s.doAuthenticateWithAuthenticationToken(ctx, req)
}

func (s *authMainSvc) AuthenticateWithAssertion(ctx context.Context, req *authv1.AuthenticateWithAssertionRequest) (*authv1.SessionToken, error) {
	return s.s.doAuthenticateWithAssertion(ctx, req)
}

func (s *authMainSvc) AuthenticateWithRefreshToken(ctx context.Context, req *authv1.AuthenticateWithRefreshTokenRequest) (*authv1.SessionToken, error) {
	return s.s.doAuthenticateWithRefreshToken(ctx, req)
}

func (s *authMainSvc) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	return s.s.doLogout(ctx, req)
}

func (s *authMainSvc) RegisterDeviceBegin(ctx context.Context, req *authv1.RegisterDeviceBeginRequest) (*authv1.RegisterDeviceBeginResponse, error) {
	return s.s.doRegisterDeviceBegin(ctx, req)
}

func (s *authMainSvc) RegisterDeviceFinish(ctx context.Context, req *authv1.RegisterDeviceFinishRequest) (*authv1.RegisterDeviceFinishResponse, error) {
	return s.s.doRegisterDeviceFinish(ctx, req)
}
