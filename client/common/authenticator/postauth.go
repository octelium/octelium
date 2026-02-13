// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authenticator

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/cliutils"
	authn "github.com/octelium/octelium/client/common/commands/auth/authenticator"
	"github.com/octelium/octelium/client/common/commands/auth/device/register"
	"github.com/octelium/octelium/octelium-go/authc"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

func getTLSConfig() (*tls.Config, error) {

	ret := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if ldflags.IsDev() || utils.IsInsecureTLS() {
		ret.InsecureSkipVerify = true
	}

	return ret, nil
}

func (a *authenticator) doPostAuth(ctx context.Context) error {

	if a.isRefresh {
		return nil
	}

	if !a.isAuthentication {
		return nil
	}

	if isAuthProxyMode() {
		return nil
	}

	domain := a.domain

	retryCodes := []codes.Code{
		codes.Unavailable,
		codes.ResourceExhausted,
		codes.Unknown,
		codes.Aborted,
		codes.DataLoss,
		codes.Internal,
		codes.DeadlineExceeded,
	}

	unaryMiddlewares := []grpc.UnaryClientInterceptor{
		grpc_retry.UnaryClientInterceptor(
			grpc_retry.WithMax(16),
			grpc_retry.WithBackoff(grpc_retry.BackoffLinear(1000*time.Millisecond)),
			grpc_retry.WithCodes(retryCodes...)),
	}

	streamMiddlewares := []grpc.StreamClientInterceptor{}

	unaryMiddlewares = append(unaryMiddlewares,
		unaryClientInterceptor(domain),
	)

	tlsConfig, err := getTLSConfig()
	if err != nil {
		return err
	}

	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    45 * time.Second,
			Timeout: 15 * time.Second,
		}),

		grpc.WithUnaryInterceptor(grpc_middleware.ChainUnaryClient(unaryMiddlewares...)),
		grpc.WithStreamInterceptor(grpc_middleware.ChainStreamClient(streamMiddlewares...)),
		grpc.WithUserAgent(fmt.Sprintf("octelium-cli/%s", ldflags.SemVer)),
	}

	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))

	conn, err := grpc.Dial(authc.GetAPIServerAddr(domain), opts...)
	if err != nil {
		return err
	}
	defer conn.Close()
	client := userv1.NewMainServiceClient(conn)

	st, err := client.GetStatus(ctx, &userv1.GetStatusRequest{})
	if err != nil {
		return err
	}

	{
		arg := st.User.Metadata.Name
		if st.User.Metadata.DisplayName != "" {
			arg = fmt.Sprintf("%s (%s)", arg, st.User.Metadata.DisplayName)
		}

		cliutils.LineInfo("You are now authenticated as %s\n", arg)
	}

	if st.User.Spec != nil &&
		st.User.Spec.Type == userv1.GetStatusResponse_User_Spec_HUMAN && !cliutils.IsSuggestedWorkloadHost() {
		if err := register.DoRegisterDevice(ctx, domain); err != nil {
			zap.L().Debug("Could not register Device", zap.Error(err))
		}

		authC, err := cliutils.NewAuthClient(ctx, domain, nil)
		if err != nil {
			return err
		}

		defer authC.Close()

		if resp, err := authC.C().GetAvailableAuthenticator(ctx,
			&authv1.GetAvailableAuthenticatorRequest{}); err == nil {
			if resp.MainAuthenticator != nil {
				zap.L().Debug("Found main Authenticator", zap.Any("authn", resp.MainAuthenticator))
				if err := authn.DoAuthenticate(ctx,
					domain, authC, umetav1.GetObjectReference(resp.MainAuthenticator)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func unaryClientInterceptor(domain string, opts ...grpc.CallOption) grpc.UnaryClientInterceptor {

	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {

		st, err := cliutils.GetDB().GetSessionToken(domain)
		if err != nil {
			return err
		}

		ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-auth", st.AccessToken)

		err = invoker(ctx, method, req, reply, cc, opts...)
		if err != nil {
			zap.L().Debug("invoker error", zap.Error(err))
		}
		return err
	}
}
