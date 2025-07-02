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

package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/client/middleware/auth"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/octelium-go/authc"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/octelium/octelium/pkg/utils/ldflags"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func GetDefaultKubeConfig() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/.kube/config", homeDir), nil
}

type ClientInfo struct {
	ClusterDomain string
	SessionName   string
	UserName      string
}

func getClientInfo(addr string) (*ClientInfo, error) {

	ret := &ClientInfo{
		ClusterDomain: addr,
	}

	return ret, nil

}

func getTLSConfig() (*tls.Config, error) {

	ret := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if ldflags.IsDev() || utils.IsInsecureTLS() {
		ret.InsecureSkipVerify = true
	}

	return ret, nil
}

func doGetGRPCClientConn(domain string, s *authv1.SessionToken) (*grpc.ClientConn, error) {

	tlsConfig, err := getTLSConfig()
	if err != nil {
		return nil, err
	}

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
		auth.UnaryClientInterceptor(domain),
	)

	streamMiddlewares = append(streamMiddlewares,
		auth.StreamClientInterceptor(domain),
	)

	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    45 * time.Second,
			Timeout: 15 * time.Second,
		}),

		grpc.WithUnaryInterceptor(grpc_middleware.ChainUnaryClient(unaryMiddlewares...)),
		grpc.WithStreamInterceptor(grpc_middleware.ChainStreamClient(streamMiddlewares...)),
		grpc.WithUserAgent(fmt.Sprintf("octelium-cli/%s", ldflags.SemVer)),
	}

	isAuthProxy := os.Getenv("OCTELIUM_AUTH_PROXY_SOCKET") != ""

	var target string

	if isAuthProxy {
		target = os.Getenv("OCTELIUM_AUTH_PROXY_SOCKET")
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		opts = append(opts, grpc.WithBlock())
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", addr)
		}))
	} else {
		target = authc.GetAPIServerAddr(domain)
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}

	return grpc.Dial(target, opts...)
}

func GetGRPCClientConn(ctx context.Context, clusterDomain string) (*grpc.ClientConn, error) {

	i, err := getClientInfo(clusterDomain)
	if err != nil {
		return nil, err
	}

	return getGRPCClientConnFromClientInfo(ctx, i)
}

func getGRPCClientConnFromClientInfo(ctx context.Context, i *ClientInfo) (*grpc.ClientConn, error) {

	if os.Getenv("OCTELIUM_AUTH_PROXY_SOCKET") != "" {
		return doGetGRPCClientConn(i.ClusterDomain, nil)
	}

	if err := authenticator.Authenticate(ctx, &authenticator.AuthenticateOpts{
		Domain: i.ClusterDomain,
	}); err != nil {
		return nil, err
	}

	d := cliutils.GetDB()
	at, err := d.GetSessionToken(i.ClusterDomain)
	if err != nil {
		return nil, err
	}

	return doGetGRPCClientConn(i.ClusterDomain, at)
}
