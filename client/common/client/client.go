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
	"fmt"
	"os"

	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/client/grpcconn"

	"google.golang.org/grpc"
)

func GetDefaultKubeConfig() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/.kube/config", homeDir), nil
}

func GetGRPCClientConn(ctx context.Context, domain string) (*grpc.ClientConn, error) {
	if os.Getenv("OCTELIUM_AUTH_PROXY_SOCKET") != "" {
		return grpcconn.DoGetGRPCClientConn(domain)
	}

	if err := authenticator.Authenticate(ctx, &authenticator.AuthenticateOpts{
		Domain: domain,
	}); err != nil {
		return nil, err
	}

	return grpcconn.DoGetGRPCClientConn(domain)
}
