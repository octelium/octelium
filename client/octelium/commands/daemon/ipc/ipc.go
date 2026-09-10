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

package ipc

import (
	"context"
	"net"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const AuthType = "octelium-local"

type Principal struct {
	ID      string
	GID     string
	Name    string
	HomeDir string
	PID     int32
}

type AuthInfo struct {
	credentials.CommonAuthInfo

	Principal *Principal
}

func (a *AuthInfo) AuthType() string {
	return AuthType
}

type TransportCredentials struct {
}

func NewTransportCredentials() credentials.TransportCredentials {
	return &TransportCredentials{}
}

func (c *TransportCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	principal, err := getPeerPrincipal(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	return conn, &AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity,
		},
		Principal: principal,
	}, nil
}

func (c *TransportCredentials) ClientHandshake(ctx context.Context,
	authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, &AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity,
		},
	}, nil
}

func (c *TransportCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: AuthType,
		SecurityVersion:  "1.0",
	}
}

func (c *TransportCredentials) Clone() credentials.TransportCredentials {
	return &TransportCredentials{}
}

func (c *TransportCredentials) OverrideServerName(_ string) error {
	return nil
}

func GetPrincipal(ctx context.Context) (*Principal, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.Errorf("Could not find the peer information of the caller")
	}

	authInfo, ok := p.AuthInfo.(*AuthInfo)
	if !ok || authInfo.Principal == nil {
		return nil, errors.Errorf("Could not find the local identity of the caller")
	}

	return authInfo.Principal, nil
}
