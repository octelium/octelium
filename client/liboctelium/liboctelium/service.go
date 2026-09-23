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

package liboctelium

import (
	"context"

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/octelium/octelium/pkg/common/clientlogin"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service struct {
	mobilev1.UnimplementedMainServiceServer

	c *Client
}

func (svc *service) findDomain(domain string) (*domainCtl, error) {
	canonical, err := canonicalizeDomain(domain)
	if err != nil {
		return nil, err
	}

	return svc.c.findDomain(canonical)
}

func (svc *service) GetInfo(ctx context.Context,
	req *mobilev1.GetInfoRequest) (*mobilev1.GetInfoResponse, error) {
	return &mobilev1.GetInfoResponse{
		Version:                   ldflags.SemVer,
		ApiMajorVersion:           apiMajorVersion,
		ApiMinorVersion:           apiMinorVersion,
		InstanceID:                svc.c.instanceID,
		AuthenticationCallbackURL: clientlogin.AppCallbackURL,
	}, nil
}

func (svc *service) GetStatus(ctx context.Context,
	req *daemonv1.GetStatusRequest) (*daemonv1.GetStatusResponse, error) {
	svc.c.reconcile()

	return svc.c.getStatus(), nil
}

func (svc *service) Authenticate(ctx context.Context,
	req *daemonv1.AuthenticateRequest) (*daemonv1.Operation, error) {
	domain, err := canonicalizeDomain(req.Domain)
	if err != nil {
		return nil, err
	}

	if err := validateAuthenticateRequest(req); err != nil {
		return nil, err
	}

	d, err := svc.c.getDomain(domain)
	if err != nil {
		return nil, err
	}

	return d.startAuthenticate(req)
}

func validateAuthenticateRequest(req *daemonv1.AuthenticateRequest) error {
	switch req.Type.(type) {
	case *daemonv1.AuthenticateRequest_Browser_:
		return nil
	case *daemonv1.AuthenticateRequest_AuthenticationToken_:
		if req.GetAuthenticationToken().GetAuthenticationToken() == "" {
			return status.Error(codes.InvalidArgument, "The authentication Token is not set")
		}
		return nil
	case *daemonv1.AuthenticateRequest_Assertion_:
		if req.GetAssertion().GetAssertion() == "" {
			return status.Error(codes.InvalidArgument, "The assertion is not set")
		}
		return nil
	default:
		return status.Error(codes.InvalidArgument, "The authentication type is not set")
	}
}

func (svc *service) CompleteAuthentication(ctx context.Context,
	req *mobilev1.CompleteAuthenticationRequest) (*daemonv1.Operation, error) {
	if req.OperationID == "" {
		return nil, status.Error(codes.InvalidArgument, "The Operation ID is not set")
	}

	if req.CallbackURL == "" {
		return nil, status.Error(codes.InvalidArgument, "The callback URL is not set")
	}

	return svc.c.completeAuthentication(req.OperationID, req.CallbackURL)
}

func (svc *service) Connect(ctx context.Context,
	req *daemonv1.ConnectRequest) (*daemonv1.Operation, error) {
	d, err := svc.findDomain(req.Domain)
	if err != nil {
		return nil, err
	}

	return d.startConnect(req.Options)
}

func (svc *service) Disconnect(ctx context.Context,
	req *daemonv1.DisconnectRequest) (*daemonv1.Operation, error) {
	d, err := svc.findDomain(req.Domain)
	if err != nil {
		return nil, err
	}

	return d.startDisconnect()
}

func (svc *service) Logout(ctx context.Context,
	req *daemonv1.LogoutRequest) (*daemonv1.Operation, error) {
	d, err := svc.findDomain(req.Domain)
	if err != nil {
		return nil, err
	}

	return d.startLogout()
}

func (svc *service) DeleteDomain(ctx context.Context,
	req *daemonv1.DeleteDomainRequest) (*daemonv1.Operation, error) {
	d, err := svc.findDomain(req.Domain)
	if err != nil {
		return nil, err
	}

	return d.startDelete()
}

func (svc *service) GetOperation(ctx context.Context,
	req *daemonv1.GetOperationRequest) (*daemonv1.Operation, error) {
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "The Operation ID is not set")
	}

	return svc.c.getOperation(req.Id)
}

func (svc *service) CancelOperation(ctx context.Context,
	req *daemonv1.CancelOperationRequest) (*daemonv1.Operation, error) {
	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "The Operation ID is not set")
	}

	return svc.c.cancelOperation(req.Id)
}

func (svc *service) GetAPICredential(ctx context.Context,
	req *daemonv1.GetAPICredentialRequest) (*daemonv1.GetAPICredentialResponse, error) {
	d, err := svc.findDomain(req.Domain)
	if err != nil {
		return nil, err
	}

	return d.getAPICredential(ctx)
}

func (svc *service) UpdateDomainSettings(ctx context.Context,
	req *daemonv1.UpdateDomainSettingsRequest) (*daemonv1.DomainSettings, error) {
	if req.Settings == nil {
		return nil, status.Error(codes.InvalidArgument, "The settings are not set")
	}

	domain, err := canonicalizeDomain(req.Domain)
	if err != nil {
		return nil, err
	}

	if _, err := getConnectOpts(req.Settings.GetConnectionOptions()); err != nil {
		return nil, err
	}

	d, err := svc.c.getDomain(domain)
	if err != nil {
		return nil, err
	}

	return d.updateSettings(req.Settings)
}

func (svc *service) SetNetworkState(ctx context.Context,
	req *mobilev1.SetNetworkStateRequest) (*mobilev1.SetNetworkStateResponse, error) {
	svc.c.network.set(req.IsAvailable, req.Id)

	return &mobilev1.SetNetworkStateResponse{}, nil
}
