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

package server

import (
	"context"

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/octelium/commands/daemon/ipc"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type service struct {
	daemonv1.UnimplementedMainServiceServer

	s *Server
}

func (svc *service) getPrincipal(ctx context.Context) (*principal, error) {
	pr, err := ipc.GetPrincipal(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return svc.s.getPrincipal(pr)
}

func (svc *service) findDomain(ctx context.Context, domain string) (*domainCtl, error) {
	p, err := svc.getPrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := validateDomain(domain); err != nil {
		return nil, err
	}

	return p.findDomain(domain)
}

func (svc *service) GetInfo(ctx context.Context,
	req *daemonv1.GetInfoRequest) (*daemonv1.GetInfoResponse, error) {
	pr, err := ipc.GetPrincipal(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &daemonv1.GetInfoResponse{
		Version:         ldflags.SemVer,
		ApiMajorVersion: apiMajorVersion,
		ApiMinorVersion: apiMinorVersion,
		InstanceID:      svc.s.instanceID,
		Principal: &daemonv1.Principal{
			Id:   pr.ID,
			Name: pr.Name,
		},
	}, nil
}

func (svc *service) GetStatus(ctx context.Context,
	req *daemonv1.GetStatusRequest) (*daemonv1.GetStatusResponse, error) {
	p, err := svc.getPrincipal(ctx)
	if err != nil {
		return nil, err
	}

	return p.getStatus(), nil
}

func (svc *service) WatchStatus(req *daemonv1.WatchStatusRequest,
	srv daemonv1.MainService_WatchStatusServer) error {
	ctx := srv.Context()

	p, err := svc.getPrincipal(ctx)
	if err != nil {
		return err
	}

	w := p.addWatcher()
	defer p.deleteWatcher(w)

	for {
		if err := srv.Send(p.getStatus()); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-svc.s.ctx.Done():
			return status.Error(codes.Unavailable, "The daemon is shutting down")
		case <-w.ch:
		}
	}
}

func (svc *service) Authenticate(ctx context.Context,
	req *daemonv1.AuthenticateRequest) (*daemonv1.Operation, error) {
	p, err := svc.getPrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := validateDomain(req.Domain); err != nil {
		return nil, err
	}

	if err := validateAuthenticateRequest(req); err != nil {
		return nil, err
	}

	d, err := p.getDomain(req.Domain)
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

func (svc *service) Connect(ctx context.Context,
	req *daemonv1.ConnectRequest) (*daemonv1.Operation, error) {
	d, err := svc.findDomain(ctx, req.Domain)
	if err != nil {
		return nil, err
	}

	return d.startConnect(req.Options)
}

func (svc *service) Disconnect(ctx context.Context,
	req *daemonv1.DisconnectRequest) (*daemonv1.Operation, error) {
	d, err := svc.findDomain(ctx, req.Domain)
	if err != nil {
		return nil, err
	}

	return d.startDisconnect()
}

func (svc *service) Logout(ctx context.Context,
	req *daemonv1.LogoutRequest) (*daemonv1.Operation, error) {
	d, err := svc.findDomain(ctx, req.Domain)
	if err != nil {
		return nil, err
	}

	return d.startLogout()
}

func (svc *service) DeleteDomain(ctx context.Context,
	req *daemonv1.DeleteDomainRequest) (*metav1.OperationResult, error) {
	d, err := svc.findDomain(ctx, req.Domain)
	if err != nil {
		return nil, err
	}

	if err := d.delete(); err != nil {
		return nil, err
	}

	return &metav1.OperationResult{}, nil
}

func (svc *service) GetOperation(ctx context.Context,
	req *daemonv1.GetOperationRequest) (*daemonv1.Operation, error) {
	p, err := svc.getPrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "The Operation ID is not set")
	}

	return p.getOperation(req.Id)
}

func (svc *service) CancelOperation(ctx context.Context,
	req *daemonv1.CancelOperationRequest) (*daemonv1.Operation, error) {
	p, err := svc.getPrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "The Operation ID is not set")
	}

	p.mu.Lock()
	op, ok := p.ops[req.Id]
	p.mu.Unlock()

	if !ok {
		return nil, status.Errorf(codes.NotFound, "Unknown Operation: %s", req.Id)
	}

	d, err := p.findDomain(op.domain)
	if err != nil {
		return nil, err
	}

	d.cancelOperation(op)

	return p.getOperation(req.Id)
}

func (svc *service) GetAPICredential(ctx context.Context,
	req *daemonv1.GetAPICredentialRequest) (*daemonv1.GetAPICredentialResponse, error) {
	d, err := svc.findDomain(ctx, req.Domain)
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

	p, err := svc.getPrincipal(ctx)
	if err != nil {
		return nil, err
	}

	if err := validateDomain(req.Settings.Domain); err != nil {
		return nil, err
	}

	if _, err := getConnectOpts(req.Settings.GetConnectionOptions(), p.id); err != nil {
		return nil, err
	}

	d, err := p.getDomain(req.Settings.Domain)
	if err != nil {
		return nil, err
	}

	return d.updateSettings(req.Settings)
}
