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
	"sync"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/client"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octelium/commands/connect"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	accessTokenRefreshInterval = 5 * time.Minute
	clusterCallTimeout         = 10 * time.Second
	disconnectTimeout          = 30 * time.Second
)

type domainCtl struct {
	p      *principal
	domain string

	authState       daemonv1.AuthenticationStatus_State
	authenticatedAt *timestamppb.Timestamp
	authExpiresAt   *timestamppb.Timestamp

	connState   daemonv1.ConnectionStatus_State
	connectedAt *timestamppb.Timestamp
	connCfg     *cliconfigv1.Connection
	connOpts    *daemonv1.ConnectionOptions

	settings *daemonv1.DomainSettings
	op       *operation
	lastErr  *daemonv1.Error

	connCancelFn context.CancelFunc
	connDoneCh   chan struct{}

	refreshCancelFn context.CancelFunc

	tokenMu sync.Mutex
}

func (p *principal) newDomainCtl(domain string) *domainCtl {
	return &domainCtl{
		p:         p,
		domain:    domain,
		authState: daemonv1.AuthenticationStatus_LOGGED_OUT,
		connState: daemonv1.ConnectionStatus_DISCONNECTED,
	}
}

func (d *domainCtl) setAuthenticationFromState(itm *cliconfigv1.State_Domain) {
	if !authenticator.HasValidRefreshToken(itm) {
		d.authState = daemonv1.AuthenticationStatus_LOGGED_OUT
		d.authenticatedAt = nil
		d.authExpiresAt = nil
		return
	}

	d.authState = daemonv1.AuthenticationStatus_AUTHENTICATED
	d.authenticatedAt = itm.GetSessionTokenSetAt()
	if expiresAt := authenticator.GetRefreshTokenExpiresAt(itm); !expiresAt.IsZero() {
		d.authExpiresAt = pbutils.Timestamp(expiresAt)
	}
}

func (d *domainCtl) reloadAuthentication() {
	itm, err := d.p.dbC.Get(d.domain)
	if err != nil {
		zap.L().Debug("Could not read the stored credentials",
			zap.String("domain", d.domain), zap.Error(err))
		itm = nil
	}

	d.setAuthenticationFromState(itm)
}

func (d *domainCtl) toPB() *daemonv1.DomainState {
	ret := &daemonv1.DomainState{
		Domain: d.domain,
		Authentication: &daemonv1.AuthenticationStatus{
			State:           d.authState,
			AuthenticatedAt: d.authenticatedAt,
			ExpiresAt:       d.authExpiresAt,
		},
		Connection: &daemonv1.ConnectionStatus{
			State:       d.connState,
			ConnectedAt: d.connectedAt,
			Options:     d.connOpts,
		},
		LastError: d.lastErr,
		Settings:  d.getSettings(),
	}

	if d.op != nil {
		ret.LastOperation = d.op.toPB()
	}

	setConnectionStatusFromConnection(ret.Connection, d.connCfg)

	return ret
}

func (d *domainCtl) getSettings() *daemonv1.DomainSettings {
	if d.settings == nil {
		return &daemonv1.DomainSettings{
			Domain: d.domain,
		}
	}

	return d.settings
}

func (d *domainCtl) beginOperation(typ daemonv1.Operation_Type,
	cancelFn context.CancelFunc) (*operation, error) {
	p := d.p

	p.mu.Lock()
	defer p.mu.Unlock()

	if d.op != nil && !d.op.isDone() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"There is already an active Operation for the domain %s", d.domain)
	}

	p.pruneOperations()

	ret := newOperation(d.domain, typ, cancelFn)
	ret.setState(daemonv1.Operation_RUNNING)

	d.op = ret
	p.ops[ret.id] = ret

	p.notify()

	return ret, nil
}

func (d *domainCtl) getOperationPB(op *operation) *daemonv1.Operation {
	d.p.mu.Lock()
	defer d.p.mu.Unlock()

	return op.toPB()
}

func (d *domainCtl) startAuthenticate(req *daemonv1.AuthenticateRequest) (*daemonv1.Operation, error) {
	switch req.Type.(type) {
	case *daemonv1.AuthenticateRequest_Browser_:
		return d.startAuthenticateBrowser(req)
	case *daemonv1.AuthenticateRequest_AuthenticationToken_:
		return d.startAuthenticateWithOpts(req, &authenticator.AuthenticateOpts{
			Domain:    d.domain,
			Scopes:    req.Scopes,
			AuthToken: req.GetAuthenticationToken().GetAuthenticationToken(),
		})
	case *daemonv1.AuthenticateRequest_Assertion_:
		return d.startAuthenticateWithOpts(req, &authenticator.AuthenticateOpts{
			Domain: d.domain,
			Scopes: req.Scopes,
			Assertion: &authenticator.AuthenticateOptsAssertion{
				Assertion:           req.GetAssertion().GetAssertion(),
				IdentityProviderRef: req.GetAssertion().GetIdentityProviderRef(),
			},
		})
	default:
		return nil, status.Error(codes.InvalidArgument, "The authentication type is not set")
	}
}

func (d *domainCtl) startAuthenticateBrowser(req *daemonv1.AuthenticateRequest) (*daemonv1.Operation, error) {
	webC, err := authenticator.NewWebAuthenticator(&authenticator.WebAuthenticatorOpts{
		Domain: d.domain,
		Scopes: req.Scopes,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"Could not initialize the web authentication: %s", err.Error())
	}

	ctx, cancelFn := context.WithCancel(d.p.opCtx())

	if err := webC.Start(ctx); err != nil {
		cancelFn()
		webC.Close()
		return nil, status.Errorf(codes.Internal,
			"Could not start the authentication callback server: %s", err.Error())
	}

	op, err := d.beginOperation(daemonv1.Operation_AUTHENTICATE, cancelFn)
	if err != nil {
		cancelFn()
		webC.Close()
		return nil, err
	}

	d.p.update(func() {
		op.action = &daemonv1.Action{
			Type: &daemonv1.Action_OpenURL_{
				OpenURL: &daemonv1.Action_OpenURL{
					Url: webC.GetLoginURL(),
				},
			},
		}
		op.setState(daemonv1.Operation_WAITING_FOR_USER)
		d.authState = daemonv1.AuthenticationStatus_AUTHENTICATING
		d.lastErr = nil
	})

	go func() {
		defer webC.Close()
		defer cancelFn()

		d.finishAuthenticate(op, webC.Wait(ctx))
	}()

	return d.getOperationPB(op), nil
}

func (d *domainCtl) startAuthenticateWithOpts(req *daemonv1.AuthenticateRequest,
	opts *authenticator.AuthenticateOpts) (*daemonv1.Operation, error) {

	ctx, cancelFn := context.WithCancel(d.p.opCtx())

	op, err := d.beginOperation(daemonv1.Operation_AUTHENTICATE, cancelFn)
	if err != nil {
		cancelFn()
		return nil, err
	}

	d.p.update(func() {
		d.authState = daemonv1.AuthenticationStatus_AUTHENTICATING
		d.lastErr = nil
	})

	go func() {
		defer cancelFn()

		d.finishAuthenticate(op, authenticator.Authenticate(ctx, opts))
	}()

	return d.getOperationPB(op), nil
}

func (d *domainCtl) finishAuthenticate(op *operation, err error) {
	var isAuthenticated bool
	var autoConnect bool

	d.p.update(func() {
		d.reloadAuthentication()

		autoConnect = d.getSettings().GetAutoConnect()

		if err != nil {
			authErr := getError(err, daemonv1.Error_AUTHENTICATION_FAILED)
			if authErr.Code != daemonv1.Error_OPERATION_CANCELED {
				d.lastErr = authErr
			}
			op.setFailed(authErr)
			return
		}

		op.setState(daemonv1.Operation_SUCCEEDED)
		isAuthenticated = d.authState == daemonv1.AuthenticationStatus_AUTHENTICATED
	})

	if err != nil {
		zap.L().Debug("Could not authenticate",
			zap.String("domain", d.domain), zap.Error(err))
		return
	}

	zap.L().Debug("Successfully authenticated", zap.String("domain", d.domain))

	if !isAuthenticated {
		return
	}

	if autoConnect {
		if _, err := d.startConnect(nil); err != nil {
			zap.L().Debug("Could not auto-connect after the authentication",
				zap.String("domain", d.domain), zap.Error(err))
		}
	}
}

func (d *domainCtl) startConnect(opts *daemonv1.ConnectionOptions) (*daemonv1.Operation, error) {
	d.p.mu.Lock()
	authState := d.authState
	connState := d.connState
	if opts == nil {
		opts = d.getSettings().GetConnectionOptions()
	}
	d.p.mu.Unlock()

	if authState != daemonv1.AuthenticationStatus_AUTHENTICATED {
		return nil, status.Errorf(codes.Unauthenticated,
			"You are not authenticated to the domain %s", d.domain)
	}

	switch connState {
	case daemonv1.ConnectionStatus_DISCONNECTED:
	case daemonv1.ConnectionStatus_DISCONNECTING:
		return nil, status.Errorf(codes.FailedPrecondition,
			"The domain %s is still disconnecting", d.domain)
	default:
		return nil, status.Errorf(codes.FailedPrecondition,
			"The domain %s is already connected", d.domain)
	}

	connOpts, err := getConnectOpts(opts, d.p.id)
	if err != nil {
		return nil, err
	}

	conn, err := connect.NewConnector(d.domain, connOpts)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	ctx, cancelFn := context.WithCancel(d.p.opCtx())

	op, err := d.beginOperation(daemonv1.Operation_CONNECT, cancelFn)
	if err != nil {
		cancelFn()
		return nil, err
	}

	connOpts.OnEvent = d.getConnectEventHandler(op)

	doneCh := make(chan struct{})

	d.p.update(func() {
		d.connState = daemonv1.ConnectionStatus_CONNECTING
		d.connOpts = normalizeConnectionOptions(opts)
		d.connCancelFn = cancelFn
		d.connDoneCh = doneCh
		d.lastErr = nil
	})

	go func() {
		defer cancelFn()

		err := conn.Run(ctx)

		d.stopRefreshLoop()

		d.p.update(func() {
			d.connState = daemonv1.ConnectionStatus_DISCONNECTED
			d.connectedAt = nil
			d.connCfg = nil
			d.connOpts = nil
			d.connCancelFn = nil
			d.connDoneCh = nil

			if err != nil {
				d.lastErr = getError(err, daemonv1.Error_CONNECTION_FAILED)
			}

			if !op.isDone() {
				if err != nil {
					op.setFailed(d.lastErr)
				} else {
					op.setState(daemonv1.Operation_CANCELED)
				}
			}
		})

		close(doneCh)
	}()

	return d.getOperationPB(op), nil
}

func (d *domainCtl) getConnectEventHandler(op *operation) func(ev *connect.Event) {
	return func(ev *connect.Event) {
		defer func() {
			if ev.Type == connect.EventTypeConnected {
				d.startRefreshLoop()
			}
		}()

		d.p.update(func() {
			switch ev.Type {
			case connect.EventTypeConnecting:
				d.connState = daemonv1.ConnectionStatus_CONNECTING
			case connect.EventTypeConnected:
				d.connState = daemonv1.ConnectionStatus_CONNECTED
				d.connCfg = ev.Connection
				if d.connectedAt == nil {
					d.connectedAt = pbutils.Now()
				}
				d.lastErr = nil
				op.setState(daemonv1.Operation_SUCCEEDED)
			case connect.EventTypeReconnecting:
				d.connState = daemonv1.ConnectionStatus_RECONNECTING
				d.connCfg = nil
				if ev.Err != nil {
					d.lastErr = getError(ev.Err, daemonv1.Error_CONNECTION_FAILED)
				}
			}
		})
	}
}

func (d *domainCtl) startDisconnect() (*daemonv1.Operation, error) {
	op, err := d.beginOperation(daemonv1.Operation_DISCONNECT, nil)
	if err != nil {
		return nil, err
	}

	d.p.mu.Lock()
	cancelFn := d.connCancelFn
	doneCh := d.connDoneCh
	if cancelFn != nil {
		d.connState = daemonv1.ConnectionStatus_DISCONNECTING
	}
	d.p.notify()
	d.p.mu.Unlock()

	if cancelFn == nil {
		d.p.update(func() {
			op.setState(daemonv1.Operation_SUCCEEDED)
		})
		return d.getOperationPB(op), nil
	}

	go func() {
		d.doDisconnect(cancelFn, doneCh)

		d.p.update(func() {
			op.setState(daemonv1.Operation_SUCCEEDED)
		})
	}()

	return d.getOperationPB(op), nil
}

func (d *domainCtl) doDisconnect(cancelFn context.CancelFunc, doneCh chan struct{}) {
	cancelFn()

	if doneCh != nil {
		select {
		case <-doneCh:
		case <-time.After(disconnectTimeout):
			zap.L().Warn("Timed out waiting for the Connection to be closed",
				zap.String("domain", d.domain))
		}
	}

	if !d.hasCredentials() {
		return
	}

	ctx, cancel := context.WithTimeout(d.p.ctx(context.Background()), clusterCallTimeout)
	defer cancel()

	conn, err := client.GetGRPCClientConn(ctx, d.domain)
	if err != nil {
		zap.L().Debug("Could not connect to the Cluster API to disconnect",
			zap.String("domain", d.domain), zap.Error(err))
		return
	}
	defer conn.Close()

	if _, err := userv1.NewMainServiceClient(conn).Disconnect(ctx,
		&userv1.DisconnectRequest{}); err != nil {
		zap.L().Debug("Could not disconnect at the Cluster",
			zap.String("domain", d.domain), zap.Error(err))
	}
}

func (d *domainCtl) startLogout() (*daemonv1.Operation, error) {
	op, err := d.beginOperation(daemonv1.Operation_LOGOUT, nil)
	if err != nil {
		return nil, err
	}

	d.p.mu.Lock()
	cancelFn := d.connCancelFn
	doneCh := d.connDoneCh
	if cancelFn != nil {
		d.connState = daemonv1.ConnectionStatus_DISCONNECTING
	}
	d.authState = daemonv1.AuthenticationStatus_LOGGING_OUT
	d.p.notify()
	d.p.mu.Unlock()

	go func() {
		if cancelFn != nil {
			d.doDisconnect(cancelFn, doneCh)
		}

		err := d.doLogout()

		d.p.update(func() {
			d.reloadAuthentication()
			if err != nil {
				d.lastErr = getError(err, daemonv1.Error_INTERNAL)
				op.setFailed(d.lastErr)
				return
			}

			d.lastErr = nil
			op.setState(daemonv1.Operation_SUCCEEDED)
		})
	}()

	return d.getOperationPB(op), nil
}

func (d *domainCtl) doLogout() error {
	d.stopRefreshLoop()

	if !d.hasCredentials() {
		return nil
	}

	ctx, cancel := context.WithTimeout(d.p.ctx(context.Background()), clusterCallTimeout)
	defer cancel()

	if c, err := cliutils.NewAuthClient(ctx, d.domain, nil); err == nil {
		defer c.Close()
		if _, err := c.C().Logout(ctx, &authv1.LogoutRequest{}); err != nil &&
			!grpcerr.IsUnauthenticated(err) {
			zap.L().Debug("Could not log out at the Cluster",
				zap.String("domain", d.domain), zap.Error(err))
		}
	} else {
		zap.L().Debug("Could not create an auth client to log out",
			zap.String("domain", d.domain), zap.Error(err))
	}

	if err := d.p.dbC.DeleteSessionToken(d.domain); err != nil &&
		!d.p.dbC.ErrorIsNotFound(err) {
		return err
	}

	return nil
}

func (d *domainCtl) hasCredentials() bool {
	_, err := d.p.dbC.GetSessionToken(d.domain)
	return err == nil
}

func (d *domainCtl) delete() error {
	d.p.mu.Lock()
	if d.op != nil && !d.op.isDone() {
		d.p.mu.Unlock()
		return status.Errorf(codes.FailedPrecondition,
			"There is already an active Operation for the domain %s", d.domain)
	}
	cancelFn := d.connCancelFn
	doneCh := d.connDoneCh
	d.p.mu.Unlock()

	if cancelFn != nil {
		d.doDisconnect(cancelFn, doneCh)
	}

	if err := d.doLogout(); err != nil {
		zap.L().Debug("Could not log out while deleting the domain",
			zap.String("domain", d.domain), zap.Error(err))
	}

	if err := d.p.dbC.Delete(d.domain); err != nil && !d.p.dbC.ErrorIsNotFound(err) {
		return status.Errorf(codes.Internal, "Could not delete the local state: %s", err.Error())
	}

	d.p.update(func() {
		delete(d.p.domains, d.domain)
	})

	return nil
}

func (d *domainCtl) updateSettings(settings *daemonv1.DomainSettings) (*daemonv1.DomainSettings, error) {
	ret := &daemonv1.DomainSettings{
		Domain:            d.domain,
		AutoConnect:       settings.GetAutoConnect(),
		ConnectionOptions: settings.GetConnectionOptions(),
	}

	if err := d.p.dbC.SetDomainSettings(d.domain, ret); err != nil {
		return nil, status.Errorf(codes.Internal, "Could not store the settings: %s", err.Error())
	}

	d.p.update(func() {
		d.settings = ret
	})

	return ret, nil
}

func (d *domainCtl) getAPICredential(ctx context.Context) (*daemonv1.GetAPICredentialResponse, error) {
	d.p.mu.Lock()
	authState := d.authState
	d.p.mu.Unlock()

	switch authState {
	case daemonv1.AuthenticationStatus_AUTHENTICATED, daemonv1.AuthenticationStatus_AUTHENTICATING:
	default:
		return nil, status.Errorf(codes.Unauthenticated,
			"You are not authenticated to the domain %s", d.domain)
	}

	d.tokenMu.Lock()
	accessToken, err := authenticator.GetAccessToken(d.p.ctx(ctx), d.domain)
	d.tokenMu.Unlock()

	if err != nil {
		d.p.update(func() {
			d.reloadAuthentication()
			d.lastErr = getError(err, daemonv1.Error_AUTHENTICATION_FAILED)
		})

		if grpcerr.IsUnauthenticated(err) {
			return nil, status.Errorf(codes.Unauthenticated,
				"You are not authenticated to the domain %s", d.domain)
		}

		return nil, status.Errorf(codes.Internal,
			"Could not get an access token: %s", err.Error())
	}

	if accessToken == "" {
		return nil, status.Errorf(codes.Unauthenticated,
			"You are not authenticated to the domain %s", d.domain)
	}

	ret := &daemonv1.GetAPICredentialResponse{
		AccessToken: accessToken,
	}

	if itm, err := d.p.dbC.Get(d.domain); err == nil {
		if expiresAt := authenticator.GetAccessTokenExpiresAt(itm); !expiresAt.IsZero() {
			ret.ExpiresAt = pbutils.Timestamp(expiresAt)
		}

		d.p.update(func() {
			d.setAuthenticationFromState(itm)
		})
	}

	return ret, nil
}

func (d *domainCtl) startRefreshLoop() {
	ctx, cancelFn := context.WithCancel(d.p.opCtx())

	d.p.mu.Lock()
	if d.refreshCancelFn != nil {
		d.p.mu.Unlock()
		cancelFn()
		return
	}
	d.refreshCancelFn = cancelFn
	d.p.mu.Unlock()

	go func() {
		tickerCh := time.NewTicker(accessTokenRefreshInterval)
		defer tickerCh.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-tickerCh.C:
				if _, err := d.getAPICredential(ctx); err != nil {
					zap.L().Debug("Could not renew the access token",
						zap.String("domain", d.domain), zap.Error(err))
				}
			}
		}
	}()
}

func (d *domainCtl) stopRefreshLoop() {
	d.p.mu.Lock()
	cancelFn := d.refreshCancelFn
	d.refreshCancelFn = nil
	d.p.mu.Unlock()

	if cancelFn != nil {
		cancelFn()
	}
}

func (d *domainCtl) cancelOperation(op *operation) {
	d.p.mu.Lock()
	cancelFn := op.cancelFn
	connCancelFn := d.connCancelFn
	isConnect := op.typ == daemonv1.Operation_CONNECT
	d.p.mu.Unlock()

	if cancelFn != nil {
		cancelFn()
	}

	if isConnect && connCancelFn != nil {
		connCancelFn()
	}

	d.p.update(func() {
		if !op.isDone() && op.typ != daemonv1.Operation_CONNECT {
			op.setFailed(&daemonv1.Error{
				Code:    daemonv1.Error_OPERATION_CANCELED,
				Message: "The Operation was canceled",
			})
		}
	})
}

func (d *domainCtl) close() {
	d.stopRefreshLoop()

	d.p.mu.Lock()
	cancelFn := d.connCancelFn
	doneCh := d.connDoneCh
	d.p.mu.Unlock()

	if cancelFn == nil {
		return
	}

	cancelFn()

	if doneCh == nil {
		return
	}

	select {
	case <-doneCh:
	case <-time.After(disconnectTimeout):
		zap.L().Warn("Timed out waiting for the Connection to be closed",
			zap.String("domain", d.domain))
	}
}
