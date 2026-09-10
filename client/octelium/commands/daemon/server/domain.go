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
	"github.com/pkg/errors"
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

	settings   *daemonv1.DomainSettings
	op         *operation
	lastErr    *daemonv1.Error
	isDeleting bool

	connGen      uint64
	connCancelFn context.CancelFunc
	connDoneCh   chan struct{}

	refreshCancelFn context.CancelFunc

	credMu sync.Mutex
}

func (p *principal) newDomainCtl(domain string) *domainCtl {
	return &domainCtl{
		p:         p,
		domain:    domain,
		authState: daemonv1.AuthenticationStatus_LOGGED_OUT,
		connState: daemonv1.ConnectionStatus_DISCONNECTED,
	}
}

func (d *domainCtl) setAuthenticationFromState(itm *cliconfigv1.State_Domain) bool {
	authState := daemonv1.AuthenticationStatus_AUTHENTICATED
	var authenticatedAt, authExpiresAt *timestamppb.Timestamp

	if !authenticator.HasValidRefreshToken(itm) {
		authState = daemonv1.AuthenticationStatus_LOGGED_OUT
	} else {
		authenticatedAt = itm.GetSessionTokenSetAt()
		if expiresAt := authenticator.GetRefreshTokenExpiresAt(itm); !expiresAt.IsZero() {
			authExpiresAt = pbutils.Timestamp(expiresAt)
		}
	}

	if d.authState == authState &&
		pbutils.IsEqual(d.authenticatedAt, authenticatedAt) &&
		pbutils.IsEqual(d.authExpiresAt, authExpiresAt) {
		return false
	}

	d.authState = authState
	d.authenticatedAt = authenticatedAt
	d.authExpiresAt = authExpiresAt

	return true
}

func (d *domainCtl) reloadAuthentication() bool {
	itm, err := d.p.dbC.Get(d.domain)
	if err != nil {
		zap.L().Debug("Could not read the stored credentials",
			zap.String("domain", d.domain), zap.Error(err))
		itm = nil
	}

	return d.setAuthenticationFromState(itm)
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
	return d.doBeginOperation(typ, cancelFn, false)
}

func (d *domainCtl) beginSupersedingOperation(typ daemonv1.Operation_Type,
	cancelFn context.CancelFunc) (*operation, error) {
	return d.doBeginOperation(typ, cancelFn, true)
}

func (d *domainCtl) doBeginOperation(typ daemonv1.Operation_Type,
	cancelFn context.CancelFunc, canSupersede bool) (*operation, error) {
	p := d.p

	p.mu.Lock()

	if d.isDeleting && typ != daemonv1.Operation_DELETE {
		p.mu.Unlock()
		return nil, status.Errorf(codes.FailedPrecondition,
			"The domain %s is being deleted", d.domain)
	}

	var cancelActiveFn context.CancelFunc

	if d.op != nil && !d.op.isDone() {
		if !canSupersede || !d.op.isCancellable() {
			p.mu.Unlock()
			return nil, status.Errorf(codes.FailedPrecondition,
				"There is already an active Operation for the domain %s", d.domain)
		}

		cancelActiveFn = d.op.cancelFn
		d.op.setCanceled("The Operation was superseded")
	}

	p.pruneOperations()

	ret := newOperation(d.domain, typ, cancelFn)
	ret.setState(daemonv1.Operation_RUNNING)

	d.op = ret
	p.ops[ret.id] = ret

	p.notify()

	p.mu.Unlock()

	if cancelActiveFn != nil {
		cancelActiveFn()
	}

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
			ExpiresAt: pbutils.Timestamp(time.Now().Add(authenticator.WebAuthenticationTimeout)),
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
		isAuthenticated = d.authState == daemonv1.AuthenticationStatus_AUTHENTICATED

		if err == nil && !isAuthenticated {
			err = errors.Errorf("The Cluster did not provide usable credentials")
		}

		if err != nil {
			authErr := getError(err, daemonv1.Error_AUTHENTICATION_FAILED)
			if authErr.Code != daemonv1.Error_OPERATION_CANCELED {
				d.lastErr = authErr
			}
			op.setFailed(authErr)
			return
		}

		d.lastErr = nil
		op.setState(daemonv1.Operation_SUCCEEDED)
	})

	if err != nil {
		zap.L().Debug("Could not authenticate",
			zap.String("domain", d.domain), zap.Error(err))
		return
	}

	zap.L().Debug("Successfully authenticated", zap.String("domain", d.domain))

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

	connOpts, err := getConnectOpts(opts, d.p)
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

	doneCh := make(chan struct{})

	var gen uint64

	d.p.update(func() {
		d.connGen++
		gen = d.connGen
		d.connState = daemonv1.ConnectionStatus_CONNECTING
		d.connOpts = normalizeConnectionOptions(opts)
		d.connCancelFn = cancelFn
		d.connDoneCh = doneCh
		d.lastErr = nil
	})

	connOpts.OnEvent = d.getConnectEventHandler(op, gen)

	go func() {
		defer cancelFn()

		err := conn.Run(ctx)

		d.stopRefreshLoop()

		d.p.update(func() {
			if d.connGen == gen {
				d.connState = daemonv1.ConnectionStatus_DISCONNECTED
				d.connectedAt = nil
				d.connCfg = nil
				d.connOpts = nil
				d.connCancelFn = nil
				d.connDoneCh = nil

				if err != nil {
					d.lastErr = getError(err, daemonv1.Error_CONNECTION_FAILED)
				}
			}

			if !op.isDone() {
				if err != nil {
					op.setFailed(getError(err, daemonv1.Error_CONNECTION_FAILED))
				} else {
					op.setCanceled("The Connection was closed")
				}
			}
		})

		close(doneCh)
	}()

	return d.getOperationPB(op), nil
}

func (d *domainCtl) getConnectEventHandler(op *operation, gen uint64) func(ev *connect.Event) {
	return func(ev *connect.Event) {
		var startRefresh bool

		d.p.update(func() {
			if d.connGen != gen {
				return
			}

			switch ev.Type {
			case connect.EventTypeConnecting:
				d.connState = daemonv1.ConnectionStatus_CONNECTING
			case connect.EventTypeConnected:
				d.connState = daemonv1.ConnectionStatus_CONNECTED
				d.connCfg = pbutils.Clone(ev.Connection).(*cliconfigv1.Connection)
				if d.connectedAt == nil {
					d.connectedAt = pbutils.Now()
				}
				d.lastErr = nil
				op.setState(daemonv1.Operation_SUCCEEDED)
				startRefresh = true
			case connect.EventTypeReconnecting:
				d.connState = daemonv1.ConnectionStatus_RECONNECTING
				d.connCfg = nil
				if ev.Err != nil {
					d.lastErr = getError(ev.Err, daemonv1.Error_CONNECTION_FAILED)
				}
			}
		})

		if startRefresh {
			d.startRefreshLoop()
		}
	}
}

func (d *domainCtl) startDisconnect() (*daemonv1.Operation, error) {
	op, err := d.beginSupersedingOperation(daemonv1.Operation_DISCONNECT, nil)
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
			d.lastErr = nil
			op.setState(daemonv1.Operation_SUCCEEDED)
		})
		return d.getOperationPB(op), nil
	}

	go func() {
		err := d.doDisconnect(cancelFn, doneCh)

		d.p.update(func() {
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

func (d *domainCtl) doDisconnect(cancelFn context.CancelFunc, doneCh chan struct{}) error {
	cancelFn()

	var retErr error

	if doneCh != nil {
		select {
		case <-doneCh:
		case <-time.After(disconnectTimeout):
			zap.L().Warn("Timed out waiting for the Connection to be closed",
				zap.String("domain", d.domain))
			retErr = errors.Errorf(
				"Timed out waiting for the Connection of the domain %s to be closed", d.domain)
		}
	}

	if !d.hasCredentials() {
		return retErr
	}

	ctx, cancel := context.WithTimeout(d.p.ctx(context.Background()), clusterCallTimeout)
	defer cancel()

	conn, err := client.GetGRPCClientConn(ctx, d.domain)
	if err != nil {
		zap.L().Debug("Could not connect to the Cluster API to disconnect",
			zap.String("domain", d.domain), zap.Error(err))
		return retErr
	}
	defer conn.Close()

	if _, err := userv1.NewMainServiceClient(conn).Disconnect(ctx,
		&userv1.DisconnectRequest{}); err != nil {
		zap.L().Debug("Could not disconnect at the Cluster",
			zap.String("domain", d.domain), zap.Error(err))
	}

	return retErr
}

func (d *domainCtl) startLogout() (*daemonv1.Operation, error) {
	op, err := d.beginSupersedingOperation(daemonv1.Operation_LOGOUT, nil)
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
		err := d.doDisconnectAndLogout(cancelFn, doneCh)

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

func (d *domainCtl) doDisconnectAndLogout(cancelFn context.CancelFunc, doneCh chan struct{}) error {
	var retErr error

	if cancelFn != nil {
		retErr = d.doDisconnect(cancelFn, doneCh)
	}

	if err := d.doLogout(); err != nil {
		return err
	}

	return retErr
}

func (d *domainCtl) doLogout() error {
	d.stopRefreshLoop()

	d.credMu.Lock()
	defer d.credMu.Unlock()

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

func (d *domainCtl) startDelete() (*daemonv1.Operation, error) {
	op, err := d.beginSupersedingOperation(daemonv1.Operation_DELETE, nil)
	if err != nil {
		return nil, err
	}

	d.p.mu.Lock()
	d.isDeleting = true
	cancelFn := d.connCancelFn
	doneCh := d.connDoneCh
	if cancelFn != nil {
		d.connState = daemonv1.ConnectionStatus_DISCONNECTING
	}
	d.p.notify()
	d.p.mu.Unlock()

	go func() {
		err := d.doDelete(cancelFn, doneCh)

		d.p.update(func() {
			if err != nil {
				d.isDeleting = false
				d.reloadAuthentication()
				d.lastErr = getError(err, daemonv1.Error_INTERNAL)
				op.setFailed(d.lastErr)
				return
			}

			delete(d.p.domains, d.domain)
			op.setState(daemonv1.Operation_SUCCEEDED)
		})
	}()

	return d.getOperationPB(op), nil
}

func (d *domainCtl) doDelete(cancelFn context.CancelFunc, doneCh chan struct{}) error {
	if err := d.doDisconnectAndLogout(cancelFn, doneCh); err != nil {
		return err
	}

	if err := d.p.dbC.Delete(d.domain); err != nil && !d.p.dbC.ErrorIsNotFound(err) {
		return errors.Errorf("Could not delete the local state: %+v", err)
	}

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

	var needsConnect bool

	d.p.update(func() {
		d.settings = ret

		needsConnect = ret.GetAutoConnect() &&
			d.authState == daemonv1.AuthenticationStatus_AUTHENTICATED &&
			d.connState == daemonv1.ConnectionStatus_DISCONNECTED &&
			(d.op == nil || d.op.isDone())
	})

	if needsConnect {
		if _, err := d.startConnect(nil); err != nil {
			zap.L().Debug("Could not auto-connect after the settings update",
				zap.String("domain", d.domain), zap.Error(err))
		}
	}

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

	d.credMu.Lock()
	accessToken, err := authenticator.GetAccessToken(d.p.ctx(ctx), d.domain)
	d.credMu.Unlock()

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

		d.p.updateIf(func() bool {
			isChanged := d.setAuthenticationFromState(itm)
			if d.lastErr != nil {
				d.lastErr = nil
				isChanged = true
			}

			return isChanged
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
