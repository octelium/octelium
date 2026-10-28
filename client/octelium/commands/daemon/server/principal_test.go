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
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/client/octelium/commands/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGetStoredDomains(t *testing.T) {
	canonical := &cliconfigv1.State_Domain{
		SessionToken: &authv1.SessionToken{RefreshToken: "canonical"},
		Settings:     &daemonv1.DomainSettings{AutoConnect: true},
	}
	other := &cliconfigv1.State_Domain{
		SessionToken: &authv1.SessionToken{RefreshToken: "other"},
	}

	domainMap := map[string]*cliconfigv1.State_Domain{
		"example.com":  canonical,
		"Example.com":  {SessionToken: &authv1.SessionToken{RefreshToken: "upper"}},
		"EXAMPLE.COM.": {SessionToken: &authv1.SessionToken{RefreshToken: "dot"}},
		"other.com":    other,
		"Upper.org":    {SessionToken: &authv1.SessionToken{RefreshToken: "upper"}},
		"invalid":      {SessionToken: &authv1.SessionToken{RefreshToken: "invalid"}},
	}

	for range 100 {
		ret := getStoredDomains(domainMap)

		assert.Equal(t, 3, len(ret))
		assert.Equal(t, canonical, ret["example.com"])
		assert.Equal(t, other, ret["other.com"])

		itm, ok := ret["upper.org"]
		assert.True(t, ok)
		assert.Nil(t, itm)
	}

	assert.Empty(t, getStoredDomains(nil))
}

func newTestMemoryPrincipal(t *testing.T) *principal {
	t.Helper()
	dbC, err := db.Open("memory")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	p := &principal{
		srv: &Server{ctx: ctx, instanceID: "test-instance"},
		id:  "1000", name: "test-user", homeDir: t.TempDir(), dbC: dbC,
		domains: make(map[string]*domainCtl), ops: make(map[string]*operation),
		watchers: make(map[*watcher]struct{}),
	}
	t.Cleanup(func() {
		cancel()
		p.close()
	})
	return p
}

func TestPrincipalWatchersCoalesceWithoutBlocking(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	first, second := p.addWatcher(), p.addWatcher()
	for range 1000 {
		p.update(func() {})
	}
	assert.Equal(t, uint64(1000), p.getStatus().Revision)
	assert.Len(t, first.ch, 1)
	assert.Len(t, second.ch, 1)
	<-first.ch
	p.deleteWatcher(first)
	p.update(func() {})
	assert.Empty(t, first.ch)
	assert.Len(t, second.ch, 1)
	p.deleteWatcher(second)
	assert.Empty(t, p.watchers)
}

func TestPrincipalConditionalUpdatesAndSortedDomains(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	w := p.addWatcher()
	p.updateIf(func() bool { return false })
	assert.Zero(t, p.revision)
	assert.Empty(t, w.ch)
	for _, domain := range []string{"z.example.com", "a.example.com", "m.example.com"} {
		_, err := p.getDomain(domain)
		require.NoError(t, err)
	}
	p.updateIf(func() bool { return true })
	got := p.getStatus()
	assert.Equal(t, uint64(1), got.Revision)
	assert.Equal(t, "test-instance", got.InstanceID)
	require.Len(t, got.Domains, 3)
	assert.Equal(t, "a.example.com", got.Domains[0].Domain)
	assert.Equal(t, "m.example.com", got.Domains[1].Domain)
	assert.Equal(t, "z.example.com", got.Domains[2].Domain)
	assert.True(t, got.UpdatedAt.IsValid())
	assert.Len(t, w.ch, 1)
}

func TestPrincipalPrunesOnlyExpiredCompletedOperations(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	for _, tt := range []struct {
		name  string
		state daemonv1.Operation_State
		at    *timestamppb.Timestamp
		keep  bool
	}{
		{"running", daemonv1.Operation_RUNNING, timestamppb.New(time.Now().Add(-time.Hour)), true},
		{"pending", daemonv1.Operation_PENDING, nil, true},
		{"waiting", daemonv1.Operation_WAITING_FOR_USER, nil, true},
		{"recent", daemonv1.Operation_SUCCEEDED, timestamppb.Now(), true},
		{"no-completion-time", daemonv1.Operation_FAILED, nil, true},
		{"expired-success", daemonv1.Operation_SUCCEEDED, timestamppb.New(time.Now().Add(-time.Hour)), false},
		{"expired-failure", daemonv1.Operation_FAILED, timestamppb.New(time.Now().Add(-time.Hour)), false},
		{"expired-cancel", daemonv1.Operation_CANCELED, timestamppb.New(time.Now().Add(-time.Hour)), false},
	} {
		op := newOperation("example.com", daemonv1.Operation_CONNECT, nil)
		op.state, op.completedAt = tt.state, tt.at
		p.ops[tt.name] = op
	}
	p.pruneOperations()
	assert.Len(t, p.ops, 5)
	for _, id := range []string{"running", "pending", "waiting", "recent", "no-completion-time"} {
		assert.Contains(t, p.ops, id)
	}
	_, err := p.getOperation("expired-success")
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestDomainOperationSupersessionCancelsOutsidePrincipalLock(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	d, err := p.getDomain("example.com")
	require.NoError(t, err)
	var canceled atomic.Int32
	first, err := d.beginOperation(daemonv1.Operation_CONNECT, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		canceled.Add(1)
	})
	require.NoError(t, err)
	_, err = d.beginOperation(daemonv1.Operation_AUTHENTICATE, func() {})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	second, err := d.beginSupersedingOperation(daemonv1.Operation_DISCONNECT, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(1), canceled.Load())
	assert.Equal(t, daemonv1.Operation_CANCELED, first.state)
	assert.Nil(t, first.cancelFn)
	assert.Same(t, second, d.op)
	assert.Equal(t, daemonv1.Operation_RUNNING, second.state)
	_, err = d.beginSupersedingOperation(daemonv1.Operation_LOGOUT, nil)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Equal(t, int32(1), canceled.Load())
}

func TestPrincipalConcurrentCancellationIsIdempotent(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	d, err := p.getDomain("example.com")
	require.NoError(t, err)
	var canceled atomic.Int32
	op, err := d.beginOperation(daemonv1.Operation_CONNECT, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		canceled.Add(1)
	})
	require.NoError(t, err)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := p.cancelOperation(op.id)
			assert.NoError(t, err)
			if assert.NotNil(t, got) {
				assert.Equal(t, daemonv1.Operation_CANCELED, got.State)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), canceled.Load())
	_, err = p.cancelOperation("missing")
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestDomainDeletingRejectsNewWork(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	d, err := p.getDomain("example.com")
	require.NoError(t, err)
	d.isDeleting = true
	for _, typ := range []daemonv1.Operation_Type{
		daemonv1.Operation_AUTHENTICATE, daemonv1.Operation_CONNECT, daemonv1.Operation_DISCONNECT, daemonv1.Operation_LOGOUT,
	} {
		_, err := d.beginOperation(typ, nil)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	}
	_, err = p.getDomain(d.domain)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = p.findDomain(d.domain)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = d.beginOperation(daemonv1.Operation_DELETE, nil)
	assert.NoError(t, err)
}

func TestDomainAutoConnectEligibility(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*domainCtl)
	}{
		{"deleting", func(d *domainCtl) { d.isDeleting = true }},
		{"disabled", func(d *domainCtl) { d.settings.AutoConnect = false }},
		{"logged-out", func(d *domainCtl) { d.authState = daemonv1.AuthenticationStatus_LOGGED_OUT }},
		{"authenticating", func(d *domainCtl) { d.authState = daemonv1.AuthenticationStatus_AUTHENTICATING }},
		{"connecting", func(d *domainCtl) { d.connState = daemonv1.ConnectionStatus_CONNECTING }},
		{"connected", func(d *domainCtl) { d.connState = daemonv1.ConnectionStatus_CONNECTED }},
		{"reconnecting", func(d *domainCtl) { d.connState = daemonv1.ConnectionStatus_RECONNECTING }},
		{"disconnecting", func(d *domainCtl) { d.connState = daemonv1.ConnectionStatus_DISCONNECTING }},
		{"active-operation", func(d *domainCtl) { d.op = newOperation(d.domain, daemonv1.Operation_AUTHENTICATE, nil) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := &domainCtl{
				domain: "example.com", authState: daemonv1.AuthenticationStatus_AUTHENTICATED,
				connState: daemonv1.ConnectionStatus_DISCONNECTED,
				settings:  &daemonv1.DomainSettings{AutoConnect: true},
			}
			assert.True(t, d.needsAutoConnect())
			tt.change(d)
			assert.False(t, d.needsAutoConnect())
		})
	}
}

func TestDomainAuthenticationExpiryAndReconcileGuards(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	d := p.newDomainCtl("example.com")
	valid := &cliconfigv1.State_Domain{
		SessionToken:      &authv1.SessionToken{RefreshToken: "refresh", RefreshTokenExpiresIn: 3600},
		SessionTokenSetAt: timestamppb.Now(),
	}
	assert.True(t, d.setAuthenticationFromState(valid))
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, d.authState)
	assert.NotNil(t, d.authenticatedAt)
	assert.NotNil(t, d.authExpiresAt)
	assert.False(t, d.setAuthenticationFromState(valid))
	expired := proto.Clone(valid).(*cliconfigv1.State_Domain)
	expired.SessionTokenSetAt = timestamppb.New(time.Now().Add(-2 * time.Hour))
	assert.True(t, d.setAuthenticationFromState(expired))
	assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT, d.authState)
	assert.Nil(t, d.authenticatedAt)
	assert.Nil(t, d.authExpiresAt)
	assert.False(t, d.setAuthenticationFromState(nil))
	for _, state := range []daemonv1.AuthenticationStatus_State{
		daemonv1.AuthenticationStatus_AUTHENTICATED, daemonv1.AuthenticationStatus_LOGGED_OUT,
		daemonv1.AuthenticationStatus_AUTHENTICATING, daemonv1.AuthenticationStatus_LOGGING_OUT,
	} {
		d.authState = state
		assert.Equal(t, state != daemonv1.AuthenticationStatus_AUTHENTICATING && state != daemonv1.AuthenticationStatus_LOGGING_OUT, d.canReconcile())
		d.isDeleting = true
		assert.False(t, d.canReconcile())
		d.isDeleting = false
	}
}

func TestDomainConnectRejectsConflictingStatesBeforeStarting(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	d, err := p.getDomain("example.com")
	require.NoError(t, err)
	_, err = d.startConnect(nil)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	d.authState = daemonv1.AuthenticationStatus_AUTHENTICATED
	for _, state := range []daemonv1.ConnectionStatus_State{
		daemonv1.ConnectionStatus_CONNECTING, daemonv1.ConnectionStatus_CONNECTED,
		daemonv1.ConnectionStatus_RECONNECTING, daemonv1.ConnectionStatus_DISCONNECTING,
	} {
		d.connState = state
		_, err := d.startConnect(nil)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	}
	d.connState = daemonv1.ConnectionStatus_DISCONNECTED
	_, err = d.startConnect(&daemonv1.ConnectionOptions{Mtu: 1})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, p.ops)
	assert.Nil(t, d.connDoneCh)
}

func TestDomainConnectEventsIgnoreStaleGenerationAndCloneConfig(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	d, err := p.getDomain("example.com")
	require.NoError(t, err)
	op, err := d.beginOperation(daemonv1.Operation_CONNECT, func() {})
	require.NoError(t, err)
	d.connGen = 2
	var stopErr error
	var canceled bool
	stale := d.getConnectEventHandler(op, 1, &stopErr, func() { canceled = true })
	stale(&connect.Event{Type: connect.EventTypeConnecting, Err: status.Error(codes.Unauthenticated, "old connection")})
	assert.False(t, canceled)
	assert.Nil(t, stopErr)
	assert.Nil(t, d.lastErr)
	assert.Equal(t, daemonv1.ConnectionStatus_DISCONNECTED, d.connState)
	handler := d.getConnectEventHandler(op, 2, &stopErr, func() { canceled = true })
	cfg := &cliconfigv1.Connection{Connection: &userv1.ConnectionState{L3Mode: userv1.ConnectionState_V4}}
	handler(&connect.Event{Type: connect.EventTypeConnected, Connection: cfg})
	assert.Equal(t, daemonv1.ConnectionStatus_CONNECTED, d.connState)
	assert.Equal(t, daemonv1.Operation_SUCCEEDED, op.state)
	require.NotNil(t, d.connectedAt)
	at := proto.Clone(d.connectedAt)
	cfg.Connection.L3Mode = userv1.ConnectionState_V6
	assert.Equal(t, userv1.ConnectionState_V4, d.connCfg.Connection.L3Mode)
	handler(&connect.Event{Type: connect.EventTypeReconnecting, Err: status.Error(codes.Unavailable, "restarting")})
	assert.Equal(t, daemonv1.ConnectionStatus_RECONNECTING, d.connState)
	assert.Nil(t, d.connCfg)
	assert.Equal(t, daemonv1.Error_CLUSTER_UNREACHABLE, d.lastErr.Code)
	handler(&connect.Event{Type: connect.EventTypeConnected, Connection: cfg})
	assert.True(t, proto.Equal(at, d.connectedAt))
	assert.Nil(t, d.lastErr)
	assert.False(t, canceled)
	d.stopRefreshLoop()
}

func TestDomainDisconnectWaitsForCleanupAndSupersedesConnect(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	d, err := p.getDomain("example.com")
	require.NoError(t, err)
	done := make(chan struct{})
	var canceled atomic.Int32
	cancelFn := func() {
		if canceled.Add(1) == 1 {
			close(done)
		}
	}
	connectOp, err := d.beginOperation(daemonv1.Operation_CONNECT, cancelFn)
	require.NoError(t, err)
	d.connCancelFn, d.connDoneCh = cancelFn, done
	d.connState = daemonv1.ConnectionStatus_CONNECTING
	op, err := d.startDisconnect()
	require.NoError(t, err)
	assert.Equal(t, daemonv1.Operation_CANCELED, connectOp.state)
	assert.Eventually(t, func() bool {
		got, err := p.getOperation(op.Id)
		return err == nil && got.State == daemonv1.Operation_SUCCEEDED
	}, time.Second, time.Millisecond)
	assert.GreaterOrEqual(t, canceled.Load(), int32(1))
	d.connCancelFn, d.connDoneCh = nil, nil
}

func TestDomainFinishAuthenticationRequiresUsableCredentials(t *testing.T) {
	p := newTestMemoryPrincipal(t)
	d, err := p.getDomain("example.com")
	require.NoError(t, err)
	op, err := d.beginOperation(daemonv1.Operation_AUTHENTICATE, func() {})
	require.NoError(t, err)
	d.authState = daemonv1.AuthenticationStatus_AUTHENTICATING
	d.finishAuthenticate(op, nil)
	assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT, d.authState)
	assert.Equal(t, daemonv1.Operation_FAILED, op.state)
	assert.Equal(t, daemonv1.Error_AUTHENTICATION_FAILED, d.lastErr.Code)
	assert.Contains(t, d.lastErr.Message, "usable credentials")
}

func TestDomainDisconnectTimeoutDoesNotReportSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestMemoryPrincipal(t)
		d, err := p.getDomain("example.com")
		require.NoError(t, err)
		var canceled bool
		started := time.Now()
		err = d.doDisconnect(func() { canceled = true }, make(chan struct{}))
		assert.True(t, canceled)
		assert.ErrorContains(t, err, "Timed out waiting for the Connection")
		assert.Equal(t, disconnectTimeout, time.Since(started))
	})
}

func TestDomainCloseCancelsRefreshAndWaitsForConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestMemoryPrincipal(t)
		d, err := p.getDomain("example.com")
		require.NoError(t, err)
		done := make(chan struct{})
		d.connDoneCh = done
		ctx, cancel := context.WithCancel(context.Background())
		d.connCancelFn = cancel
		go func() {
			<-ctx.Done()
			time.Sleep(time.Second)
			close(done)
		}()
		d.startRefreshLoop()
		require.NotNil(t, d.refreshCancelFn)
		started := time.Now()
		d.close()
		assert.Equal(t, time.Second, time.Since(started))
		assert.ErrorIs(t, ctx.Err(), context.Canceled)
		assert.Nil(t, d.refreshCancelFn)
		d.connCancelFn, d.connDoneCh = nil, nil
	})
}

func TestDaemonKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to run unresolved regressions listed in tmp/client-test-report.md")
	}
	t.Run("CL-007-auto-connect-after-transient-stop", func(t *testing.T) {
		p := newTestMemoryPrincipal(t)
		require.NoError(t, p.dbC.SetSessionToken("example.com", &authv1.SessionToken{
			AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 3600, RefreshTokenExpiresIn: 7200,
		}))
		d, err := p.getDomain("example.com")
		require.NoError(t, err)
		d.settings = &daemonv1.DomainSettings{AutoConnect: true}
		assert.True(t, d.needsAutoConnect())
		p.reconcile()
		p.mu.Lock()
		assert.NotEqual(t, daemonv1.ConnectionStatus_DISCONNECTED, d.connState)
		p.mu.Unlock()
	})
	t.Run("CL-008-grpc-cancellation-is-terminal", func(t *testing.T) {
		got := getError(status.Error(codes.Canceled, "operation canceled"), daemonv1.Error_CONNECTION_FAILED)
		assert.Equal(t, daemonv1.Error_OPERATION_CANCELED, got.Code)
		assert.False(t, got.Retryable)
	})
}
