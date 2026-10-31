//go:build !windows
// +build !windows

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
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func setTestDaemonReliabilityAPISocket(t *testing.T) string {
	t.Helper()
	socket := newTestSocketPath(t)
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", socket)
	t.Setenv("OCTELIUM_DEV", "false")
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	return socket
}

func startTestDaemonReliabilityAPI(t *testing.T, socket string, srv *testDaemonClusterAPI) *grpc.Server {
	t.Helper()
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)
	return grpcSrv
}

func connectTestDaemonReliabilityDomain(t *testing.T, ctx context.Context, srv *testServer) *daemonv1.Operation {
	t.Helper()
	op, err := srv.c.Connect(ctx, &daemonv1.ConnectRequest{
		Domain: "example.com", Options: &daemonv1.ConnectionOptions{
			L3Mode: daemonv1.ConnectionOptions_V4, ImplementationMode: daemonv1.ConnectionOptions_GVISOR,
			Dns: &daemonv1.ConnectionOptions_DNS{Mode: daemonv1.ConnectionOptions_DNS_DISABLED},
		},
	})
	require.NoError(t, err)
	return op
}

func waitTestDaemonReliabilityState(t *testing.T, ctx context.Context, srv *testServer,
	want daemonv1.ConnectionStatus_State, budget time.Duration) *daemonv1.DomainState {
	t.Helper()
	var got *daemonv1.DomainState
	require.Eventually(t, func() bool {
		snapshot, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		if err != nil || len(snapshot.Domains) != 1 {
			return false
		}
		got = snapshot.Domains[0]
		return got.Connection.State == want
	}, budget, 10*time.Millisecond, "the domain did not reach the %s state", want)
	return got
}

func TestDaemonReconnectsAfterAPIServerRestartOverIPC(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	var attempts atomic.Int32
	api := &testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(testDaemonInitialState()); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}}
	socket := setTestDaemonReliabilityAPISocket(t)
	first := startTestDaemonReliabilityAPI(t, socket, api)
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	connectTestDaemonReliabilityDomain(t, ctx, srv)
	connected := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 10*time.Second)
	require.NotNil(t, connected.Connection.ConnectedAt)
	first.Stop()
	reconnecting := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_RECONNECTING, 10*time.Second)
	require.NotNil(t, reconnecting.LastError)
	assert.True(t, reconnecting.LastError.Retryable)
	time.Sleep(3 * time.Second)
	still := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_RECONNECTING, time.Second)
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, still.Authentication.State)
	startTestDaemonReliabilityAPI(t, socket, api)
	recovered := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 15*time.Second)
	assert.Nil(t, recovered.LastError)
	assert.Equal(t, connected.Connection.ConnectedAt.AsTime(), recovered.Connection.ConnectedAt.AsTime())
	assert.Equal(t, int32(2), attempts.Load())
	_, err := srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, 10*time.Second)
	_, err = srv.srv.principal.dbC.GetConnectionCleanup("example.com")
	assert.True(t, srv.srv.principal.dbC.ErrorIsNotFound(err))
}

func TestDaemonShutdownWhileReconnectingReleasesConnection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	var attempts atomic.Int32
	drop := make(chan struct{})
	api := &testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if attempt > 1 {
			return status.Error(codes.Unavailable, "API Server unavailable")
		}
		if err := stream.Send(testDaemonInitialState()); err != nil {
			return err
		}
		select {
		case <-drop:
			return status.Error(codes.Unavailable, "API Server restart")
		case <-stream.Context().Done():
			return nil
		}
	}}
	socket := setTestDaemonReliabilityAPISocket(t)
	startTestDaemonReliabilityAPI(t, socket, api)
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	connectTestDaemonReliabilityDomain(t, ctx, srv)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 10*time.Second)
	close(drop)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_RECONNECTING, 10*time.Second)
	require.Eventually(t, func() bool {
		return attempts.Load() >= 2
	}, 10*time.Second, 10*time.Millisecond)
	_, err := srv.srv.principal.dbC.GetConnectionCleanup("example.com")
	assert.True(t, srv.srv.principal.dbC.ErrorIsNotFound(err))
	started := time.Now()
	closed := make(chan struct{})
	go func() {
		srv.close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the daemon did not shut down while its connection was reconnecting")
	}
	assert.Less(t, time.Since(started), 5*time.Second)
	stopped := attempts.Load()
	time.Sleep(6 * time.Second)
	assert.Equal(t, stopped, attempts.Load(), "a closed daemon must stop reconnecting")
}

func getTestDaemonDeadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	require.NoError(t, cmd.Run())
	return cmd.Process.Pid
}

func TestDaemonReliabilityKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to run unresolved regressions listed in tmp/client-reliability-report.md")
	}
	t.Run("RL-03-stale-crash-cleanup-is-never-reconciled", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("this test forces the Linux gVisor implementation")
		}
		api := &testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(testDaemonInitialState()); err != nil {
				return err
			}
			<-stream.Context().Done()
			return nil
		}}
		socket := setTestDaemonReliabilityAPISocket(t)
		startTestDaemonReliabilityAPI(t, socket, api)
		srv := newTestServer(t)
		authenticateTestDaemonDomain(t, srv)
		dbC := srv.srv.principal.dbC
		require.NoError(t, dbC.SetConnectionCleanup("example.com", &cliconfigv1.ConnectionCleanup{
			Id:       "crashed-daemon",
			Phase:    cliconfigv1.ConnectionCleanup_ACTIVE,
			Metadata: map[string]string{"pid": strconv.Itoa(getTestDaemonDeadPID(t))},
		}))
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		connectTestDaemonReliabilityDomain(t, ctx, srv)
		waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 10*time.Second)
		journal, err := dbC.GetConnectionCleanup("example.com")
		require.NoError(t, err)
		assert.NotEqual(t, "crashed-daemon", journal.Id,
			"the journal of a crashed daemon is neither reconciled nor replaced by the new Connection")
		assert.Equal(t, strconv.Itoa(os.Getpid()), journal.Metadata["pid"])
		_, err = srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
		require.NoError(t, err)
		waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, 10*time.Second)
		_, err = dbC.GetConnectionCleanup("example.com")
		assert.True(t, dbC.ErrorIsNotFound(err), "the stale journal outlives every later Connection")
	})
}
