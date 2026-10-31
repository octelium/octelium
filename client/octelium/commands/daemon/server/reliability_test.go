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
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/db"
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

func TestDaemonKeepsReconnectingWhenConnectionCleanupFails(t *testing.T) {
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
		if err := stream.Send(testDaemonInitialState()); err != nil {
			return err
		}
		if attempt == 1 {
			select {
			case <-drop:
				return status.Error(codes.Unavailable, "API Server restart")
			case <-stream.Context().Done():
				return nil
			}
		}
		<-stream.Context().Done()
		return nil
	}}
	socket := setTestDaemonReliabilityAPISocket(t)
	startTestDaemonReliabilityAPI(t, socket, api)
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	userHome := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(userHome, ".ssh", "known_hosts"), 0700))
	srv.srv.principal.mu.Lock()
	srv.srv.principal.homeDir = userHome
	srv.srv.principal.mu.Unlock()
	dbC := srv.srv.principal.dbC
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	connectTestDaemonReliabilityDomain(t, ctx, srv)
	connected := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 10*time.Second)
	first, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	close(drop)
	reconnecting := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_RECONNECTING, 10*time.Second)
	require.NotNil(t, reconnecting.LastError)
	assert.True(t, reconnecting.LastError.Retryable)
	recovered := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 15*time.Second)
	assert.Nil(t, recovered.LastError)
	assert.Equal(t, connected.Connection.ConnectedAt.AsTime(), recovered.Connection.ConnectedAt.AsTime())
	assert.Equal(t, int32(2), attempts.Load())
	second, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.NotEqual(t, first.Id, second.Id, "the incomplete cleanup must be reconciled before the daemon reconnects")
	assert.Equal(t, cliconfigv1.ConnectionCleanup_ACTIVE, second.Phase)
	assert.Equal(t, strconv.Itoa(os.Getpid()), second.Metadata["pid"])
	_, err = srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, 10*time.Second)
	assert.Equal(t, int32(2), attempts.Load())
}

func getTestDaemonDeadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	require.NoError(t, cmd.Run())
	return cmd.Process.Pid
}

const testDaemonUserSSHContent = "github.com ssh-ed25519 AAAAUser\n"

func getTestDaemonStaleSSHContent(domain string) string {
	return testDaemonUserSSHContent +
		"@cert-authority *." + domain + " ssh-ed25519 AAAAStale octelium-managed:" + domain + "\n"
}

func writeTestDaemonStaleSSHFiles(t *testing.T, domain string) []string {
	t.Helper()
	dir := t.TempDir()
	var ret []string
	for _, name := range []string{"known_hosts", "authorized_keys"} {
		filePath := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(filePath, []byte(getTestDaemonStaleSSHContent(domain)), 0600))
		ret = append(ret, filePath)
	}
	return ret
}

func assertTestDaemonSSHFiles(t *testing.T, paths []string, want string) {
	t.Helper()
	for _, filePath := range paths {
		content, err := os.ReadFile(filePath)
		require.NoError(t, err)
		assert.Equal(t, want, string(content), filePath)
	}
}

func newTestDaemonStaleCleanup(id string, pid int, domain string, paths []string) *cliconfigv1.ConnectionCleanup {
	return &cliconfigv1.ConnectionCleanup{
		Id:       id,
		Phase:    cliconfigv1.ConnectionCleanup_ACTIVE,
		Metadata: map[string]string{"pid": strconv.Itoa(pid)},
		Ssh:      &cliconfigv1.ConnectionCleanup_SSH{Marker: "octelium-managed:" + domain, FilePaths: paths},
	}
}

func setTestDaemonReliabilityUserHome(t *testing.T, srv *testServer) string {
	t.Helper()
	userHome := t.TempDir()
	srv.srv.principal.mu.Lock()
	srv.srv.principal.homeDir = userHome
	srv.srv.principal.mu.Unlock()
	return userHome
}

func openTestDaemonPrincipalDB(t *testing.T, dir string) *db.DB {
	t.Helper()
	dbC, err := db.OpenWithOpts(&db.Opts{Path: filepath.Join(dir, "state", "users", strconv.Itoa(os.Getuid()))})
	require.NoError(t, err)
	require.NoError(t, dbC.Migrate())
	return dbC
}

func newTestDaemonReliabilityAPI(attempts *atomic.Int32) *testDaemonClusterAPI {
	return &testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
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
}

func TestDaemonReconcilesStaleCleanupBeforeConnecting(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	var attempts atomic.Int32
	socket := setTestDaemonReliabilityAPISocket(t)
	startTestDaemonReliabilityAPI(t, socket, newTestDaemonReliabilityAPI(&attempts))
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	setTestDaemonReliabilityUserHome(t, srv)
	dbC := srv.srv.principal.dbC
	paths := writeTestDaemonStaleSSHFiles(t, "example.com")
	require.NoError(t, dbC.SetConnectionCleanup("example.com",
		newTestDaemonStaleCleanup("crashed-daemon", getTestDaemonDeadPID(t), "example.com", paths)))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	connectTestDaemonReliabilityDomain(t, ctx, srv)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 10*time.Second)
	assertTestDaemonSSHFiles(t, paths, testDaemonUserSSHContent)
	journal, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.NotEqual(t, "crashed-daemon", journal.Id)
	assert.Equal(t, cliconfigv1.ConnectionCleanup_ACTIVE, journal.Phase)
	assert.Equal(t, strconv.Itoa(os.Getpid()), journal.Metadata["pid"])
	assert.Nil(t, journal.Ssh)
	_, err = srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	disconnected := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, 10*time.Second)
	assert.Nil(t, disconnected.LastError)
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
	assert.Equal(t, int32(1), attempts.Load())
}

func TestDaemonKeepsCleanupOfRunningProcessWhenConnecting(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	var attempts atomic.Int32
	socket := setTestDaemonReliabilityAPISocket(t)
	startTestDaemonReliabilityAPI(t, socket, newTestDaemonReliabilityAPI(&attempts))
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	setTestDaemonReliabilityUserHome(t, srv)
	dbC := srv.srv.principal.dbC
	paths := writeTestDaemonStaleSSHFiles(t, "example.com")
	require.NoError(t, dbC.SetConnectionCleanup("example.com",
		newTestDaemonStaleCleanup("running-client", os.Getppid(), "example.com", paths)))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	connectTestDaemonReliabilityDomain(t, ctx, srv)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 10*time.Second)
	assertTestDaemonSSHFiles(t, paths, getTestDaemonStaleSSHContent("example.com"))
	journal, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.Equal(t, "running-client", journal.Id)
	assert.Equal(t, cliconfigv1.ConnectionCleanup_ACTIVE, journal.Phase)
	_, err = srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, 10*time.Second)
	journal, err = dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.Equal(t, "running-client", journal.Id, "the journal of another running process must never be reconciled")
	assert.Equal(t, strconv.Itoa(os.Getppid()), journal.Metadata["pid"])
	assertTestDaemonSSHFiles(t, paths, getTestDaemonStaleSSHContent("example.com"))
}

func TestDaemonConnectsWhenStaleCleanupCannotBeReconciled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	var attempts atomic.Int32
	socket := setTestDaemonReliabilityAPISocket(t)
	startTestDaemonReliabilityAPI(t, socket, newTestDaemonReliabilityAPI(&attempts))
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	setTestDaemonReliabilityUserHome(t, srv)
	dbC := srv.srv.principal.dbC
	require.NoError(t, dbC.SetConnectionCleanup("example.com",
		newTestDaemonStaleCleanup("crashed-daemon", getTestDaemonDeadPID(t), "example.com", []string{t.TempDir()})))
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	connectTestDaemonReliabilityDomain(t, ctx, srv)
	connected := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 10*time.Second)
	assert.Nil(t, connected.LastError)
	journal, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.Equal(t, "crashed-daemon", journal.Id, "a journal that could not be reconciled must be kept for a later retry")
	assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, journal.Phase)
	_, err = srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, 10*time.Second)
	journal, err = dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.Equal(t, "crashed-daemon", journal.Id)
	assert.Equal(t, int32(1), attempts.Load())
}

func TestDaemonReconcilesIncompleteCleanupOnNextConnect(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	var attempts atomic.Int32
	socket := setTestDaemonReliabilityAPISocket(t)
	startTestDaemonReliabilityAPI(t, socket, newTestDaemonReliabilityAPI(&attempts))
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	userHome := setTestDaemonReliabilityUserHome(t, srv)
	knownHosts := filepath.Join(userHome, ".ssh", "known_hosts")
	require.NoError(t, os.MkdirAll(knownHosts, 0700))
	dbC := srv.srv.principal.dbC
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	connectTestDaemonReliabilityDomain(t, ctx, srv)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 10*time.Second)
	first, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	_, err = srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, 10*time.Second)
	incomplete, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.Equal(t, first.Id, incomplete.Id)
	assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, incomplete.Phase)
	require.NoError(t, os.Remove(knownHosts))
	require.NoError(t, os.WriteFile(knownHosts, []byte(testDaemonUserSSHContent), 0600))
	connectTestDaemonReliabilityDomain(t, ctx, srv)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 10*time.Second)
	second, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.NotEqual(t, first.Id, second.Id, "the incomplete cleanup of this process must be reconciled before it connects again")
	assert.Equal(t, cliconfigv1.ConnectionCleanup_ACTIVE, second.Phase)
	assert.Equal(t, strconv.Itoa(os.Getpid()), second.Metadata["pid"])
	_, err = srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	recovered := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, 10*time.Second)
	assert.Nil(t, recovered.LastError)
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
	content, err := os.ReadFile(knownHosts)
	require.NoError(t, err)
	assert.Equal(t, testDaemonUserSSHContent, string(content))
	assert.Equal(t, int32(2), attempts.Load())
}

func TestDaemonReconcilesStaleCleanupsWhenLoading(t *testing.T) {
	dir := t.TempDir()
	dbC := openTestDaemonPrincipalDB(t, dir)
	require.NoError(t, dbC.SetSessionToken("example.com", &authv1.SessionToken{
		AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 3600, RefreshTokenExpiresIn: 7200,
	}))
	crashedPaths := writeTestDaemonStaleSSHFiles(t, "example.com")
	require.NoError(t, dbC.SetConnectionCleanup("example.com",
		newTestDaemonStaleCleanup("crashed-daemon", getTestDaemonDeadPID(t), "example.com", crashedPaths)))
	orphanPaths := writeTestDaemonStaleSSHFiles(t, "example.org")
	require.NoError(t, dbC.SetConnectionCleanup("example.org",
		newTestDaemonStaleCleanup("crashed-client", getTestDaemonDeadPID(t), "example.org", orphanPaths)))
	samePIDPaths := writeTestDaemonStaleSSHFiles(t, "example.io")
	require.NoError(t, dbC.SetConnectionCleanup("example.io",
		newTestDaemonStaleCleanup("same-pid", os.Getpid(), "example.io", samePIDPaths)))
	runningPaths := writeTestDaemonStaleSSHFiles(t, "example.net")
	require.NoError(t, dbC.SetConnectionCleanup("example.net",
		newTestDaemonStaleCleanup("running-client", os.Getppid(), "example.net", runningPaths)))
	require.NoError(t, dbC.SetConnectionCleanup("example.dev",
		newTestDaemonStaleCleanup("unreconcilable", getTestDaemonDeadPID(t), "example.dev", []string{t.TempDir()})))
	require.NoError(t, dbC.Close())
	srv := newTestServerWithDir(t, dir)
	_, err := srv.c.GetInfo(t.Context(), &daemonv1.GetInfoRequest{})
	require.NoError(t, err)
	dbC = srv.srv.principal.dbC
	assertTestDaemonSSHFiles(t, crashedPaths, testDaemonUserSSHContent)
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
	_, err = dbC.GetSessionToken("example.com")
	assert.NoError(t, err, "reconciling the journal must keep the credentials of the domain")
	assertTestDaemonSSHFiles(t, orphanPaths, testDaemonUserSSHContent)
	_, err = dbC.Get("example.org")
	assert.True(t, dbC.ErrorIsNotFound(err))
	assertTestDaemonSSHFiles(t, samePIDPaths, testDaemonUserSSHContent)
	_, err = dbC.GetConnectionCleanup("example.io")
	assert.True(t, dbC.ErrorIsNotFound(err))
	assertTestDaemonSSHFiles(t, runningPaths, getTestDaemonStaleSSHContent("example.net"))
	running, err := dbC.GetConnectionCleanup("example.net")
	require.NoError(t, err)
	assert.Equal(t, "running-client", running.Id)
	assert.Equal(t, cliconfigv1.ConnectionCleanup_ACTIVE, running.Phase)
	unreconcilable, err := dbC.GetConnectionCleanup("example.dev")
	require.NoError(t, err)
	assert.Equal(t, "unreconcilable", unreconcilable.Id)
	assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, unreconcilable.Phase)
	snapshot, err := srv.c.GetStatus(t.Context(), &daemonv1.GetStatusRequest{})
	require.NoError(t, err)
	var found bool
	for _, domain := range snapshot.Domains {
		assert.Equal(t, daemonv1.ConnectionStatus_DISCONNECTED, domain.Connection.State, domain.Domain)
		if domain.Domain == "example.com" {
			found = true
			assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, domain.Authentication.State)
		}
	}
	assert.True(t, found)
}

func TestDaemonAutoConnectsWithFreshCleanupAfterCrash(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	var attempts atomic.Int32
	socket := setTestDaemonReliabilityAPISocket(t)
	startTestDaemonReliabilityAPI(t, socket, newTestDaemonReliabilityAPI(&attempts))
	dir := t.TempDir()
	dbC := openTestDaemonPrincipalDB(t, dir)
	require.NoError(t, dbC.SetSessionToken("example.com", &authv1.SessionToken{
		AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 3600, RefreshTokenExpiresIn: 7200,
	}))
	require.NoError(t, dbC.SetDomainSettings("example.com", &daemonv1.DomainSettings{
		Domain: "example.com", AutoConnect: true, ConnectionOptions: &daemonv1.ConnectionOptions{
			L3Mode: daemonv1.ConnectionOptions_V4, ImplementationMode: daemonv1.ConnectionOptions_GVISOR,
			Dns: &daemonv1.ConnectionOptions_DNS{Mode: daemonv1.ConnectionOptions_DNS_DISABLED},
		},
	}))
	paths := writeTestDaemonStaleSSHFiles(t, "example.com")
	require.NoError(t, dbC.SetConnectionCleanup("example.com",
		newTestDaemonStaleCleanup("crashed-daemon", getTestDaemonDeadPID(t), "example.com", paths)))
	require.NoError(t, dbC.Close())
	srv := newTestServerWithDir(t, dir)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	_, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	require.NoError(t, err)
	dbC = srv.srv.principal.dbC
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 10*time.Second)
	assertTestDaemonSSHFiles(t, paths, testDaemonUserSSHContent)
	journal, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.NotEqual(t, "crashed-daemon", journal.Id)
	assert.Equal(t, cliconfigv1.ConnectionCleanup_ACTIVE, journal.Phase)
	assert.Equal(t, strconv.Itoa(os.Getpid()), journal.Metadata["pid"])
	_, err = srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, 10*time.Second)
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
	assert.Equal(t, int32(1), attempts.Load())
}

func TestDaemonConnectRetriesTransientRejection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	var attempts atomic.Int32
	api := &testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if attempt == 1 {
			return status.Error(codes.NotFound, "Session UID not Found")
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
	setTestDaemonReliabilityUserHome(t, srv)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	op := connectTestDaemonReliabilityDomain(t, ctx, srv)
	connected := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_CONNECTED, 15*time.Second)
	assert.Nil(t, connected.LastError)
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, connected.Authentication.State)
	getOp, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{Id: op.Id})
	require.NoError(t, err)
	assert.Equal(t, daemonv1.Operation_SUCCEEDED, getOp.State)
	assert.Equal(t, int32(2), attempts.Load())
	_, err = srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, 10*time.Second)
}

func TestDaemonConnectFailsAfterRepeatedRejections(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	if testing.Short() {
		t.Skip("waiting for the bounded rejection retries")
	}
	var attempts atomic.Int32
	api := &testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		return status.Error(codes.PermissionDenied, "The request is denied")
	}}
	socket := setTestDaemonReliabilityAPISocket(t)
	startTestDaemonReliabilityAPI(t, socket, api)
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	setTestDaemonReliabilityUserHome(t, srv)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	op := connectTestDaemonReliabilityDomain(t, ctx, srv)
	var getOp *daemonv1.Operation
	require.Eventually(t, func() bool {
		var err error
		getOp, err = srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{Id: op.Id})
		return err == nil && getOp.State == daemonv1.Operation_FAILED
	}, 35*time.Second, 50*time.Millisecond, "a rejection that keeps coming back must end the Connect Operation")
	require.NotNil(t, getOp.Error)
	assert.Equal(t, daemonv1.Error_PERMISSION_DENIED, getOp.Error.Code)
	disconnected := waitTestDaemonReliabilityState(t, ctx, srv, daemonv1.ConnectionStatus_DISCONNECTED, time.Second)
	require.NotNil(t, disconnected.LastError)
	assert.Equal(t, daemonv1.Error_PERMISSION_DENIED, disconnected.LastError.Code)
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, disconnected.Authentication.State)
	stopped := attempts.Load()
	assert.Greater(t, stopped, int32(1), "a rejection must be retried before the Operation fails")
	time.Sleep(3 * time.Second)
	assert.Equal(t, stopped, attempts.Load(), "a failed Connect Operation must stop retrying")
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
