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

package connect

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/client/octelium/commands/connect/controller"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func newTestReliabilityConnector(t *testing.T, opts *Opts) (*Connector, *db.DB, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the forced gVisor implementation is selected by Linux preferences")
	}
	clearTestConnectEnv(t)
	t.Setenv("OCTELIUM_DEV", "false")
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	dir, err := os.MkdirTemp("", "octelium-rel-")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "api.sock")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", socket)
	dbC, err := db.Open("memory")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, dbC.Close()) })
	opts.L3Mode = "v4"
	opts.IgnoreDNS = true
	opts.ImplementationMode = "gvisor"
	if opts.LocalDNSListenAddr == "" {
		opts.LocalDNSListenAddr = "127.0.0.1:0"
	}
	opts.UserHome = t.TempDir()
	c, err := NewConnector("example.com", opts)
	require.NoError(t, err)
	return c, dbC, socket
}

func startTestReliabilityAPI(t *testing.T, socket string, srv userv1.MainServiceServer) *grpc.Server {
	t.Helper()
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)
	return grpcSrv
}

func runTestReliabilityConnector(t *testing.T, ctx context.Context, c *Connector) (<-chan *Event, <-chan error) {
	t.Helper()
	events := make(chan *Event, 128)
	c.opts.OnEvent = func(ev *Event) {
		events <- ev
	}
	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx)
	}()
	return events, done
}

func waitTestReliabilityEvent(t *testing.T, events <-chan *Event, typ EventType, budget time.Duration) *Event {
	t.Helper()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	for {
		select {
		case ev := <-events:
			if ev.Type == typ {
				return ev
			}
		case <-timer.C:
			require.FailNow(t, "the expected connection event was not emitted", "%d", typ)
			return nil
		}
	}
}

func getTestReliabilityFreeAddrs(t *testing.T) (string, string) {
	t.Helper()
	tcpLis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpAddr := tcpLis.Addr().String()
	require.NoError(t, tcpLis.Close())
	udpLis, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	udpAddr := udpLis.LocalAddr().String()
	require.NoError(t, udpLis.Close())
	return tcpAddr, udpAddr
}

func testReliabilityDNSReady(addr string) bool {
	cl := &dns.Client{Net: "udp", Timeout: 200 * time.Millisecond}
	msg := new(dns.Msg)
	msg.SetQuestion("missing.local.example.com.", dns.TypeA)
	response, _, err := cl.Exchange(msg, addr)
	return err == nil && response.Rcode == dns.RcodeServerFailure
}

func testReliabilityTCPListening(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func TestRunGRPCReconnectsAfterAPIServerCrashAndRestart(t *testing.T) {
	var attempts atomic.Int32
	srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(testConnectInitialState()); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
	first := startTestReliabilityAPI(t, socket, srv)
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 40*time.Second)
	defer cancel()
	events, done := runTestReliabilityConnector(t, ctx, c)
	waitTestReliabilityEvent(t, events, EventTypeConnected, 10*time.Second)
	first.Stop()
	ev := waitTestReliabilityEvent(t, events, EventTypeReconnecting, 10*time.Second)
	assert.Error(t, ev.Err)
	_, err := dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err), "the controller of the lost connection must be cleaned up before reconnecting")
	time.Sleep(reconnectBackoffMax)
	select {
	case err := <-done:
		require.FailNow(t, "the client exited while the API Server was down", "%+v", err)
	default:
	}
	startTestReliabilityAPI(t, socket, srv)
	waitTestReliabilityEvent(t, events, EventTypeConnected, 15*time.Second)
	assert.Equal(t, int32(2), attempts.Load())
	cancel()
	require.NoError(t, <-done)
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
}

func TestRunGRPCKeepsRetryingTransientErrorsBeforeFirstConnection(t *testing.T) {
	transient := []codes.Code{codes.Internal, codes.ResourceExhausted, codes.Aborted}
	var attempts atomic.Int32
	srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := int(attempts.Add(1))
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if attempt <= len(transient) {
			return status.Error(transient[attempt-1], "transient Cluster error")
		}
		if err := stream.Send(testConnectInitialState()); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
	startTestReliabilityAPI(t, socket, srv)
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 40*time.Second)
	defer cancel()
	events, done := runTestReliabilityConnector(t, ctx, c)
	for _, code := range transient {
		ev := waitTestReliabilityEvent(t, events, EventTypeConnecting, 15*time.Second)
		for ev.Err == nil {
			ev = waitTestReliabilityEvent(t, events, EventTypeConnecting, 15*time.Second)
		}
		assert.Equal(t, code, status.Code(ev.Err))
	}
	waitTestReliabilityEvent(t, events, EventTypeConnected, 15*time.Second)
	assert.Equal(t, int32(len(transient)+1), attempts.Load())
	cancel()
	require.NoError(t, <-done)
}

func TestRunGRPCRetriesWhenInitialStateNeverArrives(t *testing.T) {
	if testing.Short() {
		t.Skip("waiting for the initial state timeout")
	}
	var attempts atomic.Int32
	srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if attempt == 1 {
			<-stream.Context().Done()
			return nil
		}
		if err := stream.Send(testConnectInitialState()); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
	startTestReliabilityAPI(t, socket, srv)
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 60*time.Second)
	defer cancel()
	started := time.Now()
	events, done := runTestReliabilityConnector(t, ctx, c)
	ev := waitTestReliabilityEvent(t, events, EventTypeConnecting, 5*time.Second)
	require.NoError(t, ev.Err)
	ev = waitTestReliabilityEvent(t, events, EventTypeConnecting, 30*time.Second)
	assert.ErrorContains(t, ev.Err, "initial state")
	assert.GreaterOrEqual(t, time.Since(started), 20*time.Second)
	waitTestReliabilityEvent(t, events, EventTypeConnected, 15*time.Second)
	assert.Equal(t, int32(2), attempts.Load())
	cancel()
	require.NoError(t, <-done)
}

func TestRunGRPCCancellationWhileWaitingForInitialState(t *testing.T) {
	received := make(chan struct{})
	var attempts atomic.Int32
	srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		close(received)
		<-stream.Context().Done()
		return nil
	}}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
	startTestReliabilityAPI(t, socket, srv)
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 30*time.Second)
	defer cancel()
	events, done := runTestReliabilityConnector(t, ctx, c)
	select {
	case <-received:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the client did not send its initialization request")
	}
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(3 * time.Second):
		require.FailNow(t, "the client did not stop while waiting for the initial state")
	}
	assert.Equal(t, int32(1), attempts.Load())
	var last *Event
	for {
		select {
		case ev := <-events:
			assert.NotEqual(t, EventTypeConnected, ev.Type)
			last = ev
			continue
		default:
		}
		break
	}
	require.NotNil(t, last)
	assert.Equal(t, EventTypeDisconnected, last.Type)
}

func TestRunGRPCLocalListenersAreRebuiltAcrossReconnects(t *testing.T) {
	publishedAddr, dnsAddr := getTestReliabilityFreeAddrs(t)
	_, publishedPortStr, err := net.SplitHostPort(publishedAddr)
	require.NoError(t, err)
	publishedPort, err := net.LookupPort("tcp", publishedPortStr)
	require.NoError(t, err)
	drop := make(chan struct{})
	var attempts atomic.Int32
	srv := &testConnectAPI{
		connectFn: func(stream userv1.MainService_ConnectServer) error {
			attempts.Add(1)
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(testConnectInitialState()); err != nil {
				return err
			}
			select {
			case <-drop:
				return status.Error(codes.Unavailable, "API Server restart")
			case <-stream.Context().Done():
				return nil
			}
		},
		getServiceFn: func(_ context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
			return testPublishedAPIService(req.Name, userv1.Service_Spec_TCP, 8080), nil
		},
	}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{
		UseLocalDNS:        true,
		LocalDNSListenAddr: dnsAddr,
		PublishServices:    []*PublishedService{{Name: "web", Address: "127.0.0.1", Port: publishedPort}},
	})
	startTestReliabilityAPI(t, socket, srv)
	baseline := runtime.NumGoroutine()
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 60*time.Second)
	defer cancel()
	events, done := runTestReliabilityConnector(t, ctx, c)
	for cycle := range 3 {
		waitTestReliabilityEvent(t, events, EventTypeConnected, 15*time.Second)
		require.Eventually(t, func() bool {
			return testReliabilityDNSReady(dnsAddr) && testReliabilityTCPListening(publishedAddr)
		}, 5*time.Second, 20*time.Millisecond, "the local listeners must serve again after reconnection %d", cycle)
		drop <- struct{}{}
		ev := waitTestReliabilityEvent(t, events, EventTypeReconnecting, 10*time.Second)
		assert.Equal(t, codes.Unavailable, status.Code(ev.Err))
		assert.False(t, testReliabilityDNSReady(dnsAddr), "the lost connection must release its local DNS server")
		assert.False(t, testReliabilityTCPListening(publishedAddr), "the lost connection must release its published port")
	}
	waitTestReliabilityEvent(t, events, EventTypeConnected, 15*time.Second)
	assert.Equal(t, int32(4), attempts.Load())
	cancel()
	require.NoError(t, <-done)
	tcpLis, err := net.Listen("tcp", publishedAddr)
	require.NoError(t, err, "a stopped client must release its published port")
	assert.NoError(t, tcpLis.Close())
	udpLis, err := net.ListenPacket("udp", dnsAddr)
	require.NoError(t, err, "a stopped client must release its local DNS port")
	assert.NoError(t, udpLis.Close())
	assert.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= baseline+8
	}, 10*time.Second, 50*time.Millisecond, "repeated reconnections must not leak goroutines")
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
}

func TestRunGRPCStaleDisconnectAfterReconnectIsIgnored(t *testing.T) {
	var attempts atomic.Int32
	drop, stale, fresh := make(chan struct{}), make(chan struct{}), make(chan struct{})
	srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		state := testConnectInitialState()
		if err := stream.Send(state); err != nil {
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
		select {
		case <-stale:
		case <-stream.Context().Done():
			return nil
		}
		if err := stream.Send(&userv1.ConnectResponse{
			CreatedAt: timestamppb.New(state.CreatedAt.AsTime().Add(-time.Second)),
			Event:     &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}},
		}); err != nil {
			return err
		}
		select {
		case <-fresh:
		case <-stream.Context().Done():
			return nil
		}
		if err := stream.Send(&userv1.ConnectResponse{
			CreatedAt: timestamppb.New(state.CreatedAt.AsTime().Add(time.Second)),
			Event:     &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}},
		}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
	startTestReliabilityAPI(t, socket, srv)
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 30*time.Second)
	defer cancel()
	events, done := runTestReliabilityConnector(t, ctx, c)
	waitTestReliabilityEvent(t, events, EventTypeConnected, 10*time.Second)
	close(drop)
	waitTestReliabilityEvent(t, events, EventTypeConnected, 15*time.Second)
	close(stale)
	select {
	case err := <-done:
		require.FailNow(t, "a Disconnect of the previous connection stopped the new connection", "%+v", err)
	case <-time.After(time.Second):
	}
	close(fresh)
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		require.FailNow(t, "a Disconnect of the current connection did not stop the client")
	}
	assert.Equal(t, int32(2), attempts.Load())
}

func testReliabilitySSHState() *userv1.ConnectResponse {
	msg := testConnectInitialState()
	msg.GetState().ServiceConfigs = []*userv1.ConnectionState_ServiceConfig{{
		Type: &userv1.ConnectionState_ServiceConfig_Ssh{Ssh: &userv1.ConnectionState_ServiceConfig_SSH{
			KnownHosts:     []string{"@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
			AuthorizedKeys: []string{"cert-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
		}},
	}}
	return msg
}

func TestRunGRPCCleanupFailureKeepsReconnecting(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, sshDir string)
	}{
		{"known-hosts-directory", func(t *testing.T, sshDir string) {
			require.NoError(t, os.MkdirAll(filepath.Join(sshDir, "known_hosts"), 0700))
		}},
		{"unreadable-known-hosts", func(t *testing.T, sshDir string) {
			if os.Geteuid() == 0 {
				t.Skip("root can read files without read permissions")
			}
			require.NoError(t, os.MkdirAll(sshDir, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte("example.org ssh-ed25519 AAAA\n"), 0))
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			connected := make(chan struct{}, 1)
			srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
				attempt := attempts.Add(1)
				if attempt > 2 {
					return status.Error(codes.Internal, "unexpected extra connection")
				}
				if _, err := stream.Recv(); err != nil {
					return err
				}
				if err := stream.Send(testConnectInitialState()); err != nil {
					return err
				}
				select {
				case <-connected:
				case <-stream.Context().Done():
					return nil
				}
				if attempt == 1 {
					return status.Error(codes.Unavailable, "API Server restart")
				}
				if err := stream.Send(&userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{
					Disconnect: &userv1.ConnectResponse_Disconnect{},
				}}); err != nil {
					return err
				}
				<-stream.Context().Done()
				return nil
			}}
			c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
			tt.setup(t, filepath.Join(c.opts.UserHome, ".ssh"))
			startTestReliabilityAPI(t, socket, srv)
			ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 20*time.Second)
			defer cancel()
			var events []EventType
			var journalIDs []string
			c.opts.OnEvent = func(ev *Event) {
				events = append(events, ev.Type)
				switch ev.Type {
				case EventTypeConnected:
					journal, err := dbC.GetConnectionCleanup("example.com")
					if assert.NoError(t, err, "every Connection must have its own cleanup state") {
						assert.Equal(t, cliconfigv1.ConnectionCleanup_ACTIVE, journal.Phase)
						assert.Equal(t, strconv.Itoa(os.Getpid()), journal.Metadata["pid"])
						journalIDs = append(journalIDs, journal.Id)
					}
					connected <- struct{}{}
				case EventTypeReconnecting:
					assert.Equal(t, codes.Unavailable, status.Code(ev.Err))
					_, err := dbC.GetConnectionCleanup("example.com")
					assert.True(t, dbC.ErrorIsNotFound(err), "the incomplete cleanup must be reconciled before reconnecting")
				}
			}
			err := c.Run(ctx)
			assert.ErrorContains(t, err, "Could not cleanly close the controller")
			assert.NoError(t, ctx.Err())
			assert.Equal(t, int32(2), attempts.Load())
			assert.Equal(t, []EventType{EventTypeConnecting, EventTypeConnected, EventTypeReconnecting,
				EventTypeConnected, EventTypeDisconnected}, events)
			require.Len(t, journalIDs, 2)
			assert.NotEqual(t, journalIDs[0], journalIDs[1])
			journal, err := dbC.GetConnectionCleanup("example.com")
			require.NoError(t, err, "a cleanup failure on exit must leave the cleanup state for the next launch")
			assert.Equal(t, journalIDs[1], journal.Id)
			assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, journal.Phase)
		})
	}
}

func TestRunGRPCPersistentCleanupFailureKeepsReconnecting(t *testing.T) {
	var attempts atomic.Int32
	connected := make(chan struct{}, 1)
	started := make(chan time.Time, 4)
	srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := attempts.Add(1)
		if attempt > 4 {
			return status.Error(codes.Internal, "unexpected extra connection")
		}
		started <- time.Now()
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(testReliabilitySSHState()); err != nil {
			return err
		}
		select {
		case <-connected:
		case <-stream.Context().Done():
			return nil
		}
		if attempt < 4 {
			return status.Error(codes.Unavailable, "API Server restart")
		}
		<-stream.Context().Done()
		return nil
	}}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
	t.Setenv("TMPDIR", t.TempDir())
	sshDir := filepath.Join(c.opts.UserHome, ".ssh")
	require.NoError(t, os.MkdirAll(filepath.Join(sshDir, "known_hosts"), 0700))
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	startTestReliabilityAPI(t, socket, srv)
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 30*time.Second)
	defer cancel()
	var connections, reconnections int
	var pendingID string
	c.opts.OnEvent = func(ev *Event) {
		switch ev.Type {
		case EventTypeConnected:
			connections++
			b, err := os.ReadFile(authorizedKeys)
			if assert.NoError(t, err) {
				assert.Equal(t, 1, strings.Count(string(b), "cert-authority"),
					"every Connection must install the Cluster CA exactly once")
			}
			journal, err := dbC.GetConnectionCleanup("example.com")
			if assert.NoError(t, err) {
				if pendingID == "" {
					pendingID = journal.Id
				}
				assert.Equal(t, pendingID, journal.Id, "a pending cleanup state must never be overwritten")
			}
			if connections == 4 {
				cancel()
				return
			}
			connected <- struct{}{}
		case EventTypeReconnecting:
			reconnections++
			assert.Equal(t, codes.Unavailable, status.Code(ev.Err))
			b, err := os.ReadFile(authorizedKeys)
			if assert.NoError(t, err) {
				assert.NotContains(t, string(b), "cert-authority",
					"the parts of the cleanup that can succeed must still be applied")
			}
			journal, err := dbC.GetConnectionCleanup("example.com")
			if assert.NoError(t, err, "a cleanup state that could not be reconciled must be kept") {
				assert.Equal(t, pendingID, journal.Id)
				assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, journal.Phase)
			}
		}
	}
	assert.Error(t, c.Run(ctx), "a cleanup failure on exit must be reported")
	assert.Equal(t, int32(4), attempts.Load())
	assert.Equal(t, 4, connections)
	assert.Equal(t, 3, reconnections)
	require.Len(t, started, 4)
	previous := <-started
	for range 3 {
		current := <-started
		assert.GreaterOrEqual(t, current.Sub(previous), reconnectBackoffMin)
		previous = current
	}
}

func TestRunGRPCStartFailureWithCleanupFailureReconcilesBeforeRetrying(t *testing.T) {
	var attempts atomic.Int32
	srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := attempts.Add(1)
		if attempt > 2 {
			return status.Error(codes.Internal, "unexpected extra connection")
		}
		if _, err := stream.Recv(); err != nil {
			return err
		}
		state := testConnectInitialState()
		if attempt == 1 {
			state.GetState().Addresses[0].V4 = "invalid"
		}
		if err := stream.Send(state); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
	require.NoError(t, os.MkdirAll(filepath.Join(c.opts.UserHome, ".ssh", "known_hosts"), 0700))
	startTestReliabilityAPI(t, socket, srv)
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 20*time.Second)
	defer cancel()
	var events []EventType
	c.opts.OnEvent = func(ev *Event) {
		events = append(events, ev.Type)
		switch ev.Type {
		case EventTypeConnecting:
			if ev.Err == nil {
				return
			}
			assert.ErrorContains(t, ev.Err, "Could not start controller")
			_, err := dbC.GetConnectionCleanup("example.com")
			assert.True(t, dbC.ErrorIsNotFound(err), "the incomplete cleanup must be reconciled before retrying")
		case EventTypeConnected:
			journal, err := dbC.GetConnectionCleanup("example.com")
			if assert.NoError(t, err, "the retried Connection must have its own cleanup state") {
				assert.Equal(t, cliconfigv1.ConnectionCleanup_ACTIVE, journal.Phase)
				assert.Equal(t, strconv.Itoa(os.Getpid()), journal.Metadata["pid"])
			}
			cancel()
		}
	}
	assert.Error(t, c.Run(ctx))
	assert.Equal(t, int32(2), attempts.Load())
	assert.Equal(t, []EventType{EventTypeConnecting, EventTypeConnecting, EventTypeConnected, EventTypeDisconnected}, events)
}

func TestRunGRPCCleanupFailureOnShutdownKeepsJournalForNextLaunch(t *testing.T) {
	var attempts atomic.Int32
	srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(testConnectInitialState()); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
	knownHosts := filepath.Join(c.opts.UserHome, ".ssh", "known_hosts")
	require.NoError(t, os.MkdirAll(knownHosts, 0700))
	startTestReliabilityAPI(t, socket, srv)
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 15*time.Second)
	defer cancel()
	var events []EventType
	c.opts.OnEvent = func(ev *Event) {
		events = append(events, ev.Type)
		if ev.Type == EventTypeConnected {
			cancel()
		}
	}
	assert.ErrorContains(t, c.Run(ctx), "known_hosts")
	assert.Equal(t, int32(1), attempts.Load())
	assert.Equal(t, []EventType{EventTypeConnecting, EventTypeConnected, EventTypeDisconnected}, events)
	journal, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err, "a cleanup failure on exit must leave the cleanup state for the next launch")
	assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, journal.Phase)
	require.NoError(t, os.Remove(knownHosts))
	controller.ReconcileConnectionCleanup(dbC, "example.com")
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
}

func TestRunGRPCCleanupFailureRebuildsLocalListeners(t *testing.T) {
	publishedAddr, dnsAddr := getTestReliabilityFreeAddrs(t)
	_, publishedPortStr, err := net.SplitHostPort(publishedAddr)
	require.NoError(t, err)
	publishedPort, err := net.LookupPort("tcp", publishedPortStr)
	require.NoError(t, err)
	drop := make(chan struct{})
	var attempts atomic.Int32
	srv := &testConnectAPI{
		connectFn: func(stream userv1.MainService_ConnectServer) error {
			attempts.Add(1)
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(testConnectInitialState()); err != nil {
				return err
			}
			select {
			case <-drop:
				return status.Error(codes.Unavailable, "API Server restart")
			case <-stream.Context().Done():
				return nil
			}
		},
		getServiceFn: func(_ context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
			return testPublishedAPIService(req.Name, userv1.Service_Spec_TCP, 8080), nil
		},
	}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{
		UseLocalDNS:        true,
		LocalDNSListenAddr: dnsAddr,
		PublishServices:    []*PublishedService{{Name: "web", Address: "127.0.0.1", Port: publishedPort}},
	})
	require.NoError(t, os.MkdirAll(filepath.Join(c.opts.UserHome, ".ssh", "known_hosts"), 0700))
	startTestReliabilityAPI(t, socket, srv)
	baseline := runtime.NumGoroutine()
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 60*time.Second)
	defer cancel()
	events, done := runTestReliabilityConnector(t, ctx, c)
	for cycle := range 3 {
		waitTestReliabilityEvent(t, events, EventTypeConnected, 15*time.Second)
		require.Eventually(t, func() bool {
			return testReliabilityDNSReady(dnsAddr) && testReliabilityTCPListening(publishedAddr)
		}, 5*time.Second, 20*time.Millisecond, "the local listeners must serve again after reconnection %d", cycle)
		drop <- struct{}{}
		ev := waitTestReliabilityEvent(t, events, EventTypeReconnecting, 10*time.Second)
		assert.Equal(t, codes.Unavailable, status.Code(ev.Err))
		assert.False(t, testReliabilityDNSReady(dnsAddr), "an incomplete cleanup must still release the local DNS server")
		assert.False(t, testReliabilityTCPListening(publishedAddr), "an incomplete cleanup must still release the published port")
	}
	waitTestReliabilityEvent(t, events, EventTypeConnected, 15*time.Second)
	assert.Equal(t, int32(4), attempts.Load())
	cancel()
	assert.ErrorContains(t, <-done, "known_hosts")
	tcpLis, err := net.Listen("tcp", publishedAddr)
	require.NoError(t, err, "a stopped client must release its published port")
	assert.NoError(t, tcpLis.Close())
	udpLis, err := net.ListenPacket("udp", dnsAddr)
	require.NoError(t, err, "a stopped client must release its local DNS port")
	assert.NoError(t, udpLis.Close())
	assert.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= baseline+8
	}, 10*time.Second, 50*time.Millisecond, "repeated reconnections after incomplete cleanups must not leak goroutines")
}

func TestShouldRetryRejection(t *testing.T) {
	for _, code := range allCodes {
		err := status.Error(code, "err")
		isTransient := code == codes.NotFound || code == codes.PermissionDenied
		for _, rejectedAttempts := range []int{0, 1, maxRejectedAttempts - 1, maxRejectedAttempts, maxRejectedAttempts + 1} {
			want := isTransient && rejectedAttempts < maxRejectedAttempts
			assert.False(t, shouldRetryRejection(tryConnectRet{err: err}, rejectedAttempts),
				"%s: a stop requested by the Cluster, the user or a failed cleanup is final", code)
			assert.Equal(t, want, shouldRetryRejection(tryConnectRet{err: err, needsReconnect: true}, rejectedAttempts),
				"%s after %d rejected attempts", code, rejectedAttempts)
			assert.Equal(t, want, shouldRetryRejection(tryConnectRet{
				err: errors.Wrap(err, "Could not connect to API Server"), needsReconnect: true,
			}, rejectedAttempts), "%s after %d rejected attempts", code, rejectedAttempts)
		}
	}
	assert.False(t, shouldRetryRejection(tryConnectRet{needsReconnect: true}, 0))
	assert.False(t, shouldRetryRejection(tryConnectRet{err: errors.New("Could not initialize controller"), needsReconnect: true}, 0))
}

func TestRunGRPCRetriesTransientRejectionsBeforeFirstConnection(t *testing.T) {
	for _, code := range []codes.Code{codes.NotFound, codes.PermissionDenied} {
		t.Run(code.String(), func(t *testing.T) {
			var attempts atomic.Int32
			srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
				attempt := int(attempts.Add(1))
				if _, err := stream.Recv(); err != nil {
					return err
				}
				if attempt < maxRejectedAttempts {
					return status.Error(code, "the Cluster is still starting up")
				}
				if err := stream.Send(testConnectInitialState()); err != nil {
					return err
				}
				<-stream.Context().Done()
				return nil
			}}
			c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
			startTestReliabilityAPI(t, socket, srv)
			ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 40*time.Second)
			defer cancel()
			events, done := runTestReliabilityConnector(t, ctx, c)
			for range maxRejectedAttempts - 1 {
				ev := waitTestReliabilityEvent(t, events, EventTypeConnecting, 15*time.Second)
				for ev.Err == nil {
					ev = waitTestReliabilityEvent(t, events, EventTypeConnecting, 15*time.Second)
				}
				assert.Equal(t, code, status.Code(ev.Err))
			}
			waitTestReliabilityEvent(t, events, EventTypeConnected, 15*time.Second)
			assert.Equal(t, int32(maxRejectedAttempts), attempts.Load())
			cancel()
			require.NoError(t, <-done)
		})
	}
}

func TestRunGRPCRejectionsBeforeFirstConnectionStayBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("waiting for the bounded rejection retries")
	}
	errs := []codes.Code{codes.NotFound, codes.Unavailable, codes.NotFound, codes.PermissionDenied, codes.NotFound, codes.NotFound}
	var attempts atomic.Int32
	srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := int(attempts.Add(1))
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if attempt <= len(errs) {
			return status.Error(errs[attempt-1], "rejected")
		}
		if err := stream.Send(testConnectInitialState()); err != nil {
			return err
		}
		<-stream.Context().Done()
		return nil
	}}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
	startTestReliabilityAPI(t, socket, srv)
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 45*time.Second)
	defer cancel()
	events, done := runTestReliabilityConnector(t, ctx, c)
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		require.FailNow(t, "a rejection that keeps coming back must eventually stop the client")
	}
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.True(t, isRejectedErr(err))
	assert.Equal(t, int32(len(errs)), attempts.Load(),
		"errors other than rejections must not reset the rejection budget")
	var last *Event
	for {
		select {
		case ev := <-events:
			assert.NotEqual(t, EventTypeConnected, ev.Type)
			last = ev
			continue
		default:
		}
		break
	}
	require.NotNil(t, last)
	assert.Equal(t, EventTypeDisconnected, last.Type)
	assert.Equal(t, codes.NotFound, status.Code(last.Err))
}

func TestRunGRPCInvalidArgumentStopsRejectionRetries(t *testing.T) {
	var attempts atomic.Int32
	srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if attempt == 1 {
			return status.Error(codes.NotFound, "Session UID not Found")
		}
		return status.Error(codes.InvalidArgument, "The Cluster does not support v6 only networking")
	}}
	c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
	startTestReliabilityAPI(t, socket, srv)
	ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 30*time.Second)
	defer cancel()
	err := c.Run(ctx)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, int32(2), attempts.Load())
}

func TestReliabilityKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to run unresolved regressions listed in tmp/client-reliability-report.md")
	}
	t.Run("RL-01-cleanup-failure-stops-reconnecting", func(t *testing.T) {
		var attempts atomic.Int32
		ready := make(chan struct{}, 1)
		srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
			attempt := attempts.Add(1)
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(testConnectInitialState()); err != nil {
				return err
			}
			if attempt == 1 {
				select {
				case <-ready:
				case <-stream.Context().Done():
					return nil
				}
				return status.Error(codes.Unavailable, "API Server restart")
			}
			<-stream.Context().Done()
			return nil
		}}
		c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
		require.NoError(t, os.MkdirAll(filepath.Join(c.opts.UserHome, ".ssh", "known_hosts"), 0700))
		startTestReliabilityAPI(t, socket, srv)
		ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 15*time.Second)
		defer cancel()
		events, done := runTestReliabilityConnector(t, ctx, c)
		waitTestReliabilityEvent(t, events, EventTypeConnected, 10*time.Second)
		ready <- struct{}{}
		select {
		case err := <-done:
			assert.Fail(t, "a failed controller cleanup stopped the client instead of reconnecting", "%+v", err)
		case <-time.After(8 * time.Second):
		}
		assert.Equal(t, int32(2), attempts.Load())
	})
	t.Run("RL-01-unreadable-known-hosts-stops-reconnecting", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can read files without read permissions")
		}
		var attempts atomic.Int32
		ready := make(chan struct{}, 1)
		srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
			attempt := attempts.Add(1)
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(testConnectInitialState()); err != nil {
				return err
			}
			if attempt == 1 {
				select {
				case <-ready:
				case <-stream.Context().Done():
					return nil
				}
				return status.Error(codes.Unavailable, "API Server restart")
			}
			<-stream.Context().Done()
			return nil
		}}
		c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
		sshDir := filepath.Join(c.opts.UserHome, ".ssh")
		require.NoError(t, os.MkdirAll(sshDir, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte("example.org ssh-ed25519 AAAA\n"), 0))
		startTestReliabilityAPI(t, socket, srv)
		ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 15*time.Second)
		defer cancel()
		events, done := runTestReliabilityConnector(t, ctx, c)
		waitTestReliabilityEvent(t, events, EventTypeConnected, 10*time.Second)
		ready <- struct{}{}
		select {
		case err := <-done:
			assert.Fail(t, "a user known_hosts file without read permissions stopped the client", "%+v", err)
		case <-time.After(8 * time.Second):
		}
		assert.Equal(t, int32(2), attempts.Load())
	})
	t.Run("RL-06-reconnect-backoff-jitter-at-cap", func(t *testing.T) {
		for _, attempt := range []int{3, 5, 10} {
			values := make(map[time.Duration]struct{})
			for range 200 {
				values[getReconnectBackoff(attempt)] = struct{}{}
			}
			assert.Greater(t, len(values), 1,
				"every client retries after exactly the same delay at attempt %d", attempt)
		}
	})
	t.Run("RL-07-short-lived-connections-reset-backoff", func(t *testing.T) {
		started := make(chan time.Time, 8)
		srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
			started <- time.Now()
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(testConnectInitialState()); err != nil {
				return err
			}
			return status.Error(codes.Internal, "crash right after accepting the connection")
		}}
		c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
		startTestReliabilityAPI(t, socket, srv)
		ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 30*time.Second)
		defer cancel()
		_, done := runTestReliabilityConnector(t, ctx, c)
		var times []time.Time
		for range 4 {
			select {
			case at := <-started:
				times = append(times, at)
			case <-time.After(15 * time.Second):
				require.FailNow(t, "the client stopped reconnecting")
			}
		}
		cancel()
		<-done
		assert.Greater(t, times[3].Sub(times[2]), 4*time.Second,
			"a connection dropped immediately after being established resets the backoff")
	})
	t.Run("RL-16-transient-not-found-before-first-connection", func(t *testing.T) {
		var attempts atomic.Int32
		srv := &testConnectAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
			attempt := attempts.Add(1)
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if attempt == 1 {
				return status.Error(codes.NotFound, "Session UID not Found")
			}
			if err := stream.Send(testConnectInitialState()); err != nil {
				return err
			}
			<-stream.Context().Done()
			return nil
		}}
		c, dbC, socket := newTestReliabilityConnector(t, &Opts{})
		startTestReliabilityAPI(t, socket, srv)
		ctx, cancel := context.WithTimeout(cliutils.WithDB(t.Context(), dbC), 15*time.Second)
		defer cancel()
		var connected atomic.Bool
		c.opts.OnEvent = func(ev *Event) {
			if ev.Type == EventTypeConnected {
				connected.Store(true)
				cancel()
			}
		}
		assert.NoError(t, c.Run(ctx))
		assert.True(t, connected.Load(), "a transient NotFound during a Cluster upgrade stopped the client before it connected")
	})
}
