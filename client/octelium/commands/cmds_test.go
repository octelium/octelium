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

package commands

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect"
	"github.com/octelium/octelium/client/octelium/commands/daemon/ipc"
	"github.com/octelium/octelium/client/octelium/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCmds(t *testing.T) {
	InitCmds()
	assert.True(t, Cmd.HasSubCommands())
	assert.False(t, Cmd.Runnable())
}

type testCommandAPI struct {
	userv1.UnimplementedMainServiceServer
	connectFn    func(userv1.MainService_ConnectServer) error
	getServiceFn func(context.Context, *metav1.GetOptions) (*userv1.Service, error)
}

func (s *testCommandAPI) Connect(stream userv1.MainService_ConnectServer) error {
	return s.connectFn(stream)
}

func (s *testCommandAPI) GetService(ctx context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
	return s.getServiceFn(ctx, req)
}

func newTestCommandSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\octelium-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	}
	dir, err := os.MkdirTemp("", "oct-cli-")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	return filepath.Join(dir, "api.sock")
}

func startTestCommandAPI(t *testing.T, srv *testCommandAPI) string {
	t.Helper()
	socket := newTestCommandSocket(t)
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)
	return socket
}

type testCommandProcess struct {
	cmd    *exec.Cmd
	output bytes.Buffer
	done   chan struct{}
	err    error
}

func startTestCommand(t *testing.T, binary string, env []string, args ...string) *testCommandProcess {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	p := &testCommandProcess{done: make(chan struct{})}
	p.cmd = exec.CommandContext(ctx, binary, args...)
	for _, val := range os.Environ() {
		if !strings.HasPrefix(val, "OCTELIUM_") {
			p.cmd.Env = append(p.cmd.Env, val)
		}
	}
	p.cmd.Env = append(p.cmd.Env, "OCTELIUM_PRODUCTION=true", "OCTELIUM_DEV=false", "OCTELIUM_USER_HOME="+t.TempDir())
	p.cmd.Env = append(p.cmd.Env, env...)
	p.cmd.Stdout, p.cmd.Stderr = &p.output, &p.output
	require.NoError(t, p.cmd.Start())
	go func() {
		p.err = p.cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		cancel()
		<-p.done
		if t.Failed() {
			t.Log(p.output.String())
		}
	})
	return p
}

func (p *testCommandProcess) wait(t *testing.T, budget time.Duration) error {
	t.Helper()
	select {
	case <-p.done:
		return p.err
	case <-time.After(budget):
		t.Fatal("the octelium command did not exit within the test budget")
		return nil
	}
}

func testCommandInitialState() *userv1.ConnectResponse {
	return &userv1.ConnectResponse{
		CreatedAt: timestamppb.Now(),
		Event: &userv1.ConnectResponse_State{State: &userv1.ConnectionState{
			L3Mode: userv1.ConnectionState_V4, X25519Key: make([]byte, 32),
			Addresses: []*metav1.DualStackNetwork{{V4: "100.64.0.2/32"}},
			Cidr:      &metav1.DualStackNetwork{V4: "100.64.0.0/16"},
		}},
	}
}

func testCommandDNSReady(addr string) bool {
	for _, network := range []string{"udp"} {
		cl := &dns.Client{Net: network, Timeout: 100 * time.Millisecond}
		msg := new(dns.Msg)
		msg.SetQuestion("missing.local.example.com.", dns.TypeA)
		response, _, err := cl.Exchange(msg, addr)
		if err != nil || response.Rcode != dns.RcodeServerFailure {
			return false
		}
	}
	return true
}

func TestClientCommandE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("building and exercising the client executable")
	}
	binary := filepath.Join(t.TempDir(), "octelium")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "..")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "%s", out)
	t.Run("DaemonIPCSettingsRestartAndShutdown", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("this subprocess test uses Unix shutdown signals; Windows IPC is tested in the ipc package")
		}
		socket, dir := newTestCommandSocket(t), t.TempDir()
		start := func() (*testCommandProcess, daemonv1.MainServiceClient) {
			p := startTestCommand(t, binary, nil, "daemon", "--listen", socket, "--state-dir", dir, "--homedir", t.TempDir())
			conn, err := grpc.NewClient("passthrough:///"+socket,
				grpc.WithTransportCredentials(ipc.NewTransportCredentials()), grpc.WithContextDialer(ipc.Dial))
			require.NoError(t, err)
			t.Cleanup(func() { conn.Close() })
			cl := daemonv1.NewMainServiceClient(conn)
			require.Eventually(t, func() bool {
				ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
				defer cancel()
				_, err := cl.GetInfo(ctx, &daemonv1.GetInfoRequest{})
				return err == nil
			}, 5*time.Second, 20*time.Millisecond)
			return p, cl
		}
		first, cl := start()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		info, err := cl.GetInfo(ctx, &daemonv1.GetInfoRequest{})
		require.NoError(t, err)
		watch, err := cl.WatchStatus(ctx, &daemonv1.WatchStatusRequest{})
		require.NoError(t, err)
		initial, err := watch.Recv()
		require.NoError(t, err)
		assert.Empty(t, initial.Domains)
		settings, err := cl.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
			Domain: " EXAMPLE.COM. ", Settings: &daemonv1.DomainSettings{
				ConnectionOptions: &daemonv1.ConnectionOptions{L3Mode: daemonv1.ConnectionOptions_V6, Mtu: 1280},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "example.com", settings.Domain)
		updated, err := watch.Recv()
		require.NoError(t, err)
		assert.Greater(t, updated.Revision, initial.Revision)
		require.Len(t, updated.Domains, 1)
		assert.Equal(t, daemonv1.ConnectionStatus_DISCONNECTED, updated.Domains[0].Connection.State)
		assert.NoError(t, first.cmd.Process.Signal(os.Interrupt))
		require.NoError(t, first.wait(t, 3*time.Second))
		_, err = watch.Recv()
		assert.Error(t, err)
		second, cl := start()
		nextInfo, err := cl.GetInfo(ctx, &daemonv1.GetInfoRequest{})
		require.NoError(t, err)
		assert.NotEqual(t, info.InstanceID, nextInfo.InstanceID)
		snapshot, err := cl.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		require.NoError(t, err)
		require.Len(t, snapshot.Domains, 1)
		assert.Equal(t, daemonv1.ConnectionOptions_V6, snapshot.Domains[0].Settings.ConnectionOptions.L3Mode)
		assert.Equal(t, int32(1280), snapshot.Domains[0].Settings.ConnectionOptions.Mtu)
		assert.NoError(t, second.cmd.Process.Signal(os.Interrupt))
		assert.NoError(t, second.wait(t, 3*time.Second))
	})
	t.Run("ConnectRejectedExitCodes", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("the authentication proxy transport uses Unix domain sockets")
		}
		for _, code := range []codes.Code{codes.InvalidArgument, codes.PermissionDenied, codes.NotFound} {
			t.Run(code.String(), func(t *testing.T) {
				socket := startTestCommandAPI(t, &testCommandAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
					if _, err := stream.Recv(); err != nil {
						return err
					}
					return status.Error(code, "request rejected")
				}})
				p := startTestCommand(t, binary, []string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket},
					"connect", "--domain", "example.com", "--homedir", t.TempDir(), "--ip-mode", "v4")
				err := p.wait(t, 5*time.Second)
				var exitErr *exec.ExitError
				require.ErrorAs(t, err, &exitErr)
				assert.Equal(t, connect.ExitCodeRejected, exitErr.ExitCode())
				assert.Contains(t, p.output.String(), "request rejected")
			})
		}
	})
	t.Run("ConnectRetriesAndReleasesListeners", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("this test forces the Linux gVisor implementation")
		}
		lis, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		port := lis.LocalAddr().(*net.UDPAddr).Port
		require.NoError(t, lis.Close())
		var attempts atomic.Int32
		release := make(chan struct{})
		socket := startTestCommandAPI(t, &testCommandAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
			attempt := attempts.Add(1)
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if attempt == 1 {
				return status.Error(codes.Unavailable, "API restarting")
			}
			if err := stream.Send(testCommandInitialState()); err != nil {
				return err
			}
			select {
			case <-release:
				return stream.Send(&userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}}})
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
		}})
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		p := startTestCommand(t, binary, []string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket},
			"connect", "--domain", "example.com", "--homedir", t.TempDir(), "--ip-mode", "v4",
			"--no-dns", "--implementation", "gvisor", "--localdns", "--localdns-addr", addr)
		require.Eventually(t, func() bool {
			return testCommandDNSReady(addr)
		}, 8*time.Second, 20*time.Millisecond)
		assert.Equal(t, int32(2), attempts.Load())
		close(release)
		require.NoError(t, p.wait(t, 3*time.Second))
		assert.Contains(t, p.output.String(), "Connected successfully")
		packetConn, err := net.ListenPacket("udp", addr)
		require.NoError(t, err, "disconnect must release the local DNS UDP listener")
		assert.NoError(t, packetConn.Close())
	})
	t.Run("CL-009-CancelWithUnavailableAuthProxy", func(t *testing.T) {
		if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
			t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to reproduce CL-009 in tmp/client-test-report.md")
		}
		if runtime.GOOS == "windows" {
			t.Skip("the authentication proxy transport uses Unix domain sockets")
		}
		p := startTestCommand(t, binary, []string{"OCTELIUM_AUTH_PROXY_SOCKET=" + newTestCommandSocket(t)},
			"connect", "--domain", "example.com", "--homedir", t.TempDir(), "--ip-mode", "v4")
		time.Sleep(200 * time.Millisecond)
		require.NoError(t, p.cmd.Process.Signal(os.Interrupt))
		assert.NoError(t, p.wait(t, 2*time.Second))
	})
}

func newTestCommandServedBackend(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteTo(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return conn.LocalAddr().(*net.UDPAddr)
}

func testCommandServedRoundTrip(addr string) bool {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	msg := []byte("served by the octelium executable")
	if _, err := conn.Write(msg); err != nil {
		return false
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	return err == nil && string(buf[:n]) == string(msg)
}

func TestClientServedListenerRecoveryE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("building and exercising the client executable")
	}
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	binary := filepath.Join(t.TempDir(), "octelium")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "..")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "%s", out)
	for _, scenario := range []string{"InitialService", "LegacyInitialService", "StreamedAdd", "UpdateWhilePending", "APIReconnect", "CancelWhilePending", "DeleteWhilePending"} {
		t.Run(scenario, func(t *testing.T) {
			peer := testutils.NewWGPeer(t)
			roundTrip := func(addr string) bool { return peer.RoundTrip(addr, []byte("served by the octelium executable")) }
			backend := newTestCommandServedBackend(t)
			blocker := peer.ReserveUDP("100.64.0.3", 22000)
			t.Cleanup(func() { blocker.Close() })
			nextBlocker := peer.ReserveUDP("100.64.0.4", 22001)
			t.Cleanup(func() { nextBlocker.Close() })
			free, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			healthyPort := uint32(free.LocalAddr().(*net.UDPAddr).Port)
			healthyAddr := net.JoinHostPort("100.64.0.2", fmt.Sprintf("%d", healthyPort))
			require.NoError(t, free.Close())
			service := func(name string, port uint32) *userv1.HostedService {
				address := "100.64.0.2"
				for _, blocked := range []*testutils.WGAddress{blocker, nextBlocker} {
					if uint32(blocked.LocalAddr().(*net.UDPAddr).Port) == port {
						address = blocked.LocalAddr().(*net.UDPAddr).IP.String()
					}
				}
				return &userv1.HostedService{
					Name: name, Port: port, L4Type: userv1.HostedService_UDP,
					Address:  &metav1.DualStackIP{Ipv4: address},
					Upstream: &userv1.HostedService_Upstream{Host: "127.0.0.1", Port: int32(backend.Port)},
				}
			}
			healthy := service("healthy.default", healthyPort)
			pending := service("pending.default", uint32(blocker.LocalAddr().(*net.UDPAddr).Port))
			next := service(pending.Name, uint32(nextBlocker.LocalAddr().(*net.UDPAddr).Port))
			messages := make(chan *userv1.ConnectResponse, 8)
			restart, disconnect := make(chan struct{}), make(chan struct{})
			var attempts atomic.Int32
			socket := startTestCommandAPI(t, &testCommandAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
				attempt := attempts.Add(1)
				req, err := stream.Recv()
				if err != nil {
					return err
				}
				if !req.GetInitialize().GetServiceOptions().GetServeAll() {
					return status.Error(codes.InvalidArgument, "missing serve-all request")
				}
				initial := testCommandInitialState()
				initial.GetState().ServiceOptions = &userv1.ConnectionState_ServiceOptions{Services: []*userv1.HostedService{healthy}}
				if scenario != "StreamedAdd" {
					target := pending
					if attempt > 1 {
						target = next
					}
					initial.GetState().ServiceOptions.Services = append(initial.GetState().ServiceOptions.Services, target)
				}
				if scenario == "LegacyInitialService" {
					initial.CreatedAt = nil
				}
				if err := peer.SendInitial(stream, initial); err != nil {
					return err
				}
				restartCh := restart
				if attempt > 1 {
					restartCh = nil
				}
				for {
					select {
					case msg := <-peer.Updates:
						if err := stream.Send(msg); err != nil {
							return err
						}
					case msg := <-messages:
						if scenario != "LegacyInitialService" {
							msg.CreatedAt = timestamppb.Now()
						}
						if err := stream.Send(msg); err != nil {
							return err
						}
					case <-restartCh:
						return status.Error(codes.Unavailable, "API server restart")
					case <-disconnect:
						return stream.Send(&userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}}})
					case <-stream.Context().Done():
						return nil
					}
				}
			}})
			p := startTestCommand(t, binary, []string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket},
				"connect", "--domain", "example.com", "--homedir", t.TempDir(), "--ip-mode", "v4",
				"--no-dns", "--implementation", "gvisor", "--serve-all", "--localdns-addr", "127.0.0.1:0")
			require.Eventually(t, func() bool { return roundTrip(healthyAddr) }, 8*time.Second, 10*time.Millisecond)
			if scenario == "StreamedAdd" {
				messages <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddService_{AddService: &userv1.ConnectResponse_AddService{Service: pending}}}
			}
			time.Sleep(150 * time.Millisecond)
			if scenario == "DeleteWhilePending" {
				require.NoError(t, nextBlocker.Close())
				messages <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_DeleteService_{DeleteService: &userv1.ConnectResponse_DeleteService{Name: pending.Name}}}
				barrier := service("barrier.default", next.Port)
				messages <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_AddService_{AddService: &userv1.ConnectResponse_AddService{Service: barrier}}}
				require.Eventually(t, func() bool { return roundTrip(nextBlocker.LocalAddr().String()) }, 3*time.Second, 10*time.Millisecond)
				require.NoError(t, blocker.Close())
				assert.False(t, roundTrip(blocker.LocalAddr().String()))
				require.True(t, roundTrip(healthyAddr))
				close(disconnect)
				require.NoError(t, p.wait(t, 3*time.Second))
			} else if scenario == "CancelWhilePending" {
				require.NoError(t, p.cmd.Process.Signal(os.Interrupt))
				require.NoError(t, p.wait(t, 3*time.Second))
				require.NoError(t, blocker.Close())
			} else {
				targetAddr := blocker.LocalAddr().String()
				if scenario == "APIReconnect" {
					close(restart)
					require.Eventually(t, func() bool { return attempts.Load() == 2 }, 8*time.Second, 10*time.Millisecond)
					require.Eventually(t, func() bool { return roundTrip(healthyAddr) }, 3*time.Second, 10*time.Millisecond)
					require.NoError(t, blocker.Close())
					require.NoError(t, nextBlocker.Close())
					targetAddr = nextBlocker.LocalAddr().String()
				} else if scenario == "UpdateWhilePending" {
					require.NoError(t, nextBlocker.Close())
					messages <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateService_{UpdateService: &userv1.ConnectResponse_UpdateService{Service: next}}}
					targetAddr = nextBlocker.LocalAddr().String()
					require.NoError(t, blocker.Close())
				} else {
					messages <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_UpdateService_{UpdateService: &userv1.ConnectResponse_UpdateService{Service: pending}}}
					require.NoError(t, blocker.Close())
				}
				require.Eventually(t, func() bool { return roundTrip(targetAddr) }, 6*time.Second, 10*time.Millisecond)
				require.True(t, roundTrip(healthyAddr))
				if scenario == "APIReconnect" || scenario == "UpdateWhilePending" {
					assert.False(t, roundTrip(blocker.LocalAddr().String()), "an old controller must not restore its pending listener")
				}
				messages <- &userv1.ConnectResponse{Event: &userv1.ConnectResponse_DeleteService_{DeleteService: &userv1.ConnectResponse_DeleteService{Name: pending.Name}}}
				require.Eventually(t, func() bool { return !roundTrip(targetAddr) }, 3*time.Second, 10*time.Millisecond)
				close(disconnect)
				require.NoError(t, p.wait(t, 3*time.Second))
			}
			wantAttempts := int32(1)
			if scenario == "APIReconnect" {
				wantAttempts = 2
			}
			assert.Equal(t, wantAttempts, attempts.Load())
			assert.Contains(t, p.output.String(), "Connected successfully")
			assert.False(t, roundTrip(healthyAddr), "disconnect must stop forwarding healthy served listeners")
		})
	}
}

func TestClientMalformedServedStateE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("building and exercising the client executable")
	}
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	binary := filepath.Join(t.TempDir(), "octelium")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "..")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "%s", out)
	for _, scenario := range []string{"AddMissingService", "UpdateMissingService", "DeleteMissingName", "InitialNilService"} {
		t.Run(scenario, func(t *testing.T) {
			peer := testutils.NewWGPeer(t)
			roundTrip := func(addr string) bool { return peer.RoundTrip(addr, []byte("served by the octelium executable")) }
			backend := newTestCommandServedBackend(t)
			reserved, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			port := uint32(reserved.LocalAddr().(*net.UDPAddr).Port)
			addr := net.JoinHostPort("100.64.0.2", fmt.Sprintf("%d", port))
			require.NoError(t, reserved.Close())
			firstReady, disconnect := make(chan struct{}), make(chan struct{})
			var attempts atomic.Int32
			socket := startTestCommandAPI(t, &testCommandAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
				attempt := attempts.Add(1)
				if _, err := stream.Recv(); err != nil {
					return err
				}
				initial := testCommandInitialState()
				initial.GetState().ServiceOptions = &userv1.ConnectionState_ServiceOptions{Services: []*userv1.HostedService{{
					Name: "healthy.default", Port: port, L4Type: userv1.HostedService_UDP,
					Address:  &metav1.DualStackIP{Ipv4: "100.64.0.2"},
					Upstream: &userv1.HostedService_Upstream{Host: "127.0.0.1", Port: int32(backend.Port)},
				}}}
				if attempt == 1 && scenario == "InitialNilService" {
					initial.GetState().ServiceOptions.Services = append(initial.GetState().ServiceOptions.Services, nil)
				}
				if err := peer.SendInitial(stream, initial); err != nil {
					return err
				}
				if attempt == 1 && scenario != "InitialNilService" {
					select {
					case <-firstReady:
					case <-stream.Context().Done():
						return nil
					}
					msg := &userv1.ConnectResponse{}
					switch scenario {
					case "AddMissingService":
						msg.Event = &userv1.ConnectResponse_AddService_{AddService: &userv1.ConnectResponse_AddService{}}
					case "UpdateMissingService":
						msg.Event = &userv1.ConnectResponse_UpdateService_{UpdateService: &userv1.ConnectResponse_UpdateService{}}
					case "DeleteMissingName":
						msg.Event = &userv1.ConnectResponse_DeleteService_{DeleteService: &userv1.ConnectResponse_DeleteService{}}
					}
					if err := stream.Send(msg); err != nil {
						return err
					}
				}
				select {
				case <-disconnect:
					return stream.Send(&userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{Disconnect: &userv1.ConnectResponse_Disconnect{}}})
				case <-stream.Context().Done():
					return nil
				}
			}})
			p := startTestCommand(t, binary, []string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket},
				"connect", "--domain", "example.com", "--homedir", t.TempDir(), "--ip-mode", "v4",
				"--no-dns", "--implementation", "gvisor", "--serve-all", "--localdns-addr", "127.0.0.1:0")
			if scenario != "InitialNilService" {
				require.Eventually(t, func() bool { return roundTrip(addr) }, 5*time.Second, 10*time.Millisecond)
				close(firstReady)
			}
			require.Eventually(t, func() bool { return attempts.Load() == 2 }, 8*time.Second, 10*time.Millisecond)
			require.Eventually(t, func() bool { return roundTrip(addr) }, 3*time.Second, 10*time.Millisecond)
			close(disconnect)
			require.NoError(t, p.wait(t, 3*time.Second))
			assert.Equal(t, int32(2), attempts.Load())
			assert.NotContains(t, p.output.String(), "panic:")
			assert.Contains(t, p.output.String(), "Connected successfully")
			assert.False(t, roundTrip(addr), "disconnect must stop forwarding the served listener")
		})
	}
}
