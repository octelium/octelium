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
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func startTestReliabilityCommandAPI(t *testing.T, socket string, srv *testCommandAPI) *grpc.Server {
	t.Helper()
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)
	return grpcSrv
}

func getTestReliabilityCommandAddrs(t *testing.T) (string, string) {
	t.Helper()
	udpLis, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	dnsAddr := udpLis.LocalAddr().String()
	require.NoError(t, udpLis.Close())
	tcpLis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	publishedAddr := tcpLis.Addr().String()
	require.NoError(t, tcpLis.Close())
	return dnsAddr, publishedAddr
}

func testReliabilityCommandListening(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func testReliabilityCommandService(req *metav1.GetOptions) *userv1.Service {
	return &userv1.Service{
		Metadata: &metav1.Metadata{Name: req.Name},
		Spec:     &userv1.Service_Spec{Type: userv1.Service_Spec_TCP, Port: 8080},
		Status:   &userv1.Service_Status{Namespace: "default"},
	}
}

func requireTestReliabilityCommandRunning(t *testing.T, p *testCommandProcess) {
	t.Helper()
	select {
	case <-p.done:
		require.FailNow(t, "octelium connect exited instead of reconnecting", "%+v", p.err)
	default:
	}
}

func assertTestReliabilityCommandReleased(t *testing.T, dnsAddr, publishedAddr string) {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", dnsAddr)
	require.NoError(t, err, "an exited client must release its local DNS listener")
	assert.NoError(t, packetConn.Close())
	if publishedAddr == "" {
		return
	}
	lis, err := net.Listen("tcp", publishedAddr)
	require.NoError(t, err, "an exited client must release its published port")
	assert.NoError(t, lis.Close())
}

func TestClientReliabilityE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("building and exercising the client executable")
	}
	if runtime.GOOS != "linux" {
		t.Skip("these tests force the Linux gVisor implementation and use Unix signals")
	}
	binary := filepath.Join(t.TempDir(), "octelium")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "..")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "%s", out)
	connectArgs := func(dnsAddr string, extra ...string) []string {
		return append([]string{"connect", "--domain", "example.com", "--homedir", t.TempDir(), "--ip-mode", "v4",
			"--no-dns", "--implementation", "gvisor", "--localdns", "--localdns-addr", dnsAddr}, extra...)
	}
	t.Run("APIServerCrashRestartKeepsProcessRunning", func(t *testing.T) {
		dnsAddr, publishedAddr := getTestReliabilityCommandAddrs(t)
		_, publishedPort, err := net.SplitHostPort(publishedAddr)
		require.NoError(t, err)
		var attempts atomic.Int32
		srv := &testCommandAPI{
			connectFn: func(stream userv1.MainService_ConnectServer) error {
				attempts.Add(1)
				if _, err := stream.Recv(); err != nil {
					return err
				}
				if err := stream.Send(testCommandInitialState()); err != nil {
					return err
				}
				<-stream.Context().Done()
				return nil
			},
			getServiceFn: func(_ context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
				return testReliabilityCommandService(req), nil
			},
		}
		socket := newTestCommandSocket(t)
		first := startTestReliabilityCommandAPI(t, socket, srv)
		p := startTestCommand(t, binary, []string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket},
			connectArgs(dnsAddr, "-p", "web:127.0.0.1:"+publishedPort)...)
		require.Eventually(t, func() bool {
			return testCommandDNSReady(dnsAddr) && testReliabilityCommandListening(publishedAddr)
		}, 10*time.Second, 20*time.Millisecond)
		first.Stop()
		require.Eventually(t, func() bool {
			return !testCommandDNSReady(dnsAddr) && !testReliabilityCommandListening(publishedAddr)
		}, 10*time.Second, 20*time.Millisecond, "the lost connection must release its local listeners")
		time.Sleep(3 * time.Second)
		requireTestReliabilityCommandRunning(t, p)
		startTestReliabilityCommandAPI(t, socket, srv)
		require.Eventually(t, func() bool {
			return testCommandDNSReady(dnsAddr) && testReliabilityCommandListening(publishedAddr)
		}, 20*time.Second, 20*time.Millisecond, "the restarted API Server must restore every local listener")
		assert.Equal(t, int32(2), attempts.Load())
		require.NoError(t, p.cmd.Process.Signal(syscall.SIGTERM))
		require.NoError(t, p.wait(t, 5*time.Second))
		assertTestReliabilityCommandReleased(t, dnsAddr, publishedAddr)
	})
	t.Run("APIServerUnavailableAtLaunch", func(t *testing.T) {
		dnsAddr, _ := getTestReliabilityCommandAddrs(t)
		var attempts atomic.Int32
		srv := &testCommandAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
			attempts.Add(1)
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(testCommandInitialState()); err != nil {
				return err
			}
			<-stream.Context().Done()
			return nil
		}}
		socket := newTestCommandSocket(t)
		p := startTestCommand(t, binary, []string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket}, connectArgs(dnsAddr)...)
		time.Sleep(2 * time.Second)
		requireTestReliabilityCommandRunning(t, p)
		assert.False(t, testCommandDNSReady(dnsAddr))
		startTestReliabilityCommandAPI(t, socket, srv)
		require.Eventually(t, func() bool {
			return testCommandDNSReady(dnsAddr)
		}, 20*time.Second, 20*time.Millisecond, "the client must connect once the API Server becomes reachable")
		assert.Equal(t, int32(1), attempts.Load())
		require.NoError(t, p.cmd.Process.Signal(os.Interrupt))
		require.NoError(t, p.wait(t, 5*time.Second))
		assertTestReliabilityCommandReleased(t, dnsAddr, "")
	})
	t.Run("RejectionsAfterConnectingAreRetried", func(t *testing.T) {
		dnsAddr, _ := getTestReliabilityCommandAddrs(t)
		var attempts atomic.Int32
		drop, release := make(chan struct{}), make(chan struct{})
		srv := &testCommandAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
			attempt := attempts.Add(1)
			if _, err := stream.Recv(); err != nil {
				return err
			}
			switch attempt {
			case 2:
				return status.Error(codes.PermissionDenied, "policy reloading")
			case 3:
				return status.Error(codes.NotFound, "Session UID not Found")
			}
			if err := stream.Send(testCommandInitialState()); err != nil {
				return err
			}
			wait := drop
			if attempt > 1 {
				wait = release
			}
			select {
			case <-wait:
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
			if attempt == 1 {
				return status.Error(codes.Unavailable, "API Server restart")
			}
			return stream.Send(&userv1.ConnectResponse{Event: &userv1.ConnectResponse_Disconnect_{
				Disconnect: &userv1.ConnectResponse_Disconnect{},
			}})
		}}
		socket := newTestCommandSocket(t)
		startTestReliabilityCommandAPI(t, socket, srv)
		p := startTestCommand(t, binary, []string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket}, connectArgs(dnsAddr)...)
		require.Eventually(t, func() bool {
			return testCommandDNSReady(dnsAddr)
		}, 10*time.Second, 20*time.Millisecond)
		close(drop)
		require.Eventually(t, func() bool {
			return attempts.Load() >= 3
		}, 20*time.Second, 20*time.Millisecond)
		requireTestReliabilityCommandRunning(t, p)
		require.Eventually(t, func() bool {
			return testCommandDNSReady(dnsAddr)
		}, 20*time.Second, 20*time.Millisecond, "the client must reconnect after rejections that follow a successful connection")
		assert.Equal(t, int32(4), attempts.Load())
		close(release)
		require.NoError(t, p.wait(t, 5*time.Second), "an explicit Cluster disconnect must end the client")
		assert.Contains(t, p.output.String(), "Disconnected by API Server")
		assertTestReliabilityCommandReleased(t, dnsAddr, "")
	})
	t.Run("ShutdownSignalsReleaseListeners", func(t *testing.T) {
		for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} {
			t.Run(sig.String(), func(t *testing.T) {
				dnsAddr, _ := getTestReliabilityCommandAddrs(t)
				srv := &testCommandAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
					if _, err := stream.Recv(); err != nil {
						return err
					}
					if err := stream.Send(testCommandInitialState()); err != nil {
						return err
					}
					<-stream.Context().Done()
					return nil
				}}
				socket := newTestCommandSocket(t)
				startTestReliabilityCommandAPI(t, socket, srv)
				p := startTestCommand(t, binary, []string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket}, connectArgs(dnsAddr)...)
				require.Eventually(t, func() bool {
					return testCommandDNSReady(dnsAddr)
				}, 10*time.Second, 20*time.Millisecond)
				require.NoError(t, p.cmd.Process.Signal(sig))
				require.NoError(t, p.wait(t, 5*time.Second))
				assertTestReliabilityCommandReleased(t, dnsAddr, "")
			})
		}
	})
	t.Run("RepeatedStreamDropsKeepOneProcess", func(t *testing.T) {
		dnsAddr, _ := getTestReliabilityCommandAddrs(t)
		var attempts atomic.Int32
		drops := make(chan struct{})
		srv := &testCommandAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
			attempts.Add(1)
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(testCommandInitialState()); err != nil {
				return err
			}
			select {
			case <-drops:
				return status.Error(codes.Unavailable, "ingress restart")
			case <-stream.Context().Done():
				return nil
			}
		}}
		socket := newTestCommandSocket(t)
		startTestReliabilityCommandAPI(t, socket, srv)
		p := startTestCommand(t, binary, []string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket}, connectArgs(dnsAddr)...)
		for cycle := range 3 {
			require.Eventually(t, func() bool {
				return attempts.Load() == int32(cycle+1) && testCommandDNSReady(dnsAddr)
			}, 15*time.Second, 20*time.Millisecond, "cycle %d", cycle)
			drops <- struct{}{}
		}
		require.Eventually(t, func() bool {
			return attempts.Load() == 4 && testCommandDNSReady(dnsAddr)
		}, 15*time.Second, 20*time.Millisecond)
		requireTestReliabilityCommandRunning(t, p)
		require.NoError(t, p.cmd.Process.Signal(os.Interrupt))
		require.NoError(t, p.wait(t, 5*time.Second))
		assert.Equal(t, 4, strings.Count(p.output.String(), "Connected successfully"))
		assertTestReliabilityCommandReleased(t, dnsAddr, "")
	})
}

func TestClientCleanupFailureE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("building and exercising the client executable")
	}
	if runtime.GOOS != "linux" {
		t.Skip("these tests force the Linux gVisor implementation and use Unix signals")
	}
	binary := filepath.Join(t.TempDir(), "octelium")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "..")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "%s", out)
	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, sshDir string)
	}{
		{"KnownHostsDirectory", func(t *testing.T, sshDir string) {
			require.NoError(t, os.MkdirAll(filepath.Join(sshDir, "known_hosts"), 0700))
		}},
		{"UnreadableKnownHosts", func(t *testing.T, sshDir string) {
			if os.Geteuid() == 0 {
				t.Skip("root can read files without read permissions")
			}
			require.NoError(t, os.MkdirAll(sshDir, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte("example.org ssh-ed25519 AAAA\n"), 0))
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			userHome := t.TempDir()
			tt.setup(t, filepath.Join(userHome, ".ssh"))
			dnsAddr, publishedAddr := getTestReliabilityCommandAddrs(t)
			_, publishedPort, err := net.SplitHostPort(publishedAddr)
			require.NoError(t, err)
			var attempts atomic.Int32
			drops := make(chan struct{})
			srv := &testCommandAPI{
				connectFn: func(stream userv1.MainService_ConnectServer) error {
					attempts.Add(1)
					if _, err := stream.Recv(); err != nil {
						return err
					}
					if err := stream.Send(testCommandInitialState()); err != nil {
						return err
					}
					select {
					case <-drops:
						return status.Error(codes.Unavailable, "API Server restart")
					case <-stream.Context().Done():
						return nil
					}
				},
				getServiceFn: func(_ context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
					return testReliabilityCommandService(req), nil
				},
			}
			socket := newTestCommandSocket(t)
			startTestReliabilityCommandAPI(t, socket, srv)
			p := startTestCommand(t, binary,
				[]string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket, "OCTELIUM_USER_HOME=" + userHome},
				"connect", "--domain", "example.com", "--homedir", t.TempDir(), "--ip-mode", "v4",
				"--no-dns", "--implementation", "gvisor", "--localdns", "--localdns-addr", dnsAddr,
				"-p", "web:127.0.0.1:"+publishedPort)
			for cycle := range 2 {
				require.Eventually(t, func() bool {
					return attempts.Load() == int32(cycle+1) &&
						testCommandDNSReady(dnsAddr) && testReliabilityCommandListening(publishedAddr)
				}, 15*time.Second, 20*time.Millisecond, "cycle %d", cycle)
				drops <- struct{}{}
			}
			require.Eventually(t, func() bool {
				return attempts.Load() == 3 && testCommandDNSReady(dnsAddr) && testReliabilityCommandListening(publishedAddr)
			}, 15*time.Second, 20*time.Millisecond, "an incomplete cleanup must not stop the client from reconnecting")
			requireTestReliabilityCommandRunning(t, p)
			require.NoError(t, p.cmd.Process.Signal(syscall.SIGTERM))
			assert.Error(t, p.wait(t, 5*time.Second), "a cleanup failure on exit must still be reported")
			assert.Equal(t, 3, strings.Count(p.output.String(), "Connected successfully"))
			assertTestReliabilityCommandReleased(t, dnsAddr, publishedAddr)
		})
	}
}

func getTestReliabilityCommandPrivateTmpDir(t *testing.T, lockName string) string {
	t.Helper()
	shared := filepath.Join("/run", "octelium")
	if err := os.MkdirAll(shared, 0755); err == nil {
		if f, err := os.OpenFile(filepath.Join(shared, lockName), os.O_CREATE|os.O_RDONLY, 0644); err == nil {
			f.Close()
			t.Skip("the shared lock directory is usable by this user and cannot be isolated")
		}
	}
	return t.TempDir()
}

func testReliabilityCommandSSHState(domain string) *userv1.ConnectResponse {
	msg := testCommandInitialState()
	msg.GetState().ServiceConfigs = []*userv1.ConnectionState_ServiceConfig{{
		Type: &userv1.ConnectionState_ServiceConfig_Ssh{Ssh: &userv1.ConnectionState_ServiceConfig_SSH{
			KnownHosts:     []string{"@cert-authority *." + domain + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
			AuthorizedKeys: []string{"cert-authority,principals=\"" + domain + "\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
		}},
	}}
	return msg
}

func TestClientSSHConfigLockE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("building and exercising the client executable")
	}
	if runtime.GOOS != "linux" {
		t.Skip("these tests force the Linux gVisor implementation and use Unix signals")
	}
	tmpDir := getTestReliabilityCommandPrivateTmpDir(t, "sshconfig.lock")
	binary := filepath.Join(t.TempDir(), "octelium")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "..")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "%s", out)

	userHome := t.TempDir()
	sshDir := filepath.Join(userHome, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))
	knownHosts := filepath.Join(sshDir, "known_hosts")
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	original := "example.net ssh-ed25519 AAAA\n"
	require.NoError(t, os.WriteFile(knownHosts, []byte(original), 0600))
	require.NoError(t, os.WriteFile(authorizedKeys, []byte(original), 0600))
	readFile := func(path string) string {
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		return string(b)
	}

	lockPath := filepath.Join(tmpDir, "octelium", "sshconfig.lock")
	require.NoError(t, os.MkdirAll(filepath.Dir(lockPath), 0755))
	holdLock := func(d time.Duration) {
		lock := flock.New(lockPath)
		locked, err := lock.TryLock()
		require.NoError(t, err)
		require.True(t, locked)
		timer := time.AfterFunc(d, func() { lock.Close() })
		t.Cleanup(func() {
			if timer.Stop() {
				lock.Close()
			}
		})
	}

	type testClient struct {
		domain   string
		state    *userv1.ConnectResponse
		attempts atomic.Int32
		drops    chan struct{}
		p        *testCommandProcess
	}
	var clients []*testClient
	for _, domain := range []string{"example.com", "example.org"} {
		cl := &testClient{domain: domain, state: testReliabilityCommandSSHState(domain), drops: make(chan struct{}, 1)}
		srv := &testCommandAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
			cl.attempts.Add(1)
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(proto.Clone(cl.state).(*userv1.ConnectResponse)); err != nil {
				return err
			}
			select {
			case <-cl.drops:
				return status.Error(codes.Unavailable, "API Server restart")
			case <-stream.Context().Done():
				return nil
			}
		}}
		socket := newTestCommandSocket(t)
		startTestReliabilityCommandAPI(t, socket, srv)
		cl.p = startTestCommand(t, binary,
			[]string{"OCTELIUM_AUTH_PROXY_SOCKET=" + socket, "OCTELIUM_USER_HOME=" + userHome, "TMPDIR=" + tmpDir},
			"connect", "--domain", domain, "--homedir", t.TempDir(), "--ip-mode", "v4",
			"--no-dns", "--implementation", "gvisor")
		clients = append(clients, cl)
	}
	isInstalled := func(attempts int32) bool {
		knownHostsContent, authorizedKeysContent := readFile(knownHosts), readFile(authorizedKeys)
		for _, cl := range clients {
			cfg := cl.state.GetState().ServiceConfigs[0].GetSsh()
			if cl.attempts.Load() != attempts ||
				strings.Count(knownHostsContent, cfg.KnownHosts[0]) != 1 ||
				strings.Count(authorizedKeysContent, cfg.AuthorizedKeys[0]) != 1 {
				return false
			}
		}
		return true
	}

	require.Eventually(t, func() bool {
		return isInstalled(1)
	}, 15*time.Second, 20*time.Millisecond, "both Connections must install their Cluster CA")

	holdLock(1500 * time.Millisecond)
	for _, cl := range clients {
		cl.drops <- struct{}{}
	}
	require.Eventually(t, func() bool {
		return isInstalled(2)
	}, 20*time.Second, 20*time.Millisecond,
		"both clients must reconnect and reinstall their Cluster CA after waiting for the SSH config lock")
	for _, cl := range clients {
		requireTestReliabilityCommandRunning(t, cl.p)
	}

	holdLock(time.Second)
	for _, cl := range clients {
		require.NoError(t, cl.p.cmd.Process.Signal(syscall.SIGTERM))
	}
	for _, cl := range clients {
		assert.NoError(t, cl.p.wait(t, 10*time.Second), "%s: a briefly held SSH config lock must not fail the cleanup on exit", cl.domain)
		assert.Equal(t, 2, strings.Count(cl.p.output.String(), "Connected successfully"), cl.domain)
	}
	assert.Equal(t, original, readFile(knownHosts))
	assert.Equal(t, original, readFile(authorizedKeys))
}
