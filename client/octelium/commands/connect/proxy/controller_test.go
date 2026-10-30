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

package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

func TestControllerESSHService(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctl, err := NewController(ctx, &cliconfigv1.Connection{
		Connection: &userv1.ConnectionState{
			L3Mode: userv1.ConnectionState_BOTH,
		},
		Preferences: &cliconfigv1.Connection_Preferences{
			L3Mode: cliconfigv1.Connection_Preferences_BOTH,
			ESSH: &cliconfigv1.Connection_Preferences_ESSH{
				IsEnabled: true,
			},
		},
	}, &ccommon.TestGoNetCtl{})
	assert.Nil(t, err)

	assert.Nil(t, ctl.Start(ctx))

	svc := &userv1.HostedService{
		Name:   "svc-essh",
		Port:   43211,
		L4Type: userv1.HostedService_TCP,
		Mode:   userv1.HostedService_MODE_ESSH,
		Upstream: &userv1.HostedService_Upstream{
			Host: "localhost",
			Port: 22,
		},
		Address: &metav1.DualStackIP{
			Ipv4: "127.0.0.1",
		},
	}

	assert.Nil(t, ctl.AddService(svc))
	assert.Nil(t, ctl.UpdateService(svc))
	assert.Nil(t, ctl.DeleteService(svc.Name))
	assert.Nil(t, ctl.Close())
}

func TestController(t *testing.T) {

	{
		ctx, cancel := context.WithCancel(context.Background())
		ctl, err := NewController(ctx, &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				L3Mode: userv1.ConnectionState_BOTH,
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				L3Mode: cliconfigv1.Connection_Preferences_BOTH,
			},
		}, nil)
		assert.Nil(t, err)

		ctl.Start(ctx)
		cancel()
		ctl.Close()
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		ctl, err := NewController(ctx, &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				L3Mode: userv1.ConnectionState_BOTH,
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				L3Mode: cliconfigv1.Connection_Preferences_BOTH,
			},
		}, &ccommon.TestGoNetCtl{})
		assert.Nil(t, err)

		ctl.Start(ctx)
		ctl.Close()
		cancel()
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		ctl, err := NewController(ctx, &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				L3Mode: userv1.ConnectionState_BOTH,
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				L3Mode: cliconfigv1.Connection_Preferences_BOTH,
			},
		}, &ccommon.TestGoNetCtl{})
		assert.Nil(t, err)

		err = ctl.Start(ctx)
		assert.Nil(t, err)
		err = ctl.AddService(&userv1.HostedService{
			Name: "svc-1",
			// Namespace: "ns-1",
			Port:   43210,
			L4Type: userv1.HostedService_TCP,
			Upstream: &userv1.HostedService_Upstream{
				Host: "www.google.com",
				Port: 443,
			},
			Address: &metav1.DualStackIP{
				Ipv4: "127.0.0.1",
			},
		})
		assert.Nil(t, err)
		time.Sleep(1 * time.Second)

		err = ctl.UpdateService(&userv1.HostedService{
			Name: "svc-1",
			// Namespace: "ns-1",
			Port:   43210,
			L4Type: userv1.HostedService_TCP,
			Upstream: &userv1.HostedService_Upstream{
				Host: "www.facebook.com",
				Port: 443,
			},
			Address: &metav1.DualStackIP{
				Ipv4: "127.0.0.1",
			},
		})
		assert.Nil(t, err)
		time.Sleep(1 * time.Second)

		err = ctl.DeleteService("svc-1")
		assert.Nil(t, err)
		time.Sleep(1 * time.Second)

		err = ctl.Close()
		assert.Nil(t, err)
		cancel()
	}

}

func newTestServedController(t *testing.T, ctx context.Context, goNet ccommon.GoNetCtl, svcs ...*userv1.HostedService) *Controller {
	t.Helper()
	c, err := NewController(ctx, &cliconfigv1.Connection{
		Connection: &userv1.ConnectionState{
			L3Mode:         userv1.ConnectionState_BOTH,
			ServiceOptions: &userv1.ConnectionState_ServiceOptions{Services: svcs},
		},
		Preferences: &cliconfigv1.Connection_Preferences{L3Mode: cliconfigv1.Connection_Preferences_BOTH},
	}, goNet)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, c.Close()) })
	return c
}

func newTestServedControllerBackend(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		conn, err := net.ListenPacket(network, "127.0.0.1:0")
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
		return conn.LocalAddr().String()
	}
	lis, err := net.Listen(network, "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				io.Copy(conn, conn)
			})
		}
	})
	t.Cleanup(func() { cancel(); lis.Close(); wg.Wait() })
	return lis.Addr().String()
}

func testServedControllerRoundTrip(network, addr string) bool {
	conn, err := net.DialTimeout(network, addr, 100*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(250 * time.Millisecond))
	msg := []byte("served controller recovery")
	if _, err := conn.Write(msg); err != nil {
		return false
	}
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	return err == nil && string(buf) == string(msg)
}

func newTestServedControllerService(t *testing.T, name, network, addr, backend string) *userv1.HostedService {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	var number uint32
	_, err = fmt.Sscan(port, &number)
	require.NoError(t, err)
	host, port, err := net.SplitHostPort(backend)
	require.NoError(t, err)
	var backendPort int32
	_, err = fmt.Sscan(port, &backendPort)
	require.NoError(t, err)
	l4 := userv1.HostedService_TCP
	if network == "udp" {
		l4 = userv1.HostedService_UDP
	}
	return &userv1.HostedService{
		Name: name, Port: number, L4Type: l4,
		Address:  &metav1.DualStackIP{Ipv4: "127.0.0.1"},
		Upstream: &userv1.HostedService_Upstream{Host: host, Port: backendPort},
	}
}

func TestServedControllerPendingServiceRecoversWithoutDisruptingHealthyServices(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			backend := newTestServedControllerBackend(t, network)
			var blockedAddr, healthyAddr string
			var release func() error
			if network == "tcp" {
				blocker, err := net.Listen(network, "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { blocker.Close() })
				blockedAddr, release = blocker.Addr().String(), blocker.Close
				free, err := net.Listen(network, "127.0.0.1:0")
				require.NoError(t, err)
				healthyAddr = free.Addr().String()
				require.NoError(t, free.Close())
			} else {
				blocker, err := net.ListenPacket(network, "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { blocker.Close() })
				blockedAddr, release = blocker.LocalAddr().String(), blocker.Close
				free, err := net.ListenPacket(network, "127.0.0.1:0")
				require.NoError(t, err)
				healthyAddr = free.LocalAddr().String()
				require.NoError(t, free.Close())
			}
			svc := newTestServedControllerService(t, "pending.default", network, blockedAddr, backend)
			healthy := newTestServedControllerService(t, "healthy.default", network, healthyAddr, backend)
			c := newTestServedController(t, t.Context(), nil, svc, healthy)
			require.NoError(t, c.Start(t.Context()))
			require.Eventually(t, func() bool { return testServedControllerRoundTrip(network, healthyAddr) }, 3*time.Second, 10*time.Millisecond)
			for range 5 {
				require.NoError(t, c.UpdateService(proto.Clone(svc).(*userv1.HostedService)))
			}
			require.NoError(t, release())
			require.Eventually(t, func() bool { return testServedControllerRoundTrip(network, blockedAddr) }, 6*time.Second, 10*time.Millisecond)
			require.True(t, testServedControllerRoundTrip(network, healthyAddr))
			require.NoError(t, c.DeleteService(svc.Name))
			require.True(t, testServedControllerRoundTrip(network, healthyAddr))
		})
	}
}

type testServedControllerGoNet struct {
	mu    sync.Mutex
	calls map[int]int
}

func (n *testServedControllerGoNet) GetGoNet() ccommon.GoNet { return n }

func (n *testServedControllerGoNet) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.calls == nil {
		n.calls = make(map[int]int)
	}
	n.calls[addr.Port]++
	return nil, errors.New("the interface is unavailable")
}

func (n *testServedControllerGoNet) count(port int) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.calls[port]
}

func TestServedControllerReplacementDeletionAndCloseCancelRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := &testServedControllerGoNet{}
		svc := &userv1.HostedService{
			Name: "pending.default", Port: 12345,
			Address:  &metav1.DualStackIP{Ipv4: "127.0.0.1"},
			Upstream: &userv1.HostedService_Upstream{Host: "localhost", Port: 80},
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := newTestServedController(t, ctx, n, svc)
		require.NoError(t, c.Start(ctx))
		for range 5 {
			require.NoError(t, c.Start(ctx))
		}
		synctest.Wait()
		assert.Equal(t, 1, n.count(12345))
		time.Sleep(30 * time.Second)
		synctest.Wait()
		updated := proto.Clone(svc).(*userv1.HostedService)
		updated.Port = 12346
		require.NoError(t, c.UpdateService(updated))
		synctest.Wait()
		old := n.count(12345)
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, old, n.count(12345))
		assert.Greater(t, n.count(12346), 1)
		require.NoError(t, c.DeleteService(svc.Name))
		synctest.Wait()
		deleted := n.count(12346)
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, deleted, n.count(12346))
		require.NoError(t, c.AddService(svc))
		synctest.Wait()
		require.NoError(t, c.Close())
		synctest.Wait()
		closed := n.count(12345)
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, closed, n.count(12345))
	})
}

func TestServedControllerParentCancellationStopsInitialServices(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := &testServedControllerGoNet{}
		ctx, cancel := context.WithCancel(context.Background())
		c := newTestServedController(t, ctx, n, &userv1.HostedService{
			Name: "initial.default", Port: 12345,
			Address:  &metav1.DualStackIP{Ipv4: "127.0.0.1"},
			Upstream: &userv1.HostedService_Upstream{Host: "localhost", Port: 80},
		})
		require.NoError(t, c.Start(ctx))
		synctest.Wait()
		cancel()
		synctest.Wait()
		calls := n.count(12345)
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, calls, n.count(12345))
		require.NoError(t, c.Close())
	})
}

func TestServedControllerInvalidStartupClosesPartialServices(t *testing.T) {
	free, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := free.Addr().String()
	require.NoError(t, free.Close())
	valid := newTestServedControllerService(t, "valid.default", "tcp", addr, "127.0.0.1:80")
	invalid := proto.Clone(valid).(*userv1.HostedService)
	invalid.Name, invalid.Port = "invalid.default", 65536
	c := newTestServedController(t, t.Context(), nil, valid, invalid)
	require.Error(t, c.Start(t.Context()))
	require.Error(t, c.Start(t.Context()))
	require.Error(t, c.AddService(valid))
	lis, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	assert.NoError(t, lis.Close())
	require.NoError(t, c.Close())
}

func TestServedControllerIdenticalAddsDoNotMultiplyRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := &testServedControllerGoNet{}
		svc := &userv1.HostedService{
			Name: "pending.default", Port: 12345,
			Address:  &metav1.DualStackIP{Ipv4: "127.0.0.1"},
			Upstream: &userv1.HostedService_Upstream{Host: "localhost", Port: 80},
		}
		c := newTestServedController(t, context.Background(), n, svc)
		require.NoError(t, c.Start(context.Background()))
		for range 50 {
			require.NoError(t, c.AddService(proto.Clone(svc).(*userv1.HostedService)))
		}
		synctest.Wait()
		assert.Equal(t, 1, n.count(12345))
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Greater(t, n.count(12345), 1)
		assert.Less(t, n.count(12345), 40)
		require.NoError(t, c.DeleteService(svc.Name))
		synctest.Wait()
		deleted := n.count(12345)
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, deleted, n.count(12345))
	})
}

func TestServedControllerInvalidAddDoesNotHideLaterErrors(t *testing.T) {
	c := newTestServedController(t, t.Context(), nil)
	require.NoError(t, c.Start(t.Context()))
	svc := &userv1.HostedService{
		Name: "invalid.default", Port: 65536,
		Address:  &metav1.DualStackIP{Ipv4: "127.0.0.1"},
		Upstream: &userv1.HostedService_Upstream{Host: "localhost", Port: 80},
	}
	for range 3 {
		require.Error(t, c.AddService(proto.Clone(svc).(*userv1.HostedService)))
	}
	require.NoError(t, c.Close())
}

func TestServedMalformedServicePayloadsReturnErrors(t *testing.T) {
	c := newTestServedController(t, t.Context(), nil)
	require.NoError(t, c.Start(t.Context()))
	for _, svc := range []*userv1.HostedService{nil, {}, {
		Port: 12345, Address: &metav1.DualStackIP{Ipv4: "127.0.0.1"},
		Upstream: &userv1.HostedService_Upstream{Host: "127.0.0.1", Port: 80},
	}} {
		for _, operation := range []func(*userv1.HostedService) error{c.AddService, c.UpdateService} {
			var err error
			require.NotPanics(t, func() { err = operation(svc) })
			require.Error(t, err)
		}
	}
	var err error
	require.NotPanics(t, func() { err = c.DeleteService("") })
	require.Error(t, err)
}

func TestServedNilInitialServiceClosesPartialStartup(t *testing.T) {
	for _, malformed := range []*userv1.HostedService{nil, {}} {
		free, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := free.Addr().String()
		require.NoError(t, free.Close())
		valid := newTestServedControllerService(t, "valid.default", "tcp", addr, "127.0.0.1:80")
		c := newTestServedController(t, t.Context(), nil, valid, malformed)
		require.NotPanics(t, func() { err = c.Start(t.Context()) })
		require.ErrorContains(t, err, "without a name")
		require.NoError(t, c.Close())
		require.Error(t, c.Start(t.Context()))
		lis, err := net.Listen("tcp", addr)
		require.NoError(t, err, "failed startup must release the earlier Service's listener")
		assert.NoError(t, lis.Close())
	}
}

func TestServedMalformedEventsPreserveHealthyProxy(t *testing.T) {
	backend := newTestServedControllerBackend(t, "tcp")
	free, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := free.Addr().String()
	require.NoError(t, free.Close())
	svc := newTestServedControllerService(t, "healthy.default", "tcp", addr, backend)
	c := newTestServedController(t, t.Context(), nil, svc)
	require.NoError(t, c.Start(t.Context()))
	require.Eventually(t, func() bool { return testServedControllerRoundTrip("tcp", addr) }, 2*time.Second, 10*time.Millisecond)
	for _, bad := range []*userv1.HostedService{nil, {}} {
		for range 2 {
			require.Error(t, c.AddService(bad))
			require.Error(t, c.UpdateService(bad))
			require.Error(t, c.DeleteService(""))
			require.True(t, testServedControllerRoundTrip("tcp", addr))
		}
	}
	require.NoError(t, c.UpdateService(proto.Clone(svc).(*userv1.HostedService)))
	require.True(t, testServedControllerRoundTrip("tcp", addr))
	require.NoError(t, c.DeleteService(svc.GetName()))
	lis, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	assert.NoError(t, lis.Close())
}

func TestServedOptionalConfigurationMessagesAreSafe(t *testing.T) {
	for _, cfg := range []*cliconfigv1.Connection{nil, {}, {
		Connection: &userv1.ConnectionState{L3Mode: userv1.ConnectionState_V4},
	}, {
		Preferences: &cliconfigv1.Connection_Preferences{},
	}} {
		var c *Controller
		var err error
		require.NotPanics(t, func() { c, err = NewController(t.Context(), cfg, nil) })
		require.NoError(t, err)
		require.NoError(t, c.Start(t.Context()))
		require.NoError(t, c.AddService(&userv1.HostedService{Name: "legacy.default"}))
		require.NoError(t, c.UpdateService(&userv1.HostedService{Name: "legacy.default", Upstream: &userv1.HostedService_Upstream{}}))
		require.NoError(t, c.DeleteService("legacy.default"))
		require.NoError(t, c.Close())
	}
}

func TestServedLegacyOptionalServiceMessagesRemainAccepted(t *testing.T) {
	services := []*userv1.HostedService{
		{Name: "name-only.default"},
		{Name: "no-address.default", Upstream: &userv1.HostedService_Upstream{}},
		{Name: "no-upstream.default", Address: &metav1.DualStackIP{Ipv4: "127.0.0.1"}},
		{Name: "empty-optionals.default", Upstream: &userv1.HostedService_Upstream{}, Address: &metav1.DualStackIP{}},
	}
	c := newTestServedController(t, t.Context(), nil, services...)
	require.NoError(t, c.Start(t.Context()))
	for _, svc := range services {
		require.NoError(t, c.AddService(proto.Clone(svc).(*userv1.HostedService)))
		require.NoError(t, c.UpdateService(proto.Clone(svc).(*userv1.HostedService)))
		require.NoError(t, c.DeleteService(svc.GetName()))
	}
	require.NoError(t, c.Close())
}
