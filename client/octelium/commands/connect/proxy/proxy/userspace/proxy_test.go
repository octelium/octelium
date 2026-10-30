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

package userspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

var testServerPort uint32 = 8090

func TestProxyTCP(t *testing.T) {

	listener := &userv1.HostedService{
		Port:   8091,
		L4Type: userv1.HostedService_TCP,
		Name:   "svc-1",
		Upstream: &userv1.HostedService_Upstream{
			Host: "localhost",
			Port: int32(testServerPort),
		},
	}

	addrs := []*metav1.DualStackIP{
		{
			Ipv4: "127.0.0.1",
			Ipv6: "::1",
		},

		/*
			{
				Ipv4: "127.0.0.1",
				Ipv6: "::1",
			},
			{
				Ipv4: "127.0.0.1",
				Ipv6: "::1",
			},
		*/
	}

	srvSignal := make(chan struct{})
	go func() {
		err := initTCPServer(srvSignal)
		assert.Nil(t, err)
	}()

	time.Sleep(1 * time.Second)

	ctx := context.Background()

	for _, addr := range addrs {
		proxy := NewProxyFromServiceListener(listener, addr, &ccommon.TestGoNetCtl{}, true, true)

		for _, l := range proxy.listeners {
			l.upstreamHost = net.JoinHostPort("localhost", fmt.Sprintf("%d", testServerPort))
		}

		err := proxy.Start(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		var wg sync.WaitGroup

		for i := 0; i < 3; i++ {
			if addr.Ipv4 != "" {
				wg.Add(1)
				go func() {
					err := initTCPClient(addr.Ipv4, listener.Port)
					assert.Nil(t, err, "TCP client err %+v", err)
					wg.Done()
				}()
			}

			if addr.Ipv6 != "" {
				wg.Add(1)
				go func() {
					err := initTCPClient(addr.Ipv6, listener.Port)
					assert.Nil(t, err, "TCP client err %+v", err)
					wg.Done()
				}()
			}
		}
		wg.Wait()

		err = proxy.Close()
		assert.Nil(t, err)
		time.Sleep(1 * time.Second)
	}
}

func TestProxyCloseWhileListenerNotReady(t *testing.T) {

	listenPort := uint32(18093)
	listenAddr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", listenPort))

	blocker, err := net.Listen("tcp", listenAddr)
	assert.Nil(t, err)

	proxy := NewProxyFromServiceListener(&userv1.HostedService{
		Port:   listenPort,
		L4Type: userv1.HostedService_TCP,
		Name:   "svc-close",
		Upstream: &userv1.HostedService_Upstream{
			Host: "localhost",
			Port: int32(testServerPort),
		},
	}, &metav1.DualStackIP{
		Ipv4: "127.0.0.1",
	}, &ccommon.TestGoNetCtl{}, true, false)

	assert.Nil(t, proxy.Start(context.Background()))

	time.Sleep(500 * time.Millisecond)

	assert.Nil(t, proxy.Close())
	assert.Nil(t, blocker.Close())

	time.Sleep(2 * time.Second)

	lis, err := net.Listen("tcp", listenAddr)
	assert.Nil(t, err, "%s is still bound after Close", listenAddr)
	if lis != nil {
		lis.Close()
	}
}

func initTCPServer(sig chan struct{}) error {
	l, err := net.Listen("tcp", net.JoinHostPort("localhost", fmt.Sprintf("%d", testServerPort)))
	if err != nil {
		return err
	}

	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go func(conn net.Conn) {
			defer conn.Close()

			for {
				buf := make([]byte, 1024)
				size, err := conn.Read(buf)
				if err != nil {
					return
				}
				data := buf[:size]
				conn.Write(data)
			}
		}(conn)
	}
}

func initTCPClient(addr string, port uint32) error {
	servAddr := net.JoinHostPort(addr, fmt.Sprintf("%d", port))
	strEcho := "HELLO WORLD"
	tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)
	if err != nil {
		return err
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return err
	}

	_, err = conn.Write([]byte(strEcho))
	if err != nil {
		return err
	}

	reply := make([]byte, 1024)

	_, err = conn.Read(reply)
	if err != nil {
		return err
	}

	return conn.Close()
}

type testRetryGoNet struct {
	calls atomic.Int32
}

func (n *testRetryGoNet) GetGoNet() ccommon.GoNet {
	return n
}

func (n *testRetryGoNet) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	n.calls.Add(1)
	return nil, errors.New("the interface is temporarily unavailable")
}

func TestServedTCPListenerKeepsRetryingAfterStartupWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := &testRetryGoNet{}
		p := NewProxy(&Opts{
			Name: "retry.default", L4Type: userv1.HostedService_TCP, goNetCtl: n,
			Listeners: []OptsListener{{Address: "127.0.0.1", Port: 12345}},
			Upstream:  OptsUpstream{Address: "127.0.0.1", Port: 12346},
		})
		require.NoError(t, p.Start(context.Background()))
		synctest.Wait()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		before := n.calls.Load()
		time.Sleep(60 * time.Second)
		synctest.Wait()
		assert.Greater(t, n.calls.Load(), before, "a configured Service must keep retrying after the old startup limit")
		require.NoError(t, p.Close())
		synctest.Wait()
		closed := n.calls.Load()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		assert.Equal(t, closed, n.calls.Load())
	})
}

func TestServedUDPListenerRecoversAfterPortReleased(t *testing.T) {
	blocker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { blocker.Close() })
	p := NewProxy(&Opts{
		Name: "retry.default", L4Type: userv1.HostedService_UDP, goNetCtl: &ccommon.TestGoNetCtl{},
		Listeners: []OptsListener{{Address: "127.0.0.1", Port: uint32(blocker.LocalAddr().(*net.UDPAddr).Port)}},
		Upstream:  OptsUpstream{Address: "127.0.0.1", Port: 12346},
	})
	require.NoError(t, p.Start(t.Context()))
	t.Cleanup(func() { assert.NoError(t, p.Close()) })
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, blocker.Close())
	require.Eventually(t, func() bool {
		l := p.listeners[0]
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.udpLis != nil
	}, 2*time.Second, 10*time.Millisecond)
}

func newTestServedBackend(t *testing.T, network string) net.Addr {
	t.Helper()
	if network == "udp" {
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
		return conn.LocalAddr()
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() { cancel(); lis.Close(); wg.Wait() })
	return lis.Addr()
}

func testServedEcho(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	msg := []byte("served listener recovery")
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != string(msg) {
		return errors.New("the served listener returned an unexpected response")
	}
	return nil
}

func testServedRoundTrip(network, addr string) bool {
	conn, err := net.DialTimeout(network, addr, 100*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	return testServedEcho(conn) == nil
}

func testServedListenerAddress(l *listener) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lis != nil {
		return l.lis.Addr().String()
	}
	if l.udpLis != nil {
		return l.udpLis.Addr().String()
	}
	return ""
}

func newTestServedOpts(t *testing.T, network string) *Opts {
	t.Helper()
	addr := newTestServedBackend(t, network)
	host, port, err := net.SplitHostPort(addr.String())
	require.NoError(t, err)
	var number uint32
	_, err = fmt.Sscan(port, &number)
	require.NoError(t, err)
	l4 := userv1.HostedService_TCP
	if network == "udp" {
		l4 = userv1.HostedService_UDP
	}
	return &Opts{
		Name: "recovery.default", L4Type: l4,
		Listeners: []OptsListener{{Address: "127.0.0.1"}},
		Upstream:  OptsUpstream{Address: host, Port: number},
	}
}

func TestServedTCPPortRecoveryPreservesHealthyListener(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { blocker.Close() })
	opts := newTestServedOpts(t, "tcp")
	opts.Listeners = append(opts.Listeners, OptsListener{
		Address: "127.0.0.1", Port: uint32(blocker.Addr().(*net.TCPAddr).Port),
	})
	p := NewProxy(opts)
	require.NoError(t, p.Start(t.Context()))
	t.Cleanup(func() { assert.NoError(t, p.Close()) })
	require.Eventually(t, func() bool { return testServedListenerAddress(p.listeners[0]) != "" }, time.Second, time.Millisecond)
	conn, err := net.Dial("tcp", testServedListenerAddress(p.listeners[0]))
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, testServedEcho(conn))
	time.Sleep(300 * time.Millisecond)
	require.NoError(t, testServedEcho(conn))
	require.NoError(t, blocker.Close())
	require.Eventually(t, func() bool { return testServedRoundTrip("tcp", blocker.Addr().String()) }, 6*time.Second, 10*time.Millisecond)
	require.NoError(t, testServedEcho(conn))
}

func TestServedUDPPortRecoveryForwardsTraffic(t *testing.T) {
	blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { blocker.Close() })
	opts := newTestServedOpts(t, "udp")
	opts.Listeners[0].Port = uint32(blocker.LocalAddr().(*net.UDPAddr).Port)
	p := NewProxy(opts)
	require.NoError(t, p.Start(t.Context()))
	t.Cleanup(func() { assert.NoError(t, p.Close()) })
	time.Sleep(100 * time.Millisecond)
	require.NoError(t, blocker.Close())
	require.Eventually(t, func() bool { return testServedRoundTrip("udp", blocker.LocalAddr().String()) }, 6*time.Second, 10*time.Millisecond)
	require.NoError(t, p.Close())
	conn, err := net.ListenPacket("udp", blocker.LocalAddr().String())
	require.NoError(t, err)
	assert.NoError(t, conn.Close())
}

func TestServedParentCancellationReleasesBlockedAccept(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p := NewProxy(newTestServedOpts(t, network))
			require.NoError(t, p.Start(ctx))
			t.Cleanup(func() { assert.NoError(t, p.Close()) })
			require.Eventually(t, func() bool { return testServedListenerAddress(p.listeners[0]) != "" }, time.Second, time.Millisecond)
			addr := testServedListenerAddress(p.listeners[0])
			cancel()
			require.Eventually(t, func() bool { return p.listeners[0].closed() }, time.Second, time.Millisecond)
			require.NoError(t, p.Close())
			if network == "tcp" {
				lis, err := net.Listen(network, addr)
				require.NoError(t, err)
				assert.NoError(t, lis.Close())
			} else {
				conn, err := net.ListenPacket(network, addr)
				require.NoError(t, err)
				assert.NoError(t, conn.Close())
			}
		})
	}
}

func TestServedProxyStartAndCloseAreIdempotent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := &testRetryGoNet{}
		p := NewProxy(&Opts{
			Name: "repeat.default", goNetCtl: n,
			Listeners: []OptsListener{{Address: "127.0.0.1", Port: 12345}},
		})
		for range 10 {
			require.NoError(t, p.Start(context.Background()))
		}
		synctest.Wait()
		assert.Equal(t, int32(1), n.calls.Load())
		for range 10 {
			require.NoError(t, p.Close())
		}
		synctest.Wait()
		require.Error(t, p.Start(context.Background()))
		before := n.calls.Load()
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, before, n.calls.Load())
		p = NewProxy(&Opts{Listeners: []OptsListener{{Address: "127.0.0.1"}}})
		require.NoError(t, p.Close())
		require.NoError(t, p.Close())
		require.Error(t, p.Start(context.Background()))
	})
}

func TestServedProxyConcurrentStartClose(t *testing.T) {
	for range 20 {
		p := NewProxy(&Opts{Listeners: []OptsListener{{Address: "127.0.0.1"}}})
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() { p.Start(t.Context()) })
			wg.Go(func() { assert.NoError(t, p.Close()) })
		}
		wg.Wait()
		require.NoError(t, p.Close())
		require.Empty(t, testServedListenerAddress(p.listeners[0]))
	}
}

func TestServedInvalidConfigurationDoesNotStartListeners(t *testing.T) {
	for _, tt := range []struct {
		name string
		edit func(*Opts)
	}{
		{"ListenerPort", func(o *Opts) { o.Listeners[1].Port = 65536 }},
		{"ListenerAddress", func(o *Opts) { o.Listeners[1].Address = "invalid address" }},
		{"UpstreamPort", func(o *Opts) { o.Upstream.Port = 65536 }},
		{"NegativeUpstreamPort", func(o *Opts) { o.Upstream.Port = 4294967295 }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			n := &testRetryGoNet{}
			opts := &Opts{goNetCtl: n, Listeners: []OptsListener{{Address: "127.0.0.1"}, {Address: "::1"}}}
			tt.edit(opts)
			p := NewProxy(opts)
			require.Error(t, p.Start(t.Context()))
			require.NoError(t, p.Close())
			assert.Zero(t, n.calls.Load())
			for _, l := range p.listeners {
				assert.Empty(t, testServedListenerAddress(l))
			}
		})
	}
}

func TestServedCanceledStartDoesNotBind(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p := NewProxy(&Opts{Listeners: []OptsListener{{Address: "127.0.0.1"}}})
	require.ErrorIs(t, p.Start(ctx), context.Canceled)
	require.NoError(t, p.Close())
	assert.Empty(t, testServedListenerAddress(p.listeners[0]))
}

func TestServedUnexpectedListenerCloseRecovers(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			p := NewProxy(newTestServedOpts(t, network))
			require.NoError(t, p.Start(t.Context()))
			t.Cleanup(func() { assert.NoError(t, p.Close()) })
			l := p.listeners[0]
			require.Eventually(t, func() bool { return testServedListenerAddress(l) != "" }, time.Second, time.Millisecond)
			addr := testServedListenerAddress(l)
			require.True(t, testServedRoundTrip(network, addr))
			var oldTCP net.Listener
			l.mu.Lock()
			oldTCP, oldUDP := l.lis, l.udpLis
			l.mu.Unlock()
			var active net.Conn
			if network == "tcp" {
				var err error
				active, err = net.Dial(network, addr)
				require.NoError(t, err)
				defer active.Close()
				require.NoError(t, testServedEcho(active))
				require.NoError(t, oldTCP.Close())
			} else {
				require.NoError(t, oldUDP.Close())
			}
			require.Eventually(t, func() bool {
				l.mu.Lock()
				ready := l.lis != nil && l.lis != oldTCP || l.udpLis != nil && l.udpLis != oldUDP
				l.mu.Unlock()
				if !ready {
					return false
				}
				return testServedRoundTrip(network, testServedListenerAddress(l))
			}, 6*time.Second, 10*time.Millisecond)
			if active != nil {
				require.NoError(t, testServedEcho(active))
			}
		})
	}
}

type testRecoveringGoNet struct {
	goNet       ccommon.GoNet
	unavailable atomic.Bool
	calls       atomic.Int32
	listen      func(*net.TCPAddr) (*gonet.TCPListener, error)
}

func (n *testRecoveringGoNet) GetGoNet() ccommon.GoNet { return n }

func (n *testRecoveringGoNet) ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error) {
	n.calls.Add(1)
	if n.unavailable.Load() {
		return nil, errors.New("the interface is temporarily unavailable")
	}
	if n.listen != nil {
		return n.listen(addr)
	}
	return n.goNet.ListenTCP(addr)
}

func TestServedGoNetInterfaceRecoveryCarriesTraffic(t *testing.T) {
	for _, address := range []string{"100.64.0.2", "fd00::2"} {
		t.Run(address, func(t *testing.T) {
			dev, goNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(address)}, nil, 1280)
			require.NoError(t, err)
			t.Cleanup(func() { dev.Close() })
			n := &testRecoveringGoNet{goNet: goNet}
			n.unavailable.Store(true)
			opts := newTestServedOpts(t, "tcp")
			opts.goNetCtl = n
			opts.Listeners[0] = OptsListener{Address: address, Port: 12345}
			p := NewProxy(opts)
			require.NoError(t, p.Start(t.Context()))
			t.Cleanup(func() { assert.NoError(t, p.Close()) })
			require.Eventually(t, func() bool { return n.calls.Load() > 0 }, time.Second, time.Millisecond)
			n.unavailable.Store(false)
			require.Eventually(t, func() bool { return testServedListenerAddress(p.listeners[0]) != "" }, 6*time.Second, time.Millisecond)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := goNet.DialContextTCP(ctx, &net.TCPAddr{IP: net.ParseIP(address), Port: 12345})
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, testServedEcho(conn))
		})
	}
}

func TestServedCloseJoinsLateGoNetBind(t *testing.T) {
	address := "100.64.0.2"
	dev, goNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(address)}, nil, 1280)
	require.NoError(t, err)
	defer dev.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	n := &testRecoveringGoNet{listen: func(addr *net.TCPAddr) (*gonet.TCPListener, error) {
		lis, err := goNet.ListenTCP(addr)
		close(entered)
		<-release
		return lis, err
	}}
	p := NewProxy(&Opts{goNetCtl: n, Listeners: []OptsListener{{Address: address, Port: 12345}}})
	require.NoError(t, p.Start(t.Context()))
	var released sync.Once
	defer func() {
		released.Do(func() { close(release) })
		p.Close()
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the test bind did not begin")
	}
	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	require.Eventually(t, func() bool { return p.listeners[0].closed() }, time.Second, time.Millisecond)
	select {
	case <-done:
		t.Fatal("Close returned before its in-flight bind finished")
	default:
	}
	released.Do(func() { close(release) })
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after the bind returned")
	}
	assert.Empty(t, testServedListenerAddress(p.listeners[0]))
	lis, err := goNet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(address), Port: 12345})
	require.NoError(t, err)
	assert.NoError(t, lis.Close())
}

func TestServedRetriesAndWarningsStayBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		core, logs := observer.New(zap.WarnLevel)
		undo := zap.ReplaceGlobals(zap.New(core))
		defer undo()
		n := &testRetryGoNet{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p := NewProxy(&Opts{goNetCtl: n, Listeners: []OptsListener{{Address: "127.0.0.1", Port: 12345}}})
		require.NoError(t, p.Start(ctx))
		synctest.Wait()
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		assert.Greater(t, n.calls.Load(), int32(100))
		assert.Less(t, n.calls.Load(), int32(260))
		assert.Greater(t, logs.Len(), 1)
		assert.LessOrEqual(t, logs.Len(), 21)
		cancel()
		require.NoError(t, p.Close())
		synctest.Wait()
		before := n.calls.Load()
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, before, n.calls.Load())
	})
}

func TestServedConstructorRejectsMissingProtobufMessages(t *testing.T) {
	for _, tt := range []struct {
		name string
		svc  *userv1.HostedService
		addr *metav1.DualStackIP
	}{
		{name: "NilService", addr: &metav1.DualStackIP{Ipv4: "127.0.0.1"}},
		{name: "EmptyService", svc: &userv1.HostedService{}, addr: &metav1.DualStackIP{Ipv4: "127.0.0.1"}},
		{name: "NilUpstream", svc: &userv1.HostedService{Name: "invalid.default"}, addr: &metav1.DualStackIP{Ipv4: "127.0.0.1"}},
		{name: "NilAddress", svc: &userv1.HostedService{Name: "invalid.default", Upstream: &userv1.HostedService_Upstream{Host: "127.0.0.1", Port: 80}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var p *Proxy
			require.NotPanics(t, func() { p = NewProxyFromServiceListener(tt.svc, tt.addr, nil, true, true) })
			require.Nil(t, p)
			require.Error(t, p.Start(t.Context()))
			require.NoError(t, p.Close())
		})
	}
}

func TestServedConstructorPreservesLegacyDefaults(t *testing.T) {
	p := NewProxyFromServiceListener(&userv1.HostedService{
		Name: "legacy.default", Upstream: &userv1.HostedService_Upstream{},
	}, &metav1.DualStackIP{}, nil, true, true)
	require.NotNil(t, p)
	require.NoError(t, p.Start(t.Context()))
	require.NoError(t, p.Close())
	assert.Empty(t, p.listeners)
	assert.Equal(t, userv1.HostedService_L4_UNKNOWN, p.opts.L4Type)
}

type testServedUDPGoNet struct {
	*netstack.Net
	unavailable atomic.Bool
	calls       atomic.Int32
	listen      func(*net.UDPAddr, *net.UDPAddr) (*gonet.UDPConn, error)
}

func (n *testRetryGoNet) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	n.calls.Add(1)
	return nil, errors.New("the interface is temporarily unavailable")
}

func (n *testRecoveringGoNet) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	return n.goNet.DialUDP(laddr, raddr)
}

func (n *testServedUDPGoNet) GetGoNet() ccommon.GoNet { return n }

func (n *testServedUDPGoNet) DialUDP(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
	n.calls.Add(1)
	if n.unavailable.Load() {
		return nil, errors.New("the interface is temporarily unavailable")
	}
	if n.listen != nil {
		return n.listen(laddr, raddr)
	}
	return n.Net.DialUDP(laddr, raddr)
}

func TestServedGoNetUDPBindingCarriesTraffic(t *testing.T) {
	for _, address := range []string{"100.64.0.2", "fd00::2"} {
		t.Run(address, func(t *testing.T) {
			dev, goNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(address)}, nil, 1280)
			require.NoError(t, err)
			t.Cleanup(func() { dev.Close() })
			n := &testServedUDPGoNet{Net: goNet}
			opts := newTestServedOpts(t, "udp")
			opts.goNetCtl = n
			opts.Listeners[0] = OptsListener{Address: address, Port: 12345}
			p := NewProxy(opts)
			require.NoError(t, p.Start(t.Context()))
			t.Cleanup(func() { assert.NoError(t, p.Close()) })
			require.Eventually(t, func() bool { return testServedListenerAddress(p.listeners[0]) != "" }, time.Second, time.Millisecond)
			assert.Equal(t, int32(1), n.calls.Load())
			clients := make([]*gonet.UDPConn, 0, 3)
			for range 3 {
				conn, err := goNet.DialUDP(nil, &net.UDPAddr{IP: net.ParseIP(address), Port: 12345})
				require.NoError(t, err)
				t.Cleanup(func() { conn.Close() })
				clients = append(clients, conn)
			}
			for range 3 {
				for _, conn := range clients {
					require.NoError(t, testServedEcho(conn))
				}
			}
			require.NoError(t, p.Close())
			require.Empty(t, testServedListenerAddress(p.listeners[0]))
			probe, err := goNet.DialUDP(&net.UDPAddr{IP: net.ParseIP(address), Port: 12345}, nil)
			require.NoError(t, err)
			assert.NoError(t, probe.Close())
		})
	}
}

func TestServedGoNetUDPFailuresRetryUntilCanceled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := &testServedUDPGoNet{}
		n.unavailable.Store(true)
		p := NewProxy(&Opts{
			Name: "retry.default", L4Type: userv1.HostedService_UDP, goNetCtl: n,
			Listeners: []OptsListener{{Address: "127.0.0.1", Port: 12345}},
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		require.NoError(t, p.Start(ctx))
		synctest.Wait()
		require.Equal(t, int32(1), n.calls.Load())
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		assert.Greater(t, n.calls.Load(), int32(100))
		assert.Less(t, n.calls.Load(), int32(260))
		assert.Empty(t, testServedListenerAddress(p.listeners[0]), "a userspace bind failure must not create a host listener")
		cancel()
		require.NoError(t, p.Close())
		synctest.Wait()
		before := n.calls.Load()
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, before, n.calls.Load())
	})
}

func TestServedGoNetUDPRecoveryPreservesHealthyListener(t *testing.T) {
	for _, address := range []string{"100.64.0.2", "fd00::2"} {
		t.Run(address, func(t *testing.T) {
			dev, goNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(address)}, nil, 1280)
			require.NoError(t, err)
			t.Cleanup(func() { dev.Close() })
			n := &testServedUDPGoNet{Net: goNet}
			n.unavailable.Store(true)
			opts := newTestServedOpts(t, "udp")
			opts.goNetCtl = n
			opts.Listeners = []OptsListener{{Address: address, Port: 12345}, {Address: address, Port: 12346}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p := NewProxy(opts)
			require.NoError(t, p.Start(ctx))
			t.Cleanup(func() { assert.NoError(t, p.Close()) })
			require.Eventually(t, func() bool { return n.calls.Load() >= 2 }, time.Second, time.Millisecond)
			blocker, err := goNet.DialUDP(&net.UDPAddr{IP: net.ParseIP(address), Port: 12345}, nil)
			require.NoError(t, err)
			defer blocker.Close()
			n.unavailable.Store(false)
			require.Eventually(t, func() bool { return testServedListenerAddress(p.listeners[1]) != "" }, 6*time.Second, time.Millisecond)
			healthy, err := goNet.DialUDP(nil, &net.UDPAddr{IP: net.ParseIP(address), Port: 12346})
			require.NoError(t, err)
			defer healthy.Close()
			require.NoError(t, testServedEcho(healthy))
			require.NoError(t, blocker.Close())
			require.Eventually(t, func() bool { return testServedListenerAddress(p.listeners[0]) != "" }, 6*time.Second, time.Millisecond)
			conn, err := goNet.DialUDP(nil, &net.UDPAddr{IP: net.ParseIP(address), Port: 12345})
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, testServedEcho(conn))
			l := p.listeners[0]
			l.mu.Lock()
			old := l.udpLis
			l.mu.Unlock()
			require.NoError(t, old.Close())
			require.Eventually(t, func() bool {
				l.mu.Lock()
				defer l.mu.Unlock()
				return l.udpLis != nil && l.udpLis != old
			}, 6*time.Second, time.Millisecond)
			require.NoError(t, testServedEcho(conn))
			require.NoError(t, testServedEcho(healthy))
			cancel()
			require.NoError(t, p.Close())
			for _, port := range []int{12345, 12346} {
				probe, err := goNet.DialUDP(&net.UDPAddr{IP: net.ParseIP(address), Port: port}, nil)
				require.NoError(t, err)
				assert.NoError(t, probe.Close())
			}
		})
	}
}

func TestServedGoNetUDPCloseJoinsLateBind(t *testing.T) {
	address := "100.64.0.2"
	dev, goNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(address)}, nil, 1280)
	require.NoError(t, err)
	defer dev.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	n := &testServedUDPGoNet{listen: func(laddr, raddr *net.UDPAddr) (*gonet.UDPConn, error) {
		assert.Nil(t, raddr, "a served UDP socket must remain unconnected")
		conn, err := goNet.DialUDP(laddr, raddr)
		close(entered)
		<-release
		return conn, err
	}}
	p := NewProxy(&Opts{L4Type: userv1.HostedService_UDP, goNetCtl: n, Listeners: []OptsListener{{Address: address, Port: 12345}}})
	require.NoError(t, p.Start(t.Context()))
	var released sync.Once
	defer func() {
		released.Do(func() { close(release) })
		p.Close()
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the test bind did not begin")
	}
	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	require.Eventually(t, func() bool { return p.listeners[0].closed() }, time.Second, time.Millisecond)
	select {
	case <-done:
		t.Fatal("Close returned before its in-flight bind finished")
	default:
	}
	released.Do(func() { close(release) })
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after the bind returned")
	}
	assert.Empty(t, testServedListenerAddress(p.listeners[0]))
	probe, err := goNet.DialUDP(&net.UDPAddr{IP: net.ParseIP(address), Port: 12345}, nil)
	require.NoError(t, err)
	assert.NoError(t, probe.Close())
}

func TestServedUDPNativeNetworkSelection(t *testing.T) {
	for _, ctl := range []ccommon.GoNetCtl{nil, &ccommon.TestGoNetCtl{}} {
		opts := newTestServedOpts(t, "udp")
		opts.goNetCtl = ctl
		p := NewProxy(opts)
		require.NoError(t, p.Start(t.Context()))
		t.Cleanup(func() { p.Close() })
		require.Eventually(t, func() bool { return testServedListenerAddress(p.listeners[0]) != "" }, time.Second, time.Millisecond)
		addr := testServedListenerAddress(p.listeners[0])
		require.True(t, testServedRoundTrip("udp", addr))
		require.NoError(t, p.Close())
		probe, err := net.ListenPacket("udp", addr)
		require.NoError(t, err)
		assert.NoError(t, probe.Close())
	}
}

func TestServedGoNetUDPDualStackFactoryAndEphemeralPorts(t *testing.T) {
	for _, mode := range []struct {
		name   string
		v4, v6 bool
	}{
		{"Both", true, true}, {"IPv4", true, false}, {"IPv6", false, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			dev, goNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("fd00::2")}, nil, 1280)
			require.NoError(t, err)
			t.Cleanup(func() { dev.Close() })
			backend := newTestServedBackend(t, "udp").(*net.UDPAddr)
			p := NewProxyFromServiceListener(&userv1.HostedService{
				Name: "dual.default", L4Type: userv1.HostedService_UDP,
				Upstream: &userv1.HostedService_Upstream{Host: "127.0.0.1", Port: int32(backend.Port)},
			}, &metav1.DualStackIP{Ipv4: "100.64.0.2", Ipv6: "fd00::2"}, &testServedUDPGoNet{Net: goNet}, mode.v4, mode.v6)
			require.NoError(t, p.Start(t.Context()))
			t.Cleanup(func() { p.Close() })
			want := 1
			if mode.v4 && mode.v6 {
				want = 2
			}
			require.Len(t, p.listeners, want)
			addrs := make([]*net.UDPAddr, 0, want)
			for _, l := range p.listeners {
				require.Eventually(t, func() bool { return testServedListenerAddress(l) != "" }, time.Second, time.Millisecond)
				addr, err := net.ResolveUDPAddr("udp", testServedListenerAddress(l))
				require.NoError(t, err)
				require.Positive(t, addr.Port)
				addrs = append(addrs, addr)
				conn, err := goNet.DialUDP(nil, addr)
				require.NoError(t, err)
				t.Cleanup(func() { conn.Close() })
				require.NoError(t, testServedEcho(conn))
			}
			require.NoError(t, p.Close())
			for _, addr := range addrs {
				probe, err := goNet.DialUDP(addr, nil)
				require.NoError(t, err)
				assert.NoError(t, probe.Close())
			}
		})
	}
}

func newTestServedTaggedBackend(t *testing.T, tag string) OptsUpstream {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
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
				if _, err := conn.Write([]byte(tag)); err != nil {
					return
				}
				io.Copy(conn, conn)
			})
		}
	})
	t.Cleanup(func() { cancel(); lis.Close(); wg.Wait() })
	return OptsUpstream{Address: "127.0.0.1", Port: uint32(lis.Addr().(*net.TCPAddr).Port)}
}

func testServedReadTag(conn net.Conn, tag string) error {
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	buf := make([]byte, len(tag))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if string(buf) != tag {
		return fmt.Errorf("the served listener reached %q, want %q", buf, tag)
	}
	return conn.SetReadDeadline(time.Time{})
}

func testServedDialTag(t *testing.T, dial func() (net.Conn, error), tag string) net.Conn {
	t.Helper()
	conn, err := dial()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, testServedReadTag(conn, tag))
	return conn
}

func testServedRequireClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, err := conn.Read(make([]byte, 1))
	require.Error(t, err)
	var netErr net.Error
	require.False(t, errors.As(err, &netErr) && netErr.Timeout(), "the stale connection was not closed")
}

func testServedRequireOpen(t *testing.T, conn net.Conn) {
	t.Helper()
	require.NoError(t, testServedEcho(conn))
}

func testServedTCPListener(l *listener) net.Listener {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lis
}

func TestServedTCPUpstreamUpdateKeepsListener(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		port    uint32
		gvisor  bool
	}{
		{"host", "127.0.0.1", 0, false},
		{"gvisor-v4", "100.64.0.2", 12345, true},
		{"gvisor-v6", "fd00::2", 12345, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := newTestServedTaggedBackend(t, "first")
			second := newTestServedTaggedBackend(t, "second")
			opts := &Opts{
				Name: "update.default", L4Type: userv1.HostedService_TCP,
				Listeners: []OptsListener{{Address: tc.address, Port: tc.port}},
				Upstream:  first,
			}
			var goNet *netstack.Net
			if tc.gvisor {
				dev, n, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(tc.address)}, nil, 1280)
				require.NoError(t, err)
				t.Cleanup(func() { dev.Close() })
				goNet = n
				opts.goNetCtl = &testRecoveringGoNet{goNet: n}
			}
			p := NewProxy(opts)
			require.NoError(t, p.Start(t.Context()))
			t.Cleanup(func() { assert.NoError(t, p.Close()) })
			l := p.listeners[0]
			require.Eventually(t, func() bool { return testServedListenerAddress(l) != "" }, 3*time.Second, time.Millisecond)
			addr := testServedListenerAddress(l)
			lis := testServedTCPListener(l)
			dial := func() (net.Conn, error) {
				if goNet == nil {
					return net.DialTimeout("tcp", addr, time.Second)
				}
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
				if err != nil {
					return nil, err
				}
				return goNet.DialContextTCP(ctx, tcpAddr)
			}

			current := testServedDialTag(t, dial, "first")
			testServedRequireOpen(t, current)
			for i, next := range []struct {
				upstream OptsUpstream
				tag      string
			}{
				{second, "second"},
				{first, "first"},
				{second, "second"},
			} {
				require.NoError(t, p.UpdateUpstream(next.upstream), "update %d", i)
				testServedRequireClosed(t, current)
				assert.Same(t, lis, testServedTCPListener(l), "update %d replaced the listener", i)
				assert.Equal(t, addr, testServedListenerAddress(l))
				current = testServedDialTag(t, dial, next.tag)
				testServedRequireOpen(t, current)
			}

			require.NoError(t, p.UpdateUpstream(second))
			testServedRequireOpen(t, current)
			assert.Same(t, lis, testServedTCPListener(l))
		})
	}
}

func TestServedUpstreamUpdateClosesOnlyStaleConnections(t *testing.T) {
	l := newListener("127.0.0.1", 0, &Opts{
		Name: "stale.default", L4Type: userv1.HostedService_TCP,
		Upstream: OptsUpstream{Address: "127.0.0.1", Port: 1},
	})
	pending, pendingPeer := net.Pipe()
	assigned, assignedPeer := net.Pipe()
	current, currentPeer := net.Pipe()
	for _, conn := range []net.Conn{pending, pendingPeer, assigned, assignedPeer, current, currentPeer} {
		t.Cleanup(func() { conn.Close() })
	}
	requirePeerOpen := func(conn net.Conn) {
		t.Helper()
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
		_, err := conn.Read(make([]byte, 1))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	}
	requirePeerClosed := func(conn net.Conn) {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			require.ErrorIs(t, err, io.ErrClosedPipe)
			return
		}
		_, err := conn.Read(make([]byte, 1))
		require.ErrorIs(t, err, io.EOF)
	}

	require.True(t, l.addConn(pending))
	require.True(t, l.addConn(assigned))
	host, ok := l.getConnUpstreamHost(assigned)
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1:1", host)

	l.setUpstreamHost("127.0.0.1:1")
	requirePeerOpen(assignedPeer)

	l.setUpstreamHost("127.0.0.1:2")
	requirePeerClosed(assignedPeer)
	requirePeerOpen(pendingPeer)
	assert.Equal(t, "127.0.0.1:2", l.getUpstreamHost())

	host, ok = l.getConnUpstreamHost(pending)
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1:2", host)
	require.True(t, l.addConn(current))
	host, ok = l.getConnUpstreamHost(current)
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1:2", host)

	l.removeConn(assigned)
	_, ok = l.getConnUpstreamHost(assigned)
	assert.False(t, ok)

	l.setUpstreamHost("[::1]:3")
	requirePeerClosed(pendingPeer)
	requirePeerClosed(currentPeer)

	require.NoError(t, l.close())
	_, ok = l.getConnUpstreamHost(pending)
	assert.False(t, ok)
	assert.False(t, l.addConn(pending))
}

func TestServedProxyUpdateUpstreamRejectsUnsupportedUpdates(t *testing.T) {
	var nilProxy *Proxy
	assert.Error(t, nilProxy.UpdateUpstream(OptsUpstream{Address: "127.0.0.1", Port: 80}))

	first := newTestServedTaggedBackend(t, "first")
	second := newTestServedTaggedBackend(t, "second")
	p := NewProxy(&Opts{
		Name: "rejected.default", L4Type: userv1.HostedService_TCP,
		Listeners: []OptsListener{{Address: "127.0.0.1"}},
		Upstream:  first,
	})
	require.Error(t, p.UpdateUpstream(OptsUpstream{Address: "127.0.0.1", Port: 65536}))
	assert.Equal(t, joinUpstreamHost(first), p.listeners[0].getUpstreamHost())
	assert.Equal(t, first, p.opts.Upstream)

	require.NoError(t, p.UpdateUpstream(second))
	require.NoError(t, p.Start(t.Context()))
	require.Eventually(t, func() bool { return testServedListenerAddress(p.listeners[0]) != "" }, time.Second, time.Millisecond)
	addr := testServedListenerAddress(p.listeners[0])
	testServedDialTag(t, func() (net.Conn, error) { return net.DialTimeout("tcp", addr, time.Second) }, "second")

	require.NoError(t, p.Close())
	require.Error(t, p.UpdateUpstream(first))
	assert.Equal(t, joinUpstreamHost(second), p.listeners[0].getUpstreamHost())

	udpOpts := newTestServedOpts(t, "udp")
	udpProxy := NewProxy(udpOpts)
	upstream := udpOpts.Upstream
	require.Error(t, udpProxy.UpdateUpstream(OptsUpstream{Address: "127.0.0.1", Port: 1}))
	assert.Equal(t, upstream, udpProxy.opts.Upstream)
	assert.Equal(t, joinUpstreamHost(upstream), udpProxy.listeners[0].getUpstreamHost())
	require.NoError(t, udpProxy.Start(t.Context()))
	t.Cleanup(func() { assert.NoError(t, udpProxy.Close()) })
	require.Eventually(t, func() bool { return testServedListenerAddress(udpProxy.listeners[0]) != "" }, time.Second, time.Millisecond)
	assert.True(t, testServedRoundTrip("udp", testServedListenerAddress(udpProxy.listeners[0])))
}

func TestServedTCPUpstreamUpdatesDuringConcurrentConnections(t *testing.T) {
	first := newTestServedTaggedBackend(t, "first")
	second := newTestServedTaggedBackend(t, "second")
	p := NewProxy(&Opts{
		Name: "concurrent.default", L4Type: userv1.HostedService_TCP,
		Listeners: []OptsListener{{Address: "127.0.0.1"}},
		Upstream:  first,
	})
	require.NoError(t, p.Start(t.Context()))
	t.Cleanup(func() { assert.NoError(t, p.Close()) })
	require.Eventually(t, func() bool { return testServedListenerAddress(p.listeners[0]) != "" }, time.Second, time.Millisecond)
	addr := testServedListenerAddress(p.listeners[0])
	lis := testServedTCPListener(p.listeners[0])

	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	var served atomic.Int32
	for range 8 {
		wg.Go(func() {
			for ctx.Err() == nil {
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err != nil {
					assert.NoError(t, err)
					return
				}
				conn.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, len("second"))
				n, err := io.ReadAtLeast(conn, buf, len("first"))
				conn.Close()
				if err != nil {
					continue
				}
				if tag := string(buf[:n]); tag == "first" || tag == "second" {
					served.Add(1)
				} else {
					assert.Fail(t, "unexpected upstream", tag)
				}
			}
		})
	}
	for i := range 50 {
		upstream := first
		if i%2 == 0 {
			upstream = second
		}
		require.NoError(t, p.UpdateUpstream(upstream))
		time.Sleep(time.Millisecond)
	}
	cancel()
	wg.Wait()
	assert.Positive(t, served.Load())

	require.NoError(t, p.UpdateUpstream(second))
	assert.Same(t, lis, testServedTCPListener(p.listeners[0]))
	for range 5 {
		testServedDialTag(t, func() (net.Conn, error) { return net.DialTimeout("tcp", addr, time.Second) }, "second")
	}
}
