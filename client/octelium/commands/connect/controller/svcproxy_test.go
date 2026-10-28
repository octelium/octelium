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

package controller

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const testNetstackAddr = "100.64.0.2"

func newTestSvcProxyCtl(t *testing.T, svcs ...*cliconfigv1.Connection_Preferences_PublishedService) *Controller {
	return &Controller{
		ipv4Supported: true,
		c: &cliconfigv1.Connection{
			Preferences: &cliconfigv1.Connection_Preferences{
				PublishedServices: svcs,
			},
		},
	}
}

func getFreeTestPortTCP(t *testing.T) int {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "%+v", err)
	port := lis.Addr().(*net.TCPAddr).Port
	assert.Nil(t, lis.Close())

	return port
}

func getFreeTestPortUDP(t *testing.T) int {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.Nil(t, err, "%+v", err)
	port := conn.LocalAddr().(*net.UDPAddr).Port
	assert.Nil(t, conn.Close())

	return port
}

func startTestEchoServerTCP(t *testing.T, lis net.Listener) {
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(conn)
		}
	}()
}

func startTestEchoServerUDP(t *testing.T, conn net.PacketConn) {
	go func() {
		buf := make([]byte, 2048)
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
}

func waitTestListener(t *testing.T, l *listener) {
	for range 100 {
		l.mu.Lock()
		isStarted := l.lis != nil || l.udpLis != nil
		l.mu.Unlock()
		if isStarted {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("The listener on port %d did not start", l.hostPort)
}

func doTestEchoTCP(t *testing.T, hostPort int) {
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", hostPort)))
	assert.Nil(t, err, "%+v", err)
	defer conn.Close()

	assert.Nil(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	msg := []byte("octelium-tcp")
	_, err = conn.Write(msg)
	assert.Nil(t, err, "%+v", err)

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, msg, buf)
}

func doTestEchoUDP(t *testing.T, hostPort int) {
	conn, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", hostPort)))
	assert.Nil(t, err, "%+v", err)
	defer conn.Close()

	assert.Nil(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	msg := []byte("octelium-udp")
	_, err = conn.Write(msg)
	assert.Nil(t, err, "%+v", err)

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, msg, buf[:n])
}

func TestServiceProxyTCP(t *testing.T) {
	ctx := context.Background()

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "%+v", err)
	defer backend.Close()

	startTestEchoServerTCP(t, backend)

	hostPort := getFreeTestPortTCP(t)

	c := newTestSvcProxyCtl(t, &cliconfigv1.Connection_Preferences_PublishedService{
		Fqdn:        "127.0.0.1",
		Port:        int32(backend.Addr().(*net.TCPAddr).Port),
		HostPort:    int32(hostPort),
		HostAddress: "127.0.0.1",
		L4Type:      cliconfigv1.Connection_Preferences_PublishedService_TCP,
	})

	p, err := newServiceProxy(c)
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, p.Start(ctx))
	defer p.Close()

	waitTestListener(t, p.listeners[0])

	doTestEchoTCP(t, hostPort)
}

func TestServiceProxyUDP(t *testing.T) {
	ctx := context.Background()

	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.Nil(t, err, "%+v", err)
	defer backend.Close()

	startTestEchoServerUDP(t, backend)

	hostPort := getFreeTestPortUDP(t)

	c := newTestSvcProxyCtl(t, &cliconfigv1.Connection_Preferences_PublishedService{
		Fqdn:        "127.0.0.1",
		Port:        int32(backend.LocalAddr().(*net.UDPAddr).Port),
		HostPort:    int32(hostPort),
		HostAddress: "127.0.0.1",
		L4Type:      cliconfigv1.Connection_Preferences_PublishedService_UDP,
	})

	p, err := newServiceProxy(c)
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, p.Start(ctx))
	defer p.Close()

	waitTestListener(t, p.listeners[0])

	doTestEchoUDP(t, hostPort)
}

func TestServiceProxyNetstackTCP(t *testing.T) {
	ctx := context.Background()

	c := newTestNetstackCtl(t)
	defer c.nsTun.Close()

	backendPort := getFreeTestPortTCP(t)

	backend, err := c.GetNetstackNet().ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP(testNetstackAddr),
		Port: backendPort,
	})
	assert.Nil(t, err, "%+v", err)
	defer backend.Close()

	startTestEchoServerTCP(t, backend)

	hostPort := getFreeTestPortTCP(t)

	c.c.Preferences.PublishedServices = []*cliconfigv1.Connection_Preferences_PublishedService{
		{
			Fqdn:        testNetstackAddr,
			Port:        int32(backendPort),
			HostPort:    int32(hostPort),
			HostAddress: "127.0.0.1",
			L4Type:      cliconfigv1.Connection_Preferences_PublishedService_TCP,
		},
	}

	p, err := newServiceProxy(c)
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, p.listeners[0].gonet)
	assert.Nil(t, p.Start(ctx))
	defer p.Close()

	waitTestListener(t, p.listeners[0])

	doTestEchoTCP(t, hostPort)
}

func TestServiceProxyNetstackUDP(t *testing.T) {
	ctx := context.Background()

	c := newTestNetstackCtl(t)
	defer c.nsTun.Close()

	backendPort := getFreeTestPortUDP(t)

	fa, pn := convertToFullAddr(net.ParseIP(testNetstackAddr), backendPort)
	backend, err := gonet.DialUDP(c.nsTun.stack, &fa, nil, pn)
	assert.Nil(t, err, "%+v", err)
	defer backend.Close()

	startTestEchoServerUDP(t, backend)

	hostPort := getFreeTestPortUDP(t)

	c.c.Preferences.PublishedServices = []*cliconfigv1.Connection_Preferences_PublishedService{
		{
			Fqdn:        testNetstackAddr,
			Port:        int32(backendPort),
			HostPort:    int32(hostPort),
			HostAddress: "127.0.0.1",
			L4Type:      cliconfigv1.Connection_Preferences_PublishedService_UDP,
		},
	}

	p, err := newServiceProxy(c)
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, p.listeners[0].gonet)
	assert.Nil(t, p.Start(ctx))
	defer p.Close()

	waitTestListener(t, p.listeners[0])

	doTestEchoUDP(t, hostPort)
}

func TestServiceProxyCloseReleasesListeners(t *testing.T) {
	ctx := context.Background()

	hostPortTCP := getFreeTestPortTCP(t)
	hostPortUDP := getFreeTestPortUDP(t)

	c := newTestSvcProxyCtl(t,
		&cliconfigv1.Connection_Preferences_PublishedService{
			Fqdn:        "127.0.0.1",
			Port:        int32(getFreeTestPortTCP(t)),
			HostPort:    int32(hostPortTCP),
			HostAddress: "127.0.0.1",
			L4Type:      cliconfigv1.Connection_Preferences_PublishedService_TCP,
		},
		&cliconfigv1.Connection_Preferences_PublishedService{
			Fqdn:        "127.0.0.1",
			Port:        int32(getFreeTestPortUDP(t)),
			HostPort:    int32(hostPortUDP),
			HostAddress: "127.0.0.1",
			L4Type:      cliconfigv1.Connection_Preferences_PublishedService_UDP,
		})

	p, err := newServiceProxy(c)
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, p.Start(ctx))

	for _, l := range p.listeners {
		waitTestListener(t, l)
	}

	assert.Nil(t, p.Close())
	assert.Nil(t, p.Close())

	lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", hostPortTCP)))
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, lis.Close())

	conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", hostPortUDP)))
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, conn.Close())
}

func TestServiceProxyCloseBeforeStart(t *testing.T) {
	ctx := context.Background()

	hostPortUDP := getFreeTestPortUDP(t)

	c := newTestSvcProxyCtl(t, &cliconfigv1.Connection_Preferences_PublishedService{
		Fqdn:        "127.0.0.1",
		Port:        int32(getFreeTestPortUDP(t)),
		HostPort:    int32(hostPortUDP),
		HostAddress: "127.0.0.1",
		L4Type:      cliconfigv1.Connection_Preferences_PublishedService_UDP,
	})

	p, err := newServiceProxy(c)
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, p.Close())
	assert.Nil(t, p.Start(ctx))

	time.Sleep(500 * time.Millisecond)

	conn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", hostPortUDP)))
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, conn.Close())
}

func TestServiceProxyAddPreservesActiveConnections(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backend.Close()
	startTestEchoServerTCP(t, backend)
	udpBackend, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer udpBackend.Close()
	startTestEchoServerUDP(t, udpBackend)
	initial := &cliconfigv1.Connection_Preferences_PublishedService{
		Name: "healthy.default", Fqdn: "127.0.0.1", HostAddress: "127.0.0.1",
		HostPort: int32(getFreeTestPortTCP(t)), Port: int32(backend.Addr().(*net.TCPAddr).Port),
		L4Type: cliconfigv1.Connection_Preferences_PublishedService_TCP,
	}
	c := newTestSvcProxyCtl(t, initial)
	snapshot := proto.Clone(c.c)
	p, err := newServiceProxy(c)
	require.NoError(t, err)
	c.svcProxy = p
	require.NoError(t, p.Start(t.Context()))
	defer p.Close()
	waitTestListener(t, p.listeners[0])
	original := p.listeners[0]
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(initial.HostPort)))
	require.NoError(t, err)
	defer conn.Close()
	exchange := func(msg string) {
		require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		_, err := io.WriteString(conn, msg)
		require.NoError(t, err)
		buf := make([]byte, len(msg))
		_, err = io.ReadFull(conn, buf)
		require.NoError(t, err)
		assert.Equal(t, msg, string(buf))
	}
	exchange("before adding a Service")
	addedTCP := proto.Clone(initial).(*cliconfigv1.Connection_Preferences_PublishedService)
	addedTCP.Name = "late.default"
	addedTCP.HostPort = int32(getFreeTestPortTCP(t))
	udpProbe, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprint(addedTCP.HostPort)))
	require.NoError(t, err)
	require.NoError(t, udpProbe.Close())
	addedUDP := proto.Clone(addedTCP).(*cliconfigv1.Connection_Preferences_PublishedService)
	addedUDP.L4Type = cliconfigv1.Connection_Preferences_PublishedService_UDP
	addedUDP.Port = int32(udpBackend.LocalAddr().(*net.UDPAddr).Port)
	require.NoError(t, c.AddPublishedService(addedTCP))
	require.NoError(t, c.AddPublishedService(addedUDP))
	require.Len(t, p.listeners, 3)
	waitTestListener(t, p.listeners[1])
	waitTestListener(t, p.listeners[2])
	assert.Same(t, original, p.listeners[0])
	exchange("after adding TCP and UDP Services")
	doTestEchoTCP(t, int(addedTCP.HostPort))
	doTestEchoUDP(t, int(addedUDP.HostPort))
	require.NoError(t, c.AddPublishedService(proto.Clone(addedTCP).(*cliconfigv1.Connection_Preferences_PublishedService)))
	require.Len(t, p.listeners, 3)
	conflict := proto.Clone(initial).(*cliconfigv1.Connection_Preferences_PublishedService)
	conflict.Port++
	assert.ErrorContains(t, c.AddPublishedService(conflict), "already in use")
	conflict = proto.Clone(initial).(*cliconfigv1.Connection_Preferences_PublishedService)
	conflict.Fqdn = "192.0.2.1"
	assert.ErrorContains(t, c.AddPublishedService(conflict), "already in use")
	assert.Same(t, original, p.listeners[0])
	exchange("after duplicate and conflicting requests")
	assert.True(t, proto.Equal(snapshot, c.c))
	require.NoError(t, p.Close())
	_, err = conn.Read(make([]byte, 1))
	assert.Error(t, err)
	for _, svc := range []*cliconfigv1.Connection_Preferences_PublishedService{initial, addedTCP} {
		lis, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(svc.HostPort)))
		require.NoError(t, err)
		require.NoError(t, lis.Close())
	}
	packetConn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", fmt.Sprint(addedUDP.HostPort)))
	require.NoError(t, err)
	require.NoError(t, packetConn.Close())
}

func TestServiceProxyAddValidationAndLifecycle(t *testing.T) {
	valid := &cliconfigv1.Connection_Preferences_PublishedService{
		Name: "late.default", Fqdn: "127.0.0.1", HostAddress: "127.0.0.1",
		HostPort: int32(getFreeTestPortTCP(t)), Port: 8080,
		L4Type: cliconfigv1.Connection_Preferences_PublishedService_TCP,
	}
	c := newTestSvcProxyCtl(t)
	assert.ErrorContains(t, c.AddPublishedService(valid), "not initialized")
	p, err := newServiceProxy(c)
	require.NoError(t, err)
	c.svcProxy = p
	assert.ErrorContains(t, c.AddPublishedService(valid), "not started")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	require.NoError(t, p.Start(ctx))
	defer p.Close()
	invalid := []*cliconfigv1.Connection_Preferences_PublishedService{nil, {}}
	for _, field := range []string{"fqdn", "port-zero", "port-negative", "port-overflow", "host-port-zero", "host-port-negative", "host-port-overflow", "protocol"} {
		svc := proto.Clone(valid).(*cliconfigv1.Connection_Preferences_PublishedService)
		switch field {
		case "fqdn":
			svc.Fqdn = ""
		case "port-zero":
			svc.Port = 0
		case "port-negative":
			svc.Port = -1
		case "port-overflow":
			svc.Port = 65536
		case "host-port-zero":
			svc.HostPort = 0
		case "host-port-negative":
			svc.HostPort = -1
		case "host-port-overflow":
			svc.HostPort = 65536
		case "protocol":
			svc.L4Type = 99
		}
		invalid = append(invalid, svc)
	}
	for _, svc := range invalid {
		assert.Error(t, c.AddPublishedService(svc))
	}
	assert.Empty(t, p.listeners)
	cancel()
	assert.ErrorIs(t, c.AddPublishedService(valid), context.Canceled)
	assert.Empty(t, p.listeners)
	require.NoError(t, p.Close())
	assert.ErrorContains(t, c.AddPublishedService(valid), "already closed")
	c.isClosed = true
	assert.ErrorContains(t, c.AddPublishedService(valid), "controller is already closed")
}

func TestServiceProxyConcurrentAddAndClose(t *testing.T) {
	for _, typ := range []cliconfigv1.Connection_Preferences_PublishedService_L4Type{
		cliconfigv1.Connection_Preferences_PublishedService_TCP,
		cliconfigv1.Connection_Preferences_PublishedService_UDP,
	} {
		t.Run(typ.String(), func(t *testing.T) {
			c := newTestSvcProxyCtl(t)
			p, err := newServiceProxy(c)
			require.NoError(t, err)
			c.svcProxy = p
			require.NoError(t, p.Start(t.Context()))
			defer p.Close()
			port := getFreeTestPortTCP(t)
			if typ == cliconfigv1.Connection_Preferences_PublishedService_UDP {
				port = getFreeTestPortUDP(t)
			}
			svc := &cliconfigv1.Connection_Preferences_PublishedService{
				Fqdn: "127.0.0.1", Port: 8080, HostPort: int32(port), HostAddress: "127.0.0.1", L4Type: typ,
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			for range 32 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					c.AddPublishedService(svc)
				}()
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				assert.NoError(t, p.Close())
			}()
			close(start)
			wg.Wait()
			assert.LessOrEqual(t, len(p.listeners), 1)
			assert.Error(t, c.AddPublishedService(svc))
			for _, l := range p.listeners {
				l.mu.Lock()
				assert.True(t, l.isClosed)
				assert.Empty(t, l.conns)
				l.mu.Unlock()
			}
			assert.Eventually(t, func() bool {
				addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
				if typ == cliconfigv1.Connection_Preferences_PublishedService_UDP {
					conn, err := net.ListenPacket("udp", addr)
					if err != nil {
						return false
					}
					conn.Close()
					return true
				}
				lis, err := net.Listen("tcp", addr)
				if err != nil {
					return false
				}
				lis.Close()
				return true
			}, time.Second, 10*time.Millisecond)
		})
	}
}

func TestServiceProxyAddNetstackServices(t *testing.T) {
	for _, typ := range []cliconfigv1.Connection_Preferences_PublishedService_L4Type{
		cliconfigv1.Connection_Preferences_PublishedService_TCP,
		cliconfigv1.Connection_Preferences_PublishedService_UDP,
	} {
		t.Run(typ.String(), func(t *testing.T) {
			c := newTestNetstackCtl(t)
			defer c.nsTun.Close()
			p, err := newServiceProxy(c)
			require.NoError(t, err)
			c.svcProxy = p
			require.NoError(t, p.Start(t.Context()))
			defer p.Close()
			backendPort, hostPort := getFreeTestPortTCP(t), getFreeTestPortTCP(t)
			if typ == cliconfigv1.Connection_Preferences_PublishedService_UDP {
				backendPort, hostPort = getFreeTestPortUDP(t), getFreeTestPortUDP(t)
				fa, pn := convertToFullAddr(net.ParseIP(testNetstackAddr), backendPort)
				backend, err := gonet.DialUDP(c.nsTun.stack, &fa, nil, pn)
				require.NoError(t, err)
				defer backend.Close()
				startTestEchoServerUDP(t, backend)
			} else {
				backend, err := c.GetNetstackNet().ListenTCP(&net.TCPAddr{IP: net.ParseIP(testNetstackAddr), Port: backendPort})
				require.NoError(t, err)
				defer backend.Close()
				startTestEchoServerTCP(t, backend)
			}
			require.NoError(t, c.AddPublishedService(&cliconfigv1.Connection_Preferences_PublishedService{
				Name: "late.default", Fqdn: testNetstackAddr, Port: int32(backendPort),
				HostAddress: "127.0.0.1", HostPort: int32(hostPort), L4Type: typ,
			}))
			require.Len(t, p.listeners, 1)
			assert.NotNil(t, p.listeners[0].gonet)
			waitTestListener(t, p.listeners[0])
			if typ == cliconfigv1.Connection_Preferences_PublishedService_UDP {
				doTestEchoUDP(t, hostPort)
			} else {
				doTestEchoTCP(t, hostPort)
			}
			assert.Empty(t, c.c.Preferences.PublishedServices)
		})
	}
}
