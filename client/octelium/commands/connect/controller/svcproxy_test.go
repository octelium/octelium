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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/stretchr/testify/assert"
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
