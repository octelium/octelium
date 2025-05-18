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
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/stretchr/testify/assert"
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
