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

package tcp

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func newTestUpstream(t *testing.T, handle func(conn *net.TCPConn)) *net.TCPAddr {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)

	t.Cleanup(func() {
		lis.Close()
	})

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go handle(conn.(*net.TCPConn))
		}
	}()

	return lis.Addr().(*net.TCPAddr)
}

func newTestProxiedConn(t *testing.T, upstream *net.TCPAddr) *net.TCPConn {
	pp, err := NewProxy(upstream.String())
	assert.Nil(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)

	t.Cleanup(func() {
		lis.Close()
	})

	go func() {
		conn, err := lis.Accept()
		if err != nil {
			return
		}

		connBackend, err := net.DialTCP("tcp", nil, upstream)
		if err != nil {
			conn.Close()
			return
		}

		pp.ServeTCP(conn.(*net.TCPConn), connBackend)
	}()

	conn, err := net.DialTCP("tcp", nil, lis.Addr().(*net.TCPAddr))
	assert.Nil(t, err)

	t.Cleanup(func() {
		conn.Close()
	})

	return conn
}

func TestServeTCPDeliversResponseAfterClientHalfClose(t *testing.T) {
	const want = "the complete response body that must not be truncated"

	upstream := newTestUpstream(t, func(conn *net.TCPConn) {
		defer conn.Close()

		if _, err := io.ReadAll(conn); err != nil {
			return
		}

		conn.Write([]byte(want))
		conn.CloseWrite()
	})

	conn := newTestProxiedConn(t, upstream)

	_, err := conn.Write([]byte("request"))
	assert.Nil(t, err)
	assert.Nil(t, conn.CloseWrite())

	assert.Nil(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))

	got, err := io.ReadAll(conn)
	assert.Nil(t, err)
	assert.Equal(t, want, string(got))
}

func TestServeTCPDeliversLargeResponseAfterClientHalfClose(t *testing.T) {
	want := strings.Repeat("octelium", 256*1024)

	upstream := newTestUpstream(t, func(conn *net.TCPConn) {
		defer conn.Close()

		if _, err := io.ReadAll(conn); err != nil {
			return
		}

		io.Copy(conn, strings.NewReader(want))
		conn.CloseWrite()
	})

	conn := newTestProxiedConn(t, upstream)

	_, err := conn.Write([]byte("request"))
	assert.Nil(t, err)
	assert.Nil(t, conn.CloseWrite())

	assert.Nil(t, conn.SetReadDeadline(time.Now().Add(30*time.Second)))

	got, err := io.ReadAll(conn)
	assert.Nil(t, err)
	assert.Equal(t, len(want), len(got))
}

func TestServeTCPEchoBothDirections(t *testing.T) {
	upstream := newTestUpstream(t, func(conn *net.TCPConn) {
		defer conn.Close()
		io.Copy(conn, conn)
	})

	conn := newTestProxiedConn(t, upstream)

	_, err := conn.Write([]byte("ping"))
	assert.Nil(t, err)

	assert.Nil(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))

	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	assert.Nil(t, err)
	assert.Equal(t, "ping", string(buf))
}

func TestServeTCPClosesBothSidesWhenUpstreamEnds(t *testing.T) {
	upstream := newTestUpstream(t, func(conn *net.TCPConn) {
		conn.Write([]byte("bye"))
		conn.Close()
	})

	conn := newTestProxiedConn(t, upstream)

	assert.Nil(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))

	got, err := io.ReadAll(conn)
	assert.Nil(t, err)
	assert.Equal(t, "bye", string(got))
}

func TestServeTCPDeliversDelayedResponseAfterClientHalfClose(t *testing.T) {
	const want = "the response that is sent after a long processing time"

	upstream := newTestUpstream(t, func(conn *net.TCPConn) {
		defer conn.Close()

		body, err := io.ReadAll(conn)
		if err != nil || string(body) != "request" {
			return
		}

		time.Sleep(2500 * time.Millisecond)

		conn.Write([]byte(want))
		conn.CloseWrite()
	})

	conn := newTestProxiedConn(t, upstream)

	_, err := conn.Write([]byte("request"))
	assert.Nil(t, err)
	assert.Nil(t, conn.CloseWrite())

	assert.Nil(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))

	got, err := io.ReadAll(conn)
	assert.Nil(t, err)
	assert.Equal(t, want, string(got))
}

func TestServeTCPDeliversDelayedRequestAfterUpstreamHalfClose(t *testing.T) {
	gotCh := make(chan string, 1)

	upstream := newTestUpstream(t, func(conn *net.TCPConn) {
		defer conn.Close()

		conn.Write([]byte("greeting"))
		conn.CloseWrite()

		body, _ := io.ReadAll(conn)
		gotCh <- string(body)
	})

	conn := newTestProxiedConn(t, upstream)

	assert.Nil(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))

	got, err := io.ReadAll(conn)
	assert.Nil(t, err)
	assert.Equal(t, "greeting", string(got))

	time.Sleep(2500 * time.Millisecond)

	_, err = conn.Write([]byte("delayed request"))
	assert.Nil(t, err)
	assert.Nil(t, conn.CloseWrite())

	select {
	case body := <-gotCh:
		assert.Equal(t, "delayed request", body)
	case <-time.After(10 * time.Second):
		t.Fatal("The upstream did not receive the request")
	}
}

func TestServeTCPCopyErrorClosesBothConnections(t *testing.T) {
	upstream := newTestUpstream(t, func(conn *net.TCPConn) {
		buf := make([]byte, len("request"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			return
		}

		conn.SetLinger(0)
		conn.Close()
	})

	pp, err := NewProxy(upstream.String())
	assert.Nil(t, err)

	client, downstream := newTestTCPPair(t)

	connBackend, err := net.DialTCP("tcp", nil, upstream)
	assert.Nil(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		pp.ServeTCP(downstream, connBackend)
	}()

	_, err = client.Write([]byte("request"))
	assert.Nil(t, err)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("The TCP proxy did not stop after the upstream reset the connection")
	}

	assert.Nil(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = client.Read(make([]byte, 1))
	assert.NotNil(t, err)
	if netErr, ok := err.(net.Error); ok {
		assert.False(t, netErr.Timeout())
	}
}

func newTestTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	lis, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	assert.Nil(t, err)
	defer lis.Close()

	client, err := net.DialTCP("tcp", nil, lis.Addr().(*net.TCPAddr))
	assert.Nil(t, err)

	server, err := lis.AcceptTCP()
	assert.Nil(t, err)

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	return client, server
}
