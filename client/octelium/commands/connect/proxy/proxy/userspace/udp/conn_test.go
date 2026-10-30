package udp

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func newTestUDPListener(t *testing.T) *Listener {
	t.Helper()
	l, err := Listen("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, l.Close()) })
	return l
}

func newTestUDPSession(t *testing.T, l *Listener) (*net.UDPConn, *Conn) {
	t.Helper()
	client, err := net.DialUDP("udp4", nil, l.Addr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = client.Write([]byte("first"))
	require.NoError(t, err)
	accepted := make(chan *Conn, 1)
	go func() {
		c, _ := l.Accept()
		accepted <- c
	}()
	select {
	case c := <-accepted:
		require.NotNil(t, c)
		t.Cleanup(func() { c.Close() })
		return client, c
	case <-time.After(5 * time.Second):
		t.Fatal("the UDP listener did not accept a session")
		return nil, nil
	}
}

func TestUDPSessionRoundTripAndDatagramBoundaries(t *testing.T) {
	l := newTestUDPListener(t)
	client, c := newTestUDPSession(t, l)
	buf := make([]byte, receiveMTU)
	n, err := c.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "first", string(buf[:n]))
	for _, payload := range [][]byte{[]byte("second"), {}, bytes.Repeat([]byte("a"), receiveMTU)} {
		_, err := client.Write(payload)
		require.NoError(t, err)
		n, err := c.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, payload, buf[:n])
		n, err = c.Write(buf[:n])
		require.NoError(t, err)
		assert.Equal(t, len(payload), n)
		n, err = client.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, payload, buf[:n])
	}
	require.NoError(t, c.Close())
	n, err = c.Read(buf)
	assert.Zero(t, n)
	assert.ErrorIs(t, err, io.EOF)
	assert.NoError(t, c.Close())
}

func TestUDPListenerSeparatesClientsAndUnblocksAcceptOnClose(t *testing.T) {
	l := newTestUDPListener(t)
	first, a := newTestUDPSession(t, l)
	second, b := newTestUDPSession(t, l)
	assert.NotEqual(t, first.LocalAddr().String(), second.LocalAddr().String())
	assert.NotSame(t, a, b)
	for _, c := range []*Conn{a, b} {
		buf := make([]byte, 16)
		n, err := c.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "first", string(buf[:n]))
	}
	accepted := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		accepted <- err
	}()
	require.NoError(t, l.Close())
	select {
	case err := <-accepted:
		assert.ErrorIs(t, err, errClosedListener)
	case <-time.After(time.Second):
		t.Fatal("closing the UDP listener must unblock Accept")
	}
	for _, c := range []*Conn{a, b} {
		_, err := c.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF)
	}
	assert.NoError(t, l.Close())
}

func TestUDPReadTruncatesOneDatagramWithoutMergingNext(t *testing.T) {
	l := newTestUDPListener(t)
	client, c := newTestUDPSession(t, l)
	buf := make([]byte, 2)
	n, err := c.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "fi", string(buf[:n]))
	_, err = client.Write([]byte("next"))
	require.NoError(t, err)
	buf = make([]byte, 16)
	n, err = c.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "next", string(buf[:n]))
}

func TestUDPConcurrentCloseAndRead(t *testing.T) {
	l := newTestUDPListener(t)
	_, c := newTestUDPSession(t, l)
	_, err := c.Read(make([]byte, 16))
	require.NoError(t, err)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.NoError(t, c.Close())
		}()
	}
	_, err = c.Read(make([]byte, 16))
	assert.ErrorIs(t, err, io.EOF)
	wg.Wait()
}

func TestUDPQueuedMessagesStayBounded(t *testing.T) {
	c := &Conn{}
	for range maxConnQueuedMsgs + 100 {
		c.msgs = c.appendMsg([]byte("datagram"))
	}
	assert.Len(t, c.msgs, maxConnQueuedMsgs)
}

func TestUDPSessionIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := &Listener{accepting: true, conns: make(map[string]*Conn), acceptCh: make(chan *Conn, 1)}
		c, err := l.getConn(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
		require.NoError(t, err)
		c.receiveCh <- []byte("first")
		_, err = c.Read(make([]byte, 16))
		require.NoError(t, err)
		time.Sleep(connTimeout - time.Nanosecond)
		synctest.Wait()
		l.mu.RLock()
		assert.Len(t, l.conns, 1)
		l.mu.RUnlock()
		time.Sleep(timeoutTicker + time.Nanosecond)
		synctest.Wait()
		l.mu.RLock()
		assert.Empty(t, l.conns)
		l.mu.RUnlock()
		_, err = c.Read(make([]byte, 16))
		assert.ErrorIs(t, err, io.EOF)
	})
}

func TestUDPProxyRoundTripAndListenerShutdown(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			backend.WriteToUDP(buf[:n], addr)
		}
	}()
	l := newTestUDPListener(t)
	p, err := NewProxy(backend.LocalAddr().String())
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err == nil {
			HandlerFunc(p.ServeUDP).ServeUDP(c)
		}
	}()
	client, err := net.DialUDP("udp4", nil, l.Addr().(*net.UDPAddr))
	require.NoError(t, err)
	defer client.Close()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = client.Write([]byte("proxied"))
	require.NoError(t, err)
	buf := make([]byte, 16)
	n, err := client.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "proxied", string(buf[:n]))
	require.NoError(t, l.Close())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the UDP proxy must stop when its listener closes")
	}
}

func TestUDPKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to run unresolved regressions listed in tmp/client-test-report.md")
	}
	t.Run("CL-013-stale-close-removes-new-session", func(t *testing.T) {
		l := newTestUDPListener(t)
		addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		old, err := l.getConn(addr)
		require.NoError(t, err)
		require.NoError(t, old.Close())
		current, err := l.getConn(addr)
		require.NoError(t, err)
		require.NoError(t, old.Close())
		l.mu.RLock()
		assert.Same(t, current, l.conns[addr.String()])
		l.mu.RUnlock()
	})
	t.Run("CL-014-write-after-close", func(t *testing.T) {
		l := newTestUDPListener(t)
		_, c := newTestUDPSession(t, l)
		require.NoError(t, c.Close())
		_, err := c.Write([]byte("must not be sent"))
		assert.Error(t, err)
	})
	t.Run("CL-015-new-session-expires-at-first-tick", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			l := &Listener{accepting: true, conns: make(map[string]*Conn), acceptCh: make(chan *Conn, 1)}
			c, err := l.getConn(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
			require.NoError(t, err)
			c.receiveCh <- []byte("waiting for a consumer")
			time.Sleep(timeoutTicker)
			synctest.Wait()
			l.mu.RLock()
			assert.Len(t, l.conns, 1)
			l.mu.RUnlock()
			c.Close()
		})
	})
	t.Run("CL-016-large-datagram-truncated", func(t *testing.T) {
		l := newTestUDPListener(t)
		client, c := newTestUDPSession(t, l)
		_, err := c.Read(make([]byte, 16))
		require.NoError(t, err)
		payload := bytes.Repeat([]byte("a"), receiveMTU+1)
		_, err = client.Write(payload)
		require.NoError(t, err)
		buf := make([]byte, len(payload))
		n, err := c.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, payload, buf[:n])
	})
}

func TestUDPGoNetPacketConnPreservesSessionsAndDatagrams(t *testing.T) {
	for _, address := range []string{"100.64.0.2", "fd00::2"} {
		t.Run(address, func(t *testing.T) {
			dev, goNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(address)}, nil, 1280)
			require.NoError(t, err)
			t.Cleanup(func() { dev.Close() })
			packetConn, err := goNet.DialUDP(&net.UDPAddr{IP: net.ParseIP(address)}, nil)
			require.NoError(t, err)
			l := NewListener(packetConn)
			t.Cleanup(func() { l.Close() })
			require.Equal(t, packetConn.LocalAddr().String(), l.Addr().String())
			sessions := make([]*Conn, 0, 2)
			for range 2 {
				client, err := goNet.DialUDP(nil, l.Addr().(*net.UDPAddr))
				require.NoError(t, err)
				t.Cleanup(func() { client.Close() })
				require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
				_, err = client.Write([]byte("first"))
				require.NoError(t, err)
				accepted := make(chan *Conn, 1)
				go func() {
					c, _ := l.Accept()
					accepted <- c
				}()
				var c *Conn
				select {
				case c = <-accepted:
					require.NotNil(t, c)
				case <-time.After(time.Second):
					t.Fatal("the userspace UDP listener did not accept a session")
				}
				sessions = append(sessions, c)
				buf := make([]byte, receiveMTU)
				n, err := c.Read(buf)
				require.NoError(t, err)
				require.Equal(t, "first", string(buf[:n]))
				for _, payload := range [][]byte{[]byte("second"), {}, bytes.Repeat([]byte("a"), receiveMTU)} {
					_, err := client.Write(payload)
					require.NoError(t, err)
					n, err := c.Read(buf)
					require.NoError(t, err)
					require.Equal(t, payload, buf[:n])
					n, err = c.Write(buf[:n])
					require.NoError(t, err)
					require.Equal(t, len(payload), n)
					n, err = client.Read(buf)
					require.NoError(t, err)
					require.Equal(t, payload, buf[:n])
				}
			}
			require.NotSame(t, sessions[0], sessions[1])
			addr := l.Addr().(*net.UDPAddr)
			require.NoError(t, l.Close())
			for _, c := range sessions {
				_, err := c.Read(make([]byte, 1))
				assert.ErrorIs(t, err, io.EOF)
			}
			probe, err := goNet.DialUDP(addr, nil)
			require.NoError(t, err)
			assert.NoError(t, probe.Close())
		})
	}
}

type testOwnedPacketConn struct {
	net.PacketConn
	closes atomic.Int32
	done   chan struct{}
}

func (c *testOwnedPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		close(c.done)
	}
	return n, addr, err
}

func (c *testOwnedPacketConn) Close() error {
	c.closes.Add(1)
	return c.PacketConn.Close()
}

func TestUDPWrappedPacketConnCloseOwnsSocketAndUnblocksAccept(t *testing.T) {
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	wrapped := &testOwnedPacketConn{PacketConn: packetConn, done: make(chan struct{})}
	l := NewListener(wrapped)
	t.Cleanup(func() { l.Close() })
	accepted := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		accepted <- err
	}()
	require.NoError(t, l.Close())
	require.NoError(t, l.Close())
	select {
	case err := <-accepted:
		require.ErrorIs(t, err, errClosedListener)
	case <-time.After(time.Second):
		t.Fatal("closing the packet listener did not unblock Accept")
	}
	select {
	case <-wrapped.done:
	case <-time.After(time.Second):
		t.Fatal("closing the packet listener did not stop its packet read")
	}
	assert.Equal(t, int32(1), wrapped.closes.Load())
	probe, err := net.ListenPacket("udp", l.Addr().String())
	require.NoError(t, err)
	assert.NoError(t, probe.Close())
}
