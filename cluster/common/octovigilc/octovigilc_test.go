/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package octovigilc

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const testRequestTimeout = 5 * time.Second

type testService struct {
	coctovigilv1.UnimplementedInternalServiceServer
	delay time.Duration

	mu        sync.Mutex
	calls     int
	firstCall time.Time
}

func (s *testService) Authorize(ctx context.Context, req *coctovigilv1.AuthorizeRequest) (*coctovigilv1.AuthorizeResponse, error) {
	s.mu.Lock()
	if s.calls == 0 {
		s.firstCall = time.Now()
	}
	s.calls++
	s.mu.Unlock()

	time.Sleep(s.delay)

	return &coctovigilv1.AuthorizeResponse{
		IsAuthorized: true,
	}, nil
}

func (s *testService) getCalls() (int, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.firstCall
}

type testListener struct {
	connCh chan net.Conn
	doneCh chan struct{}
	once   sync.Once
}

func (l *testListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connCh:
		return conn, nil
	case <-l.doneCh:
		return nil, net.ErrClosed
	}
}

func (l *testListener) Close() error {
	l.once.Do(func() {
		close(l.doneCh)
	})
	return nil
}

func (l *testListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

type testBackend struct {
	lis *testListener
	svc *testService
}

func newTestBackend(t *testing.T, delay time.Duration, opts ...grpc.ServerOption) *testBackend {
	ret := &testBackend{
		lis: &testListener{
			connCh: make(chan net.Conn),
			doneCh: make(chan struct{}),
		},
		svc: &testService{
			delay: delay,
		},
	}

	srv := grpc.NewServer(append(opts, grpc.Creds(insecure.NewCredentials()))...)
	coctovigilv1.RegisterInternalServiceServer(srv, ret.svc)

	go srv.Serve(ret.lis)
	t.Cleanup(srv.Stop)

	return ret
}

type testFrameReader struct {
	buf     []byte
	preface int
}

func (r *testFrameReader) feed(b []byte, fn func(http2.FrameHeader, []byte)) {
	r.buf = append(r.buf, b...)

	if r.preface > 0 {
		if len(r.buf) < r.preface {
			return
		}
		r.buf = r.buf[r.preface:]
		r.preface = 0
	}

	for {
		hdr, err := http2.ReadFrameHeader(bytes.NewReader(r.buf))
		if err != nil || len(r.buf) < 9+int(hdr.Length) {
			return
		}

		fn(hdr, r.buf[9:9+hdr.Length])
		r.buf = r.buf[9+hdr.Length:]
	}
}

type testGoAway struct {
	code  http2.ErrCode
	debug string
}

type testConn struct {
	net.Conn
	backend   *testBackend
	createdAt time.Time

	mu           sync.Mutex
	isBlackholed bool
	closedAt     time.Time
	written      testFrameReader
	read         testFrameReader
	pings        int
	goAways      []testGoAway
}

func (c *testConn) Read(b []byte) (int, error) {
	for {
		n, err := c.Conn.Read(b)

		c.mu.Lock()
		if !c.isBlackholed {
			c.read.feed(b[:n], func(hdr http2.FrameHeader, payload []byte) {
				if hdr.Type == http2.FrameGoAway {
					c.goAways = append(c.goAways, testGoAway{
						code:  http2.ErrCode(binary.BigEndian.Uint32(payload[4:8])),
						debug: string(payload[8:]),
					})
				}
			})
			c.mu.Unlock()
			return n, err
		}
		c.mu.Unlock()

		if err != nil {
			return 0, err
		}
	}
}

func (c *testConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.isBlackholed {
		c.mu.Unlock()
		return len(b), nil
	}
	c.written.feed(b, func(hdr http2.FrameHeader, payload []byte) {
		if hdr.Type == http2.FramePing && !hdr.Flags.Has(http2.FlagPingAck) &&
			bytes.Equal(payload, make([]byte, 8)) {
			c.pings++
		}
	})
	c.mu.Unlock()

	return c.Conn.Write(b)
}

func (c *testConn) Close() error {
	c.mu.Lock()
	if c.closedAt.IsZero() {
		c.closedAt = time.Now()
	}
	c.mu.Unlock()

	return c.Conn.Close()
}

func (c *testConn) setBlackholed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isBlackholed = true
}

func (c *testConn) getPings() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pings
}

func (c *testConn) getGoAways() []testGoAway {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]testGoAway(nil), c.goAways...)
}

func (c *testConn) getClosedAt() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closedAt
}

type testDialer struct {
	mu       sync.Mutex
	backends []*testBackend
	next     int
	conns    []*testConn
}

func (d *testDialer) setBackends(next int, backends ...*testBackend) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.next = next
	d.backends = backends
}

func (d *testDialer) dial(ctx context.Context, _ string) (net.Conn, error) {
	d.mu.Lock()
	backend := d.backends[d.next%len(d.backends)]
	d.next++
	d.mu.Unlock()

	clientConn, serverConn := net.Pipe()

	select {
	case backend.lis.connCh <- serverConn:
	case <-ctx.Done():
		clientConn.Close()
		serverConn.Close()
		return nil, ctx.Err()
	}

	ret := &testConn{
		Conn:      clientConn,
		backend:   backend,
		createdAt: time.Now(),
		written: testFrameReader{
			preface: len(http2.ClientPreface),
		},
	}

	d.mu.Lock()
	d.conns = append(d.conns, ret)
	d.mu.Unlock()

	return ret, nil
}

func (d *testDialer) getConns() []*testConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*testConn(nil), d.conns...)
}

func newTestClient(t *testing.T, d *testDialer) coctovigilv1.InternalServiceClient {
	opts := append(getDialOpts(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(d.dial),
	)

	conn, err := grpc.NewClient("passthrough:///octovigil", opts...)
	require.Nil(t, err)
	t.Cleanup(func() {
		conn.Close()
	})

	return coctovigilv1.NewInternalServiceClient(conn)
}

func doAuthorize(c coctovigilv1.InternalServiceClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), testRequestTimeout)
	defer cancel()

	_, err := c.Authorize(ctx, &coctovigilv1.AuthorizeRequest{})
	return err
}

func doAuthorizeEvery(c coctovigilv1.InternalServiceClient, offset, interval time.Duration, n int) []error {
	ret := make([]error, n)
	var wg sync.WaitGroup

	time.Sleep(offset)
	for i := range n {
		wg.Go(func() {
			ret[i] = doAuthorize(c)
		})
		time.Sleep(interval)
	}
	wg.Wait()

	return ret
}

func TestNewClient(t *testing.T) {

	c, err := NewClient(context.Background())
	if err != nil {
		assert.Nil(t, c)
		return
	}

	assert.NotNil(t, c.InternalC())
}

func TestKeepalive(t *testing.T) {

	idle := maxConnectionAge*9/10 - keepaliveTime/2

	t.Run("enforcement", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d := &testDialer{}
			d.setBackends(0, newTestBackend(t, 0, GetServerKeepaliveOpts()...))
			c := newTestClient(t, d)

			require.Nil(t, doAuthorize(c))
			time.Sleep(idle)
			require.Nil(t, doAuthorize(c))

			conns := d.getConns()
			require.Len(t, conns, 1)
			assert.Equal(t, int(idle/keepaliveTime), conns[0].getPings())
			assert.Empty(t, conns[0].getGoAways())
			assert.True(t, conns[0].getClosedAt().IsZero())
		})
	})

	t.Run("default", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d := &testDialer{}
			d.setBackends(0, newTestBackend(t, 0))
			c := newTestClient(t, d)

			require.Nil(t, doAuthorize(c))
			start := time.Now()
			time.Sleep(idle)
			require.Nil(t, doAuthorize(c))

			conns := d.getConns()
			require.Len(t, conns, 2)
			assert.Equal(t, []testGoAway{
				{
					code:  http2.ErrCodeEnhanceYourCalm,
					debug: "too_many_pings",
				},
			}, conns[0].getGoAways())
			assert.Less(t, conns[0].getClosedAt().Sub(start), idle)
		})
	})
}

func TestKeepaliveDeadConnection(t *testing.T) {

	detection := keepaliveTime + keepaliveTimeout

	t.Run("idle", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d := &testDialer{}
			d.setBackends(0, newTestBackend(t, 0, GetServerKeepaliveOpts()...))
			c := newTestClient(t, d)

			require.Nil(t, doAuthorize(c))
			start := time.Now()
			d.getConns()[0].setBlackholed()

			time.Sleep(2 * detection)
			assert.Equal(t, detection, d.getConns()[0].getClosedAt().Sub(start))

			require.Nil(t, doAuthorize(c))
			assert.Len(t, d.getConns(), 2)
		})
	})

	t.Run("busy", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d := &testDialer{}
			d.setBackends(0, newTestBackend(t, 0, GetServerKeepaliveOpts()...))
			c := newTestClient(t, d)

			require.Nil(t, doAuthorize(c))
			start := time.Now()
			d.getConns()[0].setBlackholed()

			offset := 500 * time.Millisecond
			errs := doAuthorizeEvery(c, offset, time.Second, 120)

			for i, err := range errs {
				at := offset + time.Duration(i)*time.Second
				if at+testRequestTimeout < detection {
					assert.Equal(t, codes.DeadlineExceeded, status.Code(err), at)
				} else {
					assert.Nil(t, err, at)
				}
			}

			conns := d.getConns()
			require.Len(t, conns, 2)
			assert.Equal(t, detection, conns[0].getClosedAt().Sub(start))
			assert.True(t, conns[1].getClosedAt().IsZero())
		})
	})
}

func TestMaxConnectionAge(t *testing.T) {

	synctest.Test(t, func(t *testing.T) {
		delay := 2 * time.Second
		backendA := newTestBackend(t, delay, GetServerKeepaliveOpts()...)
		backendB := newTestBackend(t, delay, GetServerKeepaliveOpts()...)

		d := &testDialer{}
		d.setBackends(0, backendA)
		c := newTestClient(t, d)

		require.Nil(t, doAuthorize(c))
		start := time.Now()
		d.setBackends(1, backendA, backendB)

		duration := 6 * maxConnectionAge
		errs := doAuthorizeEvery(c, 0, time.Second, int(duration/time.Second))
		for i, err := range errs {
			assert.Nil(t, err, i)
		}

		callsA, _ := backendA.svc.getCalls()
		callsB, firstCallB := backendB.svc.getCalls()
		assert.Equal(t, len(errs)+1, callsA+callsB)
		assert.Greater(t, callsB, len(errs)/4)
		assert.Greater(t, callsA, len(errs)/4)
		assert.LessOrEqual(t, firstCallB.Sub(start), maxConnectionAge*11/10+time.Second)

		conns := d.getConns()
		assert.GreaterOrEqual(t, len(conns), int(duration/(maxConnectionAge*11/10+delay)))
		assert.LessOrEqual(t, len(conns), int(duration/(maxConnectionAge*9/10))+1)

		for i, conn := range conns {
			if i%2 == 0 {
				assert.Equal(t, backendA, conn.backend, i)
			} else {
				assert.Equal(t, backendB, conn.backend, i)
			}

			assert.Empty(t, conn.getPings(), i)

			closedAt := conn.getClosedAt()
			if closedAt.IsZero() {
				assert.Equal(t, len(conns)-1, i)
				continue
			}

			goAways := conn.getGoAways()
			require.NotEmpty(t, goAways, i)
			for _, goAway := range goAways {
				assert.Equal(t, http2.ErrCodeNo, goAway.code, i)
			}

			lifetime := closedAt.Sub(conn.createdAt)
			assert.GreaterOrEqual(t, lifetime, maxConnectionAge*9/10, i)
			assert.LessOrEqual(t, lifetime, maxConnectionAge*11/10+delay, i)
		}
	})
}
