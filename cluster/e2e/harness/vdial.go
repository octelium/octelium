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

package harness

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	ingressPort = 443

	apiConnBufferSize = 8 * 1024
	apiConnWindowSize = 64 * 1024
)

type gate struct {
	mu     sync.Mutex
	closed bool
	ch     chan struct{}
}

func newGate() *gate {
	ret := &gate{ch: make(chan struct{})}
	close(ret.ch)
	return ret
}

func (g *gate) close() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return
	}
	g.closed = true
	g.ch = make(chan struct{})
}

func (g *gate) open() {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.closed {
		return
	}
	g.closed = false
	close(g.ch)
}

func (g *gate) isClosed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed
}

func (g *gate) wait(ctx context.Context) error {
	g.mu.Lock()
	ch := g.ch
	g.mu.Unlock()

	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type gatedConn struct {
	net.Conn
	g   *gate
	ctx context.Context
}

func (c *gatedConn) Read(b []byte) (int, error) {
	if err := c.g.wait(c.ctx); err != nil {
		return 0, net.ErrClosed
	}
	return c.Conn.Read(b)
}

func (c *gatedConn) Write(b []byte) (int, error) {
	if err := c.g.wait(c.ctx); err != nil {
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

type IngressDialer struct {
	Addr       string
	ServerName string
	TLSConfig  *tls.Config
	Timeout    time.Duration
}

func (d *IngressDialer) dialContext(g *gate, closeCtx context.Context) func(ctx context.Context, _ string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		timeout := d.Timeout
		if timeout == 0 {
			timeout = 15 * time.Second
		}

		conn, err := (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).
			DialContext(ctx, "tcp", d.Addr)
		if err != nil {
			return nil, err
		}

		if g == nil {
			return conn, nil
		}

		return &gatedConn{Conn: conn, g: g, ctx: closeCtx}, nil
	}
}

func (d *IngressDialer) tlsConfig() *tls.Config {
	ret := &tls.Config{MinVersion: tls.VersionTLS12}
	if d.TLSConfig != nil {
		ret = d.TLSConfig.Clone()
	}
	ret.ServerName = d.ServerName
	return ret
}

func (d *IngressDialer) grpcConn(g *gate, closeCtx context.Context,
	extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(d.tlsConfig())),
		grpc.WithAuthority(d.ServerName),
		grpc.WithContextDialer(d.dialContext(g, closeCtx)),
		grpc.WithReadBufferSize(apiConnBufferSize),
		grpc.WithWriteBufferSize(apiConnBufferSize),
		grpc.WithInitialWindowSize(apiConnWindowSize),
		grpc.WithInitialConnWindowSize(apiConnWindowSize),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
		grpc.WithUserAgent("octelium-e2e-chaos"),
		grpc.WithDisableRetry(),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  time.Second,
				Multiplier: 1.6,
				Jitter:     0.2,
				MaxDelay:   5 * time.Second,
			},
			MinConnectTimeout: 15 * time.Second,
		}),
	}

	return grpc.NewClient(fmt.Sprintf("passthrough:///%s", d.Addr), append(opts, extra...)...)
}

func (d *IngressDialer) GRPCConn(extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	return d.grpcConn(nil, context.Background(), extra...)
}

type VConn struct {
	pool *VConnPool
	cc   *grpc.ClientConn
	g    *gate

	closeCtx context.Context
	cancel   context.CancelFunc

	refs int
}

func (c *VConn) CC() *grpc.ClientConn { return c.cc }

func (c *VConn) Freeze() { c.g.close() }

func (c *VConn) Thaw() { c.g.open() }

func (c *VConn) IsFrozen() bool { return c.g.isClosed() }

func (c *VConn) Release() {
	c.pool.release(c)
}

func (c *VConn) close() {
	c.cancel()
	c.cc.Close()
}

type VConnPool struct {
	dialer  *IngressDialer
	perConn int

	mu    sync.Mutex
	conns []*VConn
	total int
}

func NewVConnPool(dialer *IngressDialer, streamsPerConn int) *VConnPool {
	return &VConnPool{
		dialer:  dialer,
		perConn: max(1, streamsPerConn),
	}
}

func (p *VConnPool) StreamsPerConn() int { return p.perConn }

func (p *VConnPool) Acquire() (*VConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.perConn > 1 {
		var best *VConn
		for _, c := range p.conns {
			if c.refs < p.perConn && !c.g.isClosed() && (best == nil || c.refs < best.refs) {
				best = c
			}
		}
		if best != nil {
			best.refs++
			return best, nil
		}
	}

	closeCtx, cancel := context.WithCancel(context.Background())
	g := newGate()

	cc, err := p.dialer.grpcConn(g, closeCtx)
	if err != nil {
		cancel()
		return nil, err
	}

	ret := &VConn{
		pool:     p,
		cc:       cc,
		g:        g,
		closeCtx: closeCtx,
		cancel:   cancel,
		refs:     1,
	}

	p.conns = append(p.conns, ret)
	p.total++

	return ret, nil
}

func (p *VConnPool) release(c *VConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	c.refs--
	if c.refs > 0 {
		return
	}

	if p.perConn > 1 && !c.g.isClosed() {
		return
	}

	for i, cur := range p.conns {
		if cur == c {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			break
		}
	}

	go c.close()
}

func (p *VConnPool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

func (p *VConnPool) Dialed() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.total
}

func (p *VConnPool) Close() {
	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()

	for _, c := range conns {
		c.g.open()
		c.close()
	}
}

func (h *H) IngressAddr() string {
	h.ingressOnce.Do(func() {
		h.ingressAddr = resolveIngressAddr(h.ExternalIP)
		zap.L().Info("Resolved the address the load generators dial for the Cluster ingress",
			zap.String("addr", h.ingressAddr))
	})

	return h.ingressAddr
}

func resolveIngressAddr(externalIP string) string {
	candidates := []string{}
	if externalIP != "" {
		candidates = append(candidates, net.JoinHostPort(externalIP, fmt.Sprintf("%d", ingressPort)))
	}
	candidates = append(candidates, net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", ingressPort)))

	for _, addr := range candidates {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			continue
		}
		conn.Close()
		return addr
	}

	return candidates[len(candidates)-1]
}

func (h *H) TLSRoots() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if h.State.CertPath != "" {
		pem, err := os.ReadFile(h.State.CertPath)
		if err != nil {
			return nil, errors.Errorf("Could not read the Cluster certificate %s: %+v",
				h.State.CertPath, err)
		}
		pool.AppendCertsFromPEM(pem)
	}

	return pool, nil
}

func (h *H) APIServerName() string {
	return fmt.Sprintf("octelium-api.%s", h.Domain)
}

func (h *H) IngressDialer(serverName string) (*IngressDialer, error) {
	roots, err := h.TLSRoots()
	if err != nil {
		return nil, err
	}

	return &IngressDialer{
		Addr:       h.IngressAddr(),
		ServerName: serverName,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
	}, nil
}
