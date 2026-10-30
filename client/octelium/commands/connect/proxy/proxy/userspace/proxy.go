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
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy/userspace/tcp"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy/userspace/udp"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	listenerRetryMin = 250 * time.Millisecond
	listenerRetryMax = 5 * time.Second
)

type listener struct {
	name string

	address string
	port    uint32

	opts *Opts

	upstreamHost string

	isClosed bool
	mu       sync.Mutex
	lis      net.Listener
	udpLis   *udp.Listener
	conns    map[net.Conn]struct{}
}

type Proxy struct {
	listeners []*listener
	opts      *Opts
	cancelFn  context.CancelFunc
	mu        sync.Mutex
	isClosed  bool
	wg        sync.WaitGroup
}

type Opts struct {
	Name     string
	L4Type   userv1.HostedService_L4Type
	goNetCtl ccommon.GoNetCtl

	Listeners []OptsListener

	Upstream OptsUpstream
}

type OptsListener struct {
	Address string
	Port    uint32
}

type OptsUpstream struct {
	Address string
	Port    uint32
}

func newListener(address string, port uint32, opts *Opts) *listener {
	return &listener{
		name:         fmt.Sprintf("%s-%s-%s", opts.Name, opts.L4Type, address),
		opts:         opts,
		address:      address,
		port:         port,
		upstreamHost: net.JoinHostPort(opts.Upstream.Address, fmt.Sprintf("%d", opts.Upstream.Port)),
	}
}

func NewProxy(opts *Opts) *Proxy {
	ret := &Proxy{
		opts: opts,
	}

	for _, l := range opts.Listeners {
		ret.listeners = append(ret.listeners, newListener(l.Address, l.Port, opts))
	}

	return ret
}

func NewProxyFromServiceListener(listener *userv1.HostedService, addr *metav1.DualStackIP, goNetCtl ccommon.GoNetCtl, ipv4Supported, ipv6Supported bool) *Proxy {
	if listener.GetName() == "" || listener.GetUpstream() == nil || addr == nil {
		return nil
	}

	opts := &Opts{
		Name:   listener.GetName(),
		L4Type: listener.GetL4Type(),
		Upstream: OptsUpstream{
			Address: listener.GetUpstream().GetHost(),
			Port:    uint32(listener.GetUpstream().GetPort()),
		},
		goNetCtl: goNetCtl,
	}

	if ipv4Supported && addr.GetIpv4() != "" {
		opts.Listeners = append(opts.Listeners, OptsListener{
			Address: addr.GetIpv4(),
			Port:    listener.GetPort(),
		})
	}

	if ipv6Supported && addr.GetIpv6() != "" {
		opts.Listeners = append(opts.Listeners, OptsListener{
			Address: addr.GetIpv6(),
			Port:    listener.GetPort(),
		})
	}

	return NewProxy(opts)
}

func (p *Proxy) Start(ctx context.Context) error {
	if p == nil {
		return errors.Errorf("Cannot start a nil proxy")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.isClosed {
		return errors.Errorf("The proxy is already closed")
	}
	if p.cancelFn != nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.opts.Upstream.Port > 65535 {
		return errors.Errorf("Invalid upstream port: %d", p.opts.Upstream.Port)
	}
	for _, l := range p.listeners {
		if l.port > 65535 {
			return errors.Errorf("Invalid listener port: %d", l.port)
		}
		if l.address != "" {
			if _, err := netip.ParseAddr(l.address); err != nil {
				return errors.Wrapf(err, "Invalid listener address: %s", l.address)
			}
		}
	}
	ctx, cancelFn := context.WithCancel(ctx)
	p.cancelFn = cancelFn

	for _, l := range p.listeners {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			l.start(ctx)
		}()
	}

	return nil
}

func (p *Proxy) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	p.isClosed = true
	if p.cancelFn != nil {
		p.cancelFn()
	}
	p.mu.Unlock()

	for _, l := range p.listeners {
		l.close()
	}

	p.wg.Wait()

	return nil
}

func (l *listener) start(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { l.close() })
	defer stop()
	defer l.close()
	start := l.doStartTCP
	if l.opts.L4Type == userv1.HostedService_UDP {
		start = l.doStartUDP
	}
	delay := listenerRetryMin
	var lastWarning time.Time
	for {
		if ctx.Err() != nil || l.closed() {
			return nil
		}
		started := time.Now()
		err := start(ctx)
		if ctx.Err() != nil || l.closed() {
			return nil
		}
		if time.Since(started) >= listenerRetryMax {
			delay = listenerRetryMin
		}
		if lastWarning.IsZero() || time.Since(lastWarning) >= 30*time.Second {
			zap.L().Warn("Service listener failed. Retrying",
				zap.String("listener", l.name), zap.Error(err))
			lastWarning = time.Now()
		}
		timer := time.NewTimer(delay/2 + time.Duration(rand.Int64N(int64(delay/2)+1)))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		delay = min(2*delay, listenerRetryMax)
	}
}

func (l *listener) closed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.isClosed
}

func (l *listener) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isClosed {
		return nil
	}

	l.isClosed = true
	if l.lis != nil {
		l.lis.Close()
	}
	if l.udpLis != nil {
		l.udpLis.Close()
	}

	for conn := range l.conns {
		conn.Close()
	}
	l.conns = nil

	return nil
}

func (l *listener) addConn(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isClosed {
		return false
	}
	if l.conns == nil {
		l.conns = make(map[net.Conn]struct{})
	}
	l.conns[conn] = struct{}{}

	return true
}

func (l *listener) removeConn(conn net.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.conns, conn)
}

func (l *listener) setLis(lis net.Listener) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isClosed {
		return false
	}
	l.lis = lis

	return true
}

func (l *listener) setUDPLis(lis *udp.Listener) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isClosed {
		return false
	}
	l.udpLis = lis

	return true
}

func (l *listener) doStartTCP(ctx context.Context) error {

	pp, err := tcp.NewProxy(l.upstreamHost)
	if err != nil {
		return err
	}

	listenerAddr := net.JoinHostPort(l.address, fmt.Sprintf("%d", l.port))

	lis, err := func() (net.Listener, error) {
		if l.opts.goNetCtl != nil {
			if goNet := l.opts.goNetCtl.GetGoNet(); goNet != nil {
				addr, err := net.ResolveTCPAddr("tcp", listenerAddr)
				if err != nil {
					return nil, err
				}
				return goNet.ListenTCP(addr)
			}
		}
		return net.Listen("tcp", listenerAddr)
	}()
	if err != nil {
		return err
	}
	defer func() {
		lis.Close()
		l.mu.Lock()
		if l.lis == lis {
			l.lis = nil
		}
		l.mu.Unlock()
	}()

	if ctx.Err() != nil || !l.setLis(lis) {
		zap.S().Debugf("TCP listener %s was closed before it started", listenerAddr)
		return nil
	}

	zap.S().Debugf("TCP listener %s successfully started", listenerAddr)

	for {
		select {
		case <-ctx.Done():
			zap.S().Debugf("shutting down proxy for %s", listenerAddr)
			return nil
		default:
			conn, err := lis.Accept()
			if err != nil {
				return err
			}

			if !l.addConn(conn) {
				conn.Close()
				return nil
			}

			go func(conn net.Conn) {
				defer l.removeConn(conn)

				zap.S().Debugf("Starting serving connection on %s", listenerAddr)
				tcpAddr, err := net.ResolveTCPAddr("tcp", l.upstreamHost)
				if err != nil {
					zap.S().Debugf("Could not resolve the upstream %s: %+v", l.upstreamHost, err)
					conn.Close()
					return
				}

				connBackend, err := net.DialTCP("tcp", nil, tcpAddr)
				if err != nil {
					zap.S().Debugf("Could not dial the upstream %s: %+v", l.upstreamHost, err)
					conn.Close()
					return
				}

				pp.ServeTCP(conn.(tcp.WriteCloser), connBackend)

				zap.S().Debugf("Done serving connection on %s", listenerAddr)
			}(conn)
		}

	}
}

func (l *listener) doStartUDP(ctx context.Context) error {

	proxy, err := udp.NewProxy(l.upstreamHost)
	if err != nil {
		return err
	}

	listenerAddr := net.JoinHostPort(l.address, fmt.Sprintf("%d", l.port))

	addrL, err := net.ResolveUDPAddr("udp", listenerAddr)
	if err != nil {
		return err
	}

	udpLis, err := udp.Listen("udp", addrL)
	if err != nil {
		return err
	}
	defer func() {
		udpLis.Close()
		l.mu.Lock()
		if l.udpLis == udpLis {
			l.udpLis = nil
		}
		l.mu.Unlock()
	}()

	if ctx.Err() != nil || !l.setUDPLis(udpLis) {
		zap.S().Debugf("UDP listener %s was closed before it started", listenerAddr)
		return nil
	}

	zap.S().Debugf("UDP listener %s successfully started", listenerAddr)

	for {
		select {
		case <-ctx.Done():
			zap.S().Debugf("shutting down proxy for %s", listenerAddr)
			return nil
		default:
			conn, err := udpLis.Accept()
			if err != nil {
				return err
			}

			go func() {
				proxy.ServeUDP(conn)
				zap.S().Debugf("Done serving connection for %s", listenerAddr)
			}()
		}
	}
}
