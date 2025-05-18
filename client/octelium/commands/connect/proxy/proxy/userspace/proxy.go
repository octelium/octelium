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
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy/userspace/tcp"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy/userspace/udp"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
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
}

type Proxy struct {
	listeners []*listener
	opts      *Opts
	cancelFn  context.CancelFunc
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

	opts := &Opts{
		Name:   listener.Name,
		L4Type: listener.L4Type,
		Upstream: OptsUpstream{
			Address: listener.Upstream.Host,
			Port:    uint32(listener.Upstream.Port),
		},
		goNetCtl: goNetCtl,
	}

	if ipv4Supported && addr.Ipv4 != "" {
		opts.Listeners = append(opts.Listeners, OptsListener{
			Address: addr.Ipv4,
			Port:    listener.Port,
		})
	}

	if ipv6Supported && addr.Ipv6 != "" {
		opts.Listeners = append(opts.Listeners, OptsListener{
			Address: addr.Ipv6,
			Port:    listener.Port,
		})
	}

	return NewProxy(opts)
}

func (p *Proxy) Start(ctx context.Context) error {
	ctx, cancelFn := context.WithCancel(ctx)
	p.cancelFn = cancelFn

	for _, l := range p.listeners {
		if err := l.start(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (p *Proxy) Close() error {

	for _, l := range p.listeners {
		l.close()
	}

	p.cancelFn()

	return nil
}

func (l *listener) start(ctx context.Context) error {
	switch l.opts.L4Type {
	case userv1.HostedService_UDP:
		return l.startUDP(ctx)
	default:
		return l.startTCP(ctx)
	}
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

	return nil
}

func (l *listener) startUDP(ctx context.Context) error {
	go l.doStartUDP(ctx)
	return nil
}

func (l *listener) startTCP(ctx context.Context) error {
	go l.doStartTCP(ctx)
	return nil
}

func (l *listener) doStartTCP(ctx context.Context) error {

	pp, err := tcp.NewProxy(l.upstreamHost)
	if err != nil {
		zap.S().Errorf("Could not initialize new TCP proxy: %+v", err)
		return err
	}

	listenerAddr := net.JoinHostPort(l.address, fmt.Sprintf("%d", l.port))

	l.lis, err = func() (net.Listener, error) {
		var err error
		var listener net.Listener
		for i := 0; i < 100; i++ {

			gonet := l.opts.goNetCtl.GetGoNet()

			if gonet != nil {

				zap.L().Debug("Proxy listening in gvisor mode")
				tcpAddr, err := net.ResolveTCPAddr("tcp", listenerAddr)
				if err != nil {
					return nil, err
				}

				listener, err = gonet.ListenTCP(tcpAddr)
				if err == nil {
					return listener, nil
				}

			} else {
				zap.L().Debug("Proxy listening in host mode")
				listener, err = net.Listen("tcp", listenerAddr)
				if err == nil {
					return listener, nil
				}
			}

			zap.S().Warnf("Could not listen on TCP port on %s: %+v. Trying again (attempt %d).", listenerAddr, err, i)
			time.Sleep(250 * time.Millisecond)
		}
		return nil, errors.Errorf("Could not listen on TCP port on %s:.", listenerAddr)
	}()
	if err != nil {
		zap.S().Errorf("Could not listen on TCP port on %s: %+v", listenerAddr, err)
		return err
	}

	zap.S().Debugf("TCP listener %s successfully started", listenerAddr)

	defer l.close()

	for {
		select {
		case <-ctx.Done():
			zap.S().Debugf("shutting down proxy for %s", listenerAddr)
			return nil
		default:
			conn, err := l.lis.Accept()
			if err != nil {
				zap.S().Debugf("Could not accept conn: %+v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			go func(conn net.Conn) {
				zap.S().Debugf("Starting serving connection on %s", listenerAddr)
				tcpAddr, err := net.ResolveTCPAddr("tcp", l.upstreamHost)
				if err != nil {
					return
				}

				connBackend, err := net.DialTCP("tcp", nil, tcpAddr)
				if err != nil {
					return
				}

				kgonet := l.opts.goNetCtl.GetGoNet()

				if kgonet != nil {
					pp.ServeTCP(conn.(*gonet.TCPConn), connBackend)
				} else {
					pp.ServeTCP(conn.(*net.TCPConn), connBackend)
				}

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

	l.udpLis, err = udp.Listen("udp", addrL)
	if err != nil {
		zap.S().Errorf("Could not listen on UDP addr %s", listenerAddr)
		return err
	}

	defer l.close()

	for {
		select {
		case <-ctx.Done():
			zap.S().Debugf("shutting down proxy for %s", listenerAddr)
			return nil
		default:
			conn, err := l.udpLis.Accept()
			if err != nil {
				zap.S().Debugf("Could not accept conn: %+v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}

			go func() {
				proxy.ServeUDP(conn)
				zap.S().Debugf("Done serving connection for %s", listenerAddr)
			}()
		}
	}
}
