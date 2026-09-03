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
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy/userspace/tcp"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy/userspace/udp"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gvisor.dev/gvisor/pkg/sync"
)

type serviceProxy struct {
	listeners []*listener
	ctl       *Controller
	cancelFn  context.CancelFunc
	mu        sync.Mutex
	isClosed  bool
}

func newServiceProxy(ctl *Controller) (*serviceProxy, error) {

	ret := &serviceProxy{
		ctl: ctl,
	}

	for _, svc := range ctl.c.Preferences.PublishedServices {
		ret.listeners = append(ret.listeners, newListener(svc, ctl))
	}

	return ret, nil
}

func (s *serviceProxy) Start(ctx context.Context) error {
	ctx, cancelFn := context.WithCancel(ctx)
	s.cancelFn = cancelFn

	if len(s.listeners) == 0 {
		return nil
	}

	for _, l := range s.listeners {
		switch l.typ {
		case cliconfigv1.Connection_Preferences_PublishedService_TCP:
			l.startTCP(ctx)
		case cliconfigv1.Connection_Preferences_PublishedService_UDP:
			l.startUDP(ctx)
		}
	}

	return nil
}

func (s *serviceProxy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}
	s.isClosed = true

	zap.L().Debug("Closing Service proxy controller")

	for _, lis := range s.listeners {
		lis.close()
	}

	if s.cancelFn != nil {
		s.cancelFn()
	}

	zap.L().Debug("Service proxy controller successfully close")

	return nil
}

type listener struct {
	port        int
	hostPort    int
	hostAddress string
	svcFQDN     string

	ctl   *Controller
	gonet *Net
	typ   cliconfigv1.Connection_Preferences_PublishedService_L4Type

	lis    net.Listener
	udpLis *udp.Listener

	mu       sync.Mutex
	isClosed bool
	conns    map[io.Closer]struct{}
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

func (l *listener) addConn(conn io.Closer) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isClosed {
		return false
	}
	if l.conns == nil {
		l.conns = make(map[io.Closer]struct{})
	}
	l.conns[conn] = struct{}{}

	return true
}

func (l *listener) removeConn(conn io.Closer) {
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

func newListener(svc *cliconfigv1.Connection_Preferences_PublishedService, ctl *Controller) *listener {
	return &listener{
		ctl:      ctl,
		gonet:    ctl.GetNetstackNet(),
		svcFQDN:  svc.Fqdn,
		port:     int(svc.Port),
		hostPort: int(svc.HostPort),
		typ:      svc.L4Type,
		hostAddress: func() string {
			if govalidator.IsIP(svc.HostAddress) {
				return svc.HostAddress
			}

			return "localhost"
		}(),
	}
}

func (l *listener) startTCP(ctx context.Context) error {
	go l.doStartTCP(ctx)
	return nil
}

func (l *listener) startUDP(ctx context.Context) error {
	go l.doStartUDP(ctx)
	return nil
}

func (l *listener) doStartTCP(ctx context.Context) error {

	pp, err := tcp.NewProxy(l.svcFQDN)
	if err != nil {
		zap.L().Error("Could not initialize new TCP proxy", zap.Error(err))
		return err
	}

	listenerAddr := net.JoinHostPort(l.hostAddress, fmt.Sprintf("%d", l.hostPort))

	lis, err := func() (net.Listener, error) {

		var err error
		var listener net.Listener
		for i := range 100 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			listener, err = net.Listen("tcp", listenerAddr)
			if err == nil {
				return listener, nil
			}

			zap.L().Warn("Could not listen on TCP port",
				zap.String("addr", listenerAddr), zap.Error(err), zap.Int("attempt", i))
			time.Sleep(250 * time.Millisecond)
		}
		return nil, errors.Errorf("Could not listen on TCP port on %s:.", listenerAddr)
	}()
	if err != nil {
		zap.L().Error("Could not listen on TCP", zap.String("addr", listenerAddr), zap.Error(err))
		return err
	}

	if !l.setLis(lis) {
		zap.L().Debug("TCP listener was closed before it started", zap.String("addr", listenerAddr))
		return lis.Close()
	}

	zap.L().Debug("TCP listener successfully started", zap.String("addr", listenerAddr))

	defer l.close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := lis.Accept()
			if err != nil {
				zap.L().Debug("Could not accept conn", zap.String("addr", listenerAddr), zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if !l.addConn(conn) {
				conn.Close()
				return nil
			}

			go func(conn net.Conn) {
				defer l.removeConn(conn)

				zap.L().Debug("Starting serving connection", zap.String("addr", listenerAddr))
				connBackend, err := l.getConnBackendTCP()
				if err != nil {
					zap.L().Error("Could not get conn backend", zap.Error(err))
					conn.Close()
					return
				}
				pp.ServeTCP(conn.(*net.TCPConn), connBackend)
				zap.L().Debug("Done serving connection", zap.String("addr", listenerAddr))
			}(conn)
		}
	}
}

func (l *listener) doStartUDP(ctx context.Context) error {

	pp, err := udp.NewProxy(l.svcFQDN)
	if err != nil {
		zap.L().Error("Could not initialize new UDP proxy", zap.Error(err))
		return err
	}

	listenerAddr := net.JoinHostPort(l.hostAddress, fmt.Sprintf("%d", l.hostPort))

	udpAddr, err := net.ResolveUDPAddr("udp", listenerAddr)
	if err != nil {
		zap.L().Error("Could not resolve the UDP listener addr",
			zap.String("addr", listenerAddr), zap.Error(err))
		return err
	}

	lis, err := func() (*udp.Listener, error) {

		var err error
		var listener *udp.Listener
		for i := range 100 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}

			listener, err = udp.Listen("udp", udpAddr)
			if err == nil {
				return listener, nil
			}

			zap.L().Warn("Could not listen on UDP port",
				zap.String("addr", listenerAddr), zap.Error(err), zap.Int("attempt", i))
			time.Sleep(250 * time.Millisecond)
		}
		return nil, errors.Errorf("Could not listen on UDP port on %s:.", listenerAddr)
	}()
	if err != nil {
		zap.L().Error("Could not listen on UDP", zap.String("addr", listenerAddr), zap.Error(err))
		return err
	}

	if !l.setUDPLis(lis) {
		zap.L().Debug("UDP listener was closed before it started", zap.String("addr", listenerAddr))
		return lis.Close()
	}

	zap.L().Debug("UDP listener successfully started", zap.String("addr", listenerAddr))

	defer l.close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := lis.Accept()
			if err != nil {
				zap.L().Debug("Could not accept conn", zap.String("addr", listenerAddr), zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if !l.addConn(conn) {
				conn.Close()
				return nil
			}

			go func(conn *udp.Conn) {
				defer l.removeConn(conn)

				zap.L().Debug("Starting serving connection", zap.String("addr", listenerAddr))
				connBackend, err := l.getConnBackendUDP()
				if err != nil {
					zap.L().Error("Could not get conn backend", zap.Error(err))
					conn.Close()
					return
				}
				pp.ServeUDPConn(conn, connBackend)
				zap.L().Debug("Done serving connection", zap.String("addr", listenerAddr))
			}(conn)
		}
	}
}

func (l *listener) getConnBackendTCP() (tcp.WriteCloser, error) {
	var connBackend tcp.WriteCloser

	if l.gonet != nil {
		addrs, err := l.gonet.LookupHost(l.svcFQDN)
		if err != nil {
			return nil, errors.Errorf("Could not lookupHost via gVisor: %s", err)
		}
		if len(addrs) == 0 {
			return nil, errors.Errorf("Could not resolve Service: %s", l.svcFQDN)
		}

		tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(addrs[0], fmt.Sprintf("%d", l.port)))
		if err != nil {
			return nil, err
		}
		connBackend, err = l.gonet.DialTCP(tcpAddr)
		if err != nil {
			return nil, errors.Errorf("Could not dialTCP via gVisor: %s", err)
		}

	} else {

		resolvedServiceIP, err := l.resolveService()
		if err != nil {
			return nil, err
		}

		tcpAddr, err := net.ResolveTCPAddr("tcp",
			net.JoinHostPort(resolvedServiceIP.String(), fmt.Sprintf("%d", l.port)))
		if err != nil {
			return nil, err
		}

		connBackend, err = net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			return nil, err
		}
	}
	return connBackend, nil
}

func (l *listener) getConnBackendUDP() (net.Conn, error) {
	var connBackend net.Conn

	if l.gonet != nil {
		addrs, err := l.gonet.LookupHost(l.svcFQDN)
		if err != nil {
			return nil, errors.Errorf("Could not lookupHost via gVisor: %s", err)
		}
		if len(addrs) == 0 {
			return nil, errors.Errorf("Could not resolve Service: %s", l.svcFQDN)
		}

		udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addrs[0], fmt.Sprintf("%d", l.port)))
		if err != nil {
			return nil, err
		}
		connBackend, err = l.gonet.DialUDP(nil, udpAddr)
		if err != nil {
			return nil, errors.Errorf("Could not dialUDP via gVisor: %s", err)
		}

	} else {

		resolvedServiceIP, err := l.resolveService()
		if err != nil {
			return nil, err
		}

		udpAddr, err := net.ResolveUDPAddr("udp",
			net.JoinHostPort(resolvedServiceIP.String(), fmt.Sprintf("%d", l.port)))
		if err != nil {
			return nil, err
		}

		connBackend, err = net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return nil, err
		}
	}
	return connBackend, nil
}

func (l *listener) resolveService() (net.IP, error) {
	if ip := net.ParseIP(l.svcFQDN); ip != nil {
		return ip, nil
	}

	dnsServer := l.ctl.getCurrentDNS()
	if dnsServer == nil {
		return nil, errors.Errorf("No DNS servers available to resolve the Service: %s", l.svcFQDN)
	}

	var qTypes []uint16
	if l.ctl.ipv6Supported {
		qTypes = append(qTypes, dns.TypeAAAA)
	}
	if l.ctl.ipv4Supported {
		qTypes = append(qTypes, dns.TypeA)
	}
	if len(qTypes) == 0 {
		return nil, errors.Errorf("No supported address family to resolve the Service: %s", l.svcFQDN)
	}

	srvAddr := net.JoinHostPort(dnsServer.String(), "53")

	var retErr error
	for _, qType := range qTypes {
		ip, err := l.doResolveService(srvAddr, qType)
		if err != nil {
			zap.L().Debug("Could not resolve the Service",
				zap.String("svc", l.svcFQDN), zap.Uint16("qType", qType), zap.Error(err))
			retErr = err
			continue
		}

		return ip, nil
	}

	return nil, retErr
}

func (l *listener) doResolveService(srvAddr string, qType uint16) (net.IP, error) {
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(l.svcFQDN+".", qType)

	r, _, err := c.Exchange(&m, srvAddr)
	if err != nil {
		return nil, err
	}

	for _, answer := range r.Answer {
		switch record := answer.(type) {
		case *dns.AAAA:
			if record.AAAA != nil {
				return record.AAAA, nil
			}
		case *dns.A:
			if record.A != nil {
				return record.A, nil
			}
		}
	}

	return nil, errors.Errorf("Could not resolve Service: %s", l.svcFQDN)
}
