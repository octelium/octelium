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
	"net"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy/userspace/tcp"
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
			zap.L().Warn("UDP-based published Services are currently unsupported. Skipping...")
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

	s.cancelFn()

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

	lis net.Listener

	mu       sync.Mutex
	isClosed bool
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

	return nil
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

func (l *listener) doStartTCP(ctx context.Context) error {

	pp, err := tcp.NewProxy(l.svcFQDN)
	if err != nil {
		zap.L().Error("Could not initialize new TCP proxy", zap.Error(err))
		return err
	}

	listenerAddr := net.JoinHostPort(l.hostAddress, fmt.Sprintf("%d", l.hostPort))

	l.lis, err = func() (net.Listener, error) {

		var err error
		var listener net.Listener
		for i := range 100 {
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

	zap.L().Debug("TCP listener successfully started", zap.String("addr", listenerAddr))

	defer l.close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := l.lis.Accept()
			if err != nil {
				zap.L().Debug("Could not accept conn", zap.String("addr", listenerAddr), zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			go func(conn net.Conn) {
				zap.L().Debug("Starting serving connection", zap.String("addr", listenerAddr))
				connBackend, err := l.getConnBackendTCP()
				if err != nil {
					zap.L().Error("Could not get conn backend", zap.Error(err))
					return
				}
				pp.ServeTCP(conn.(*net.TCPConn), connBackend)
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

func (l *listener) resolveService() (net.IP, error) {
	c := dns.Client{}
	m := dns.Msg{}
	if l.ctl.ipv6Supported {
		m.SetQuestion(l.svcFQDN+".", dns.TypeAAAA)
	} else {
		m.SetQuestion(l.svcFQDN+".", dns.TypeA)
	}

	r, _, err := c.Exchange(&m, net.JoinHostPort(l.ctl.getCurrentDNS().String(), "53"))
	if err != nil {
		return nil, err
	}

	if len(r.Answer) == 0 {
		return nil, errors.Errorf("Could not resolve Service: %s", l.svcFQDN)
	}

	if l.ctl.ipv6Supported {
		record := r.Answer[0].(*dns.AAAA)
		return record.AAAA, nil
	} else {
		record := r.Answer[0].(*dns.A)
		return record.A, nil
	}
}
