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

package esocks5

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"

	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	handshakeTimeout = 10 * time.Second
	dialTimeout      = 20 * time.Second
)

type Opts struct {
	GoNetCtl    ccommon.GoNetCtl
	ListenAddrs []string
}

type Server struct {
	opts *Opts

	socksSrv *gosocks5.Server

	cancelFn context.CancelFunc

	listeners []net.Listener

	mu       sync.Mutex
	isClosed bool
}

func NewServer(opts *Opts) (*Server, error) {
	if opts == nil {
		return nil, errors.Errorf("nil embedded SOCKS5 opts")
	}

	if opts.GoNetCtl == nil {
		return nil, errors.Errorf("nil embedded SOCKS5 GoNetCtl")
	}

	if len(opts.ListenAddrs) == 0 {
		return nil, errors.Errorf("embedded SOCKS5 listen addrs are empty")
	}

	ret := &Server{
		opts: opts,
	}

	ret.socksSrv = gosocks5.NewServer(
		gosocks5.WithAuthMethods([]gosocks5.Authenticator{
			gosocks5.NoAuthAuthenticator{},
		}),
		gosocks5.WithResolver(noResolveResolver{}),
		gosocks5.WithRule(&gosocks5.PermitCommand{
			EnableConnect:   true,
			EnableBind:      false,
			EnableAssociate: false,
		}),
		gosocks5.WithLogger(zapLogger{}),
		gosocks5.WithConnectHandle(ret.handleConnect),
		gosocks5.WithBindHandle(rejectUnsupportedCommand),
		gosocks5.WithAssociateHandle(rejectUnsupportedCommand),
	)

	return ret, nil
}

func (s *Server) Start(ctx context.Context) error {
	ctx, cancelFn := context.WithCancel(ctx)
	s.cancelFn = cancelFn

	for _, listenerAddr := range s.opts.ListenAddrs {
		zap.L().Debug("Starting embedded SOCKS5 listener",
			zap.String("addr", listenerAddr))

		lis, err := s.getListener(listenerAddr)
		if err != nil {
			s.Close()
			return err
		}

		s.listeners = append(s.listeners, lis)

		go func(ctx context.Context, lis net.Listener) {
			if err := s.doRun(ctx, lis); err != nil {
				zap.L().Debug("embedded SOCKS5 listener exited", zap.Error(err))
			}
		}(ctx, lis)
	}

	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isClosed {
		return nil
	}

	s.isClosed = true

	zap.L().Debug("Closing embedded SOCKS5 server")

	if s.cancelFn != nil {
		s.cancelFn()
	}

	for _, lis := range s.listeners {
		lis.Close()
	}

	zap.L().Debug("Embedded SOCKS5 server is now closed")
	return nil
}

func (s *Server) doRun(ctx context.Context, lis net.Listener) error {
	for {
		conn, err := lis.Accept()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				zap.L().Debug("embedded SOCKS5 accept timeout", zap.Error(opErr))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			select {
			case <-ctx.Done():
				zap.L().Debug("embedded SOCKS5 listener shutting down")
				return nil
			default:
				zap.L().Debug("Could not accept embedded SOCKS5 conn", zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	zap.L().Debug("Starting embedded SOCKS5 connection",
		zap.String("remoteAddr", conn.RemoteAddr().String()))

	ctx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()
	defer conn.Close()

	doneCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-doneCh:
		}
	}()
	defer close(doneCh)

	if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		zap.L().Debug("Could not set embedded SOCKS5 handshake deadline", zap.Error(err))
	}

	if err := s.socksSrv.ServeConn(conn); err != nil {
		zap.L().Debug("embedded SOCKS5 connection ended", zap.Error(err))
	}
}

func (s *Server) handleConnect(ctx context.Context, writer io.Writer, req *gosocks5.Request) error {
	clientConn, ok := writer.(net.Conn)
	if !ok {
		gosocks5.SendReply(writer, statute.RepServerFailure, nil)
		return errors.Errorf("embedded SOCKS5 writer is not net.Conn: %T", writer)
	}

	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		zap.L().Debug("Could not clear embedded SOCKS5 conn deadline", zap.Error(err))
	}

	target, err := newTarget(req)
	if err != nil {
		gosocks5.SendReply(writer, statute.RepAddrTypeNotSupported, nil)
		return err
	}

	upstreamConn, err := s.dialTarget(ctx, target.addr)
	if err != nil {
		zap.L().Debug("Could not dial embedded SOCKS5 target",
			zap.String("target", target.addr),
			zap.Error(err))
		gosocks5.SendReply(writer, statute.RepServerFailure, nil)
		return err
	}

	defer upstreamConn.Close()

	if err := gosocks5.SendReply(writer, statute.RepSuccess, upstreamConn.LocalAddr()); err != nil {
		return err
	}

	proxyConn(ctx, clientConn, req.Reader, writer, upstreamConn)

	return nil
}

func (s *Server) dialTarget(ctx context.Context, addr string) (net.Conn, error) {
	ctx, cancelFn := context.WithTimeout(ctx, dialTimeout)
	defer cancelFn()

	zap.L().Debug("Dialing embedded SOCKS5 target via host network",
		zap.String("addr", addr))

	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", addr)
}

func (s *Server) getListener(listenerAddr string) (net.Listener, error) {
	var err error
	var listener net.Listener

	for i := 0; i < 100; i++ {
		gonet := s.opts.GoNetCtl.GetGoNet()
		if gonet != nil {
			zap.L().Debug("embedded SOCKS5 listening in gVisor netstack mode",
				zap.String("addr", listenerAddr))

			tcpAddr, err := net.ResolveTCPAddr("tcp", listenerAddr)
			if err != nil {
				return nil, err
			}

			listener, err = gonet.ListenTCP(tcpAddr)
			if err == nil {
				return listener, nil
			}
		} else {
			zap.L().Debug("embedded SOCKS5 listening in host mode",
				zap.String("addr", listenerAddr))

			listener, err = net.Listen("tcp", listenerAddr)
			if err == nil {
				return listener, nil
			}
		}

		zap.L().Warn("Could not listen on embedded SOCKS5 TCP port",
			zap.String("addr", listenerAddr),
			zap.Error(err),
			zap.Int("attempt", i))
		time.Sleep(250 * time.Millisecond)
	}

	return nil, errors.Errorf("could not listen on embedded SOCKS5 TCP address: %s", listenerAddr)
}

func proxyConn(
	ctx context.Context,
	clientConn net.Conn,
	clientReader io.Reader,
	clientWriter io.Writer,
	upstreamConn net.Conn,
) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		copyAndCloseWrite(upstreamConn, clientReader)
	}()

	go func() {
		defer wg.Done()
		copyAndCloseWrite(clientWriter, upstreamConn)
	}()

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-ctx.Done():
		clientConn.Close()
		upstreamConn.Close()
	case <-doneCh:
	}
}

func copyAndCloseWrite(dst io.Writer, src io.Reader) {
	if _, err := io.Copy(dst, src); err != nil && !isExpectedNetErr(err) {
		zap.L().Debug("embedded SOCKS5 copy error", zap.Error(err))
	}

	if err := closeWrite(dst); err != nil {
		zap.L().Debug("embedded SOCKS5 closeWrite failed", zap.Error(err))
	}

	if c, ok := dst.(interface{ SetReadDeadline(time.Time) error }); ok {
		if err := c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			zap.L().Debug("embedded SOCKS5 set read deadline failed", zap.Error(err))
		}
	}
}

type target struct {
	host string
	port int
	addr string
}

func newTarget(req *gosocks5.Request) (*target, error) {
	if req == nil || req.RawDestAddr == nil {
		return nil, errors.Errorf("nil embedded SOCKS5 request destination")
	}

	if req.Command != statute.CommandConnect {
		return nil, errors.Errorf("unsupported embedded SOCKS5 command: %d", req.Command)
	}

	raw := req.RawDestAddr
	if raw.Port <= 0 || raw.Port > 65535 {
		return nil, errors.Errorf("invalid embedded SOCKS5 destination port: %d", raw.Port)
	}

	ret := &target{
		port: raw.Port,
	}

	switch raw.AddrType {
	case statute.ATYPDomain:
		host, err := normalizeDomain(raw.FQDN)
		if err != nil {
			return nil, err
		}
		ret.host = host

	case statute.ATYPIPv4:
		ip := raw.IP.To4()
		if ip == nil {
			return nil, errors.Errorf("invalid embedded SOCKS5 IPv4 destination")
		}
		ret.host = ip.String()

	case statute.ATYPIPv6:
		ip := raw.IP.To16()
		if ip == nil || ip.To4() != nil {
			return nil, errors.Errorf("invalid embedded SOCKS5 IPv6 destination")
		}
		ret.host = ip.String()

	default:
		return nil, errors.Errorf("unsupported embedded SOCKS5 address type: %d", raw.AddrType)
	}

	ret.addr = net.JoinHostPort(ret.host, strconv.Itoa(ret.port))
	return ret, nil
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	if domain == "" {
		return "", errors.Errorf("empty embedded SOCKS5 domain destination")
	}

	if len(domain) > 253 {
		return "", errors.Errorf("embedded SOCKS5 domain destination is too long")
	}

	if strings.ContainsAny(domain, "\x00/\\") {
		return "", errors.Errorf("embedded SOCKS5 domain destination contains invalid characters")
	}

	return domain, nil
}

func rejectUnsupportedCommand(ctx context.Context, writer io.Writer, req *gosocks5.Request) error {
	gosocks5.SendReply(writer, statute.RepCommandNotSupported, nil)
	return errors.Errorf("unsupported embedded SOCKS5 command: %d", req.Command)
}

func closeWrite(conn any) error {
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

type closeWriter interface {
	CloseWrite() error
}

func isExpectedNetErr(err error) bool {
	if err == nil {
		return true
	}

	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

type noResolveResolver struct{}

func (noResolveResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

type zapLogger struct{}

func (zapLogger) Errorf(format string, args ...interface{}) {
	zap.S().Debugf("embedded SOCKS5: "+format, args...)
}
