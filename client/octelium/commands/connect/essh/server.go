//go:build !windows
// +build !windows

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

package essh

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"sync"
	"time"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	handshakeTimeout   = 15 * time.Second
	maxConcurrentConns = 128
)

type Server struct {
	sshConfig *ssh.ServerConfig
	isClosed  bool
	isStarted bool
	mu        sync.Mutex
	wg        sync.WaitGroup
	closeDone chan struct{}

	opts     *Opts
	cancelFn context.CancelFunc

	listeners []net.Listener
	conns     map[net.Conn]struct{}

	connSem chan struct{}

	usr      *user.User
	sameUser bool
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	ctx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()

	zap.L().Debug("Starting eSSH handleConn", zap.String("addr", c.RemoteAddr().String()))

	if err := c.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		zap.L().Debug("Could not set the eSSH handshake deadline", zap.Error(err))
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		zap.L().Debug("Could not complete the eSSH handshake", zap.Error(err))
		c.Close()
		return
	}

	if err := c.SetDeadline(time.Time{}); err != nil {
		zap.L().Debug("Could not clear the eSSH handshake deadline", zap.Error(err))
	}

	dctx, err := newDctx(c, sshConn, s.usr, s.sameUser)
	if err != nil {
		zap.L().Debug("Could not create a new dctx", zap.Error(err))
		sshConn.Close()
		c.Close()
		return
	}

	defer func() {
		dctx.close()
		dctx.wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("eSSH: ctx done. Exiting handleConn loop")
			return
		case req := <-reqs:
			if req == nil {
				zap.L().Debug("eSSH: no more reqs. Exiting handleConn loop")
				return
			}
			dctx.handleGlobalReq(req)
		case nch, ok := <-chans:
			if !ok || nch == nil {
				zap.L().Debug("eSSH: Nil nch. Exiting handleConn loop")
				return
			}
			dctx.wg.Add(1)
			go func() {
				defer dctx.wg.Done()
				dctx.handleNewChannel(ctx, nch)
			}()
		}
	}
}

func (d *dctx) handleGlobalReq(req *ssh.Request) {
	if req == nil {
		return
	}

	zap.L().Debug("New global req", zap.String("type", req.Type))
	switch req.Type {
	case "keepalive@openssh.com":
		if req.WantReply {
			req.Reply(true, nil)
		}
	default:
		req.Reply(false, nil)
	}
}

func (c *dctx) handleNewChannel(ctx context.Context, nch ssh.NewChannel) {
	zap.L().Debug("Starting handleNewChannel", zap.String("type", nch.ChannelType()))

	switch nch.ChannelType() {
	case "session":
		c.handleSessionRequests(ctx, nch)
	case "direct-tcpip":
		c.handleTCPIPChan(ctx, nch)
	default:
		zap.L().Debug("Unsupported channel", zap.String("channelType", nch.ChannelType()))
		nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("Unsupported channel type: %s", nch.ChannelType()))
	}
}

func (s *Server) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.Errorf("nil context")
	}

	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return errors.Errorf("eSSH server is already closed")
	}
	if s.isStarted {
		s.mu.Unlock()
		return errors.Errorf("eSSH server is already started")
	}
	s.isStarted = true
	ctx, cancelFn := context.WithCancel(ctx)
	s.cancelFn = cancelFn
	s.mu.Unlock()

	var listeners []net.Listener
	for _, listenerAddr := range s.opts.ListenAddrs {

		zap.L().Debug("Starting running eSSH server",
			zap.Any("listenAddr", listenerAddr))

		lis, err := s.getListener(ctx, listenerAddr)
		if err != nil {
			cancelFn()
			for _, listener := range listeners {
				listener.Close()
			}
			s.mu.Lock()
			if !s.isClosed {
				s.isStarted = false
				s.cancelFn = nil
			}
			s.mu.Unlock()
			return err
		}
		listeners = append(listeners, lis)
	}

	s.mu.Lock()
	if s.isClosed || ctx.Err() != nil {
		ctxErr := ctx.Err()
		if !s.isClosed {
			s.isStarted = false
			s.cancelFn = nil
		}
		s.mu.Unlock()
		cancelFn()
		for _, listener := range listeners {
			listener.Close()
		}
		if ctxErr != nil {
			return ctxErr
		}
		return errors.Errorf("eSSH server was closed during startup")
	}
	s.listeners = listeners
	s.wg.Add(len(listeners))
	s.mu.Unlock()

	for _, lis := range listeners {
		go func(ctx context.Context, lis net.Listener) {
			defer s.wg.Done()
			if err := s.doRun(ctx, lis); err != nil {
				zap.L().Debug("essh: Could not run listener", zap.Error(err))
			}
		}(ctx, lis)
	}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.isClosed {
		closeDone := s.closeDone
		s.mu.Unlock()
		<-closeDone
		return nil
	}

	zap.L().Debug("Starting closing eSSH server")
	s.isClosed = true
	cancelFn := s.cancelFn
	listeners := append([]net.Listener(nil), s.listeners...)
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	if cancelFn != nil {
		cancelFn()
	}

	for _, lis := range listeners {
		lis.Close()
	}
	for _, conn := range conns {
		conn.Close()
	}
	s.wg.Wait()

	zap.L().Debug("eSSH server is now closed")
	close(s.closeDone)

	return nil
}

func (s *Server) doRun(ctx context.Context, lis net.Listener) error {

	for {
		conn, err := lis.Accept()
		if err != nil {
			zap.L().Debug("Could not accept eSSH conn", zap.Error(err))
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				zap.L().Debug("eSSH Timeout err", zap.Error(opErr))
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(100 * time.Millisecond):
				}
				continue
			}

			select {
			case <-ctx.Done():
				zap.L().Debug("shutting down eSSH server")
				return nil
			default:
				return err
			}
		}

		select {
		case s.connSem <- struct{}{}:
		default:
			zap.L().Warn("Too many concurrent eSSH connections. Rejecting the connection",
				zap.String("addr", conn.RemoteAddr().String()),
				zap.Int("max", maxConcurrentConns))
			conn.Close()
			continue
		}

		s.mu.Lock()
		if s.isClosed {
			s.mu.Unlock()
			<-s.connSem
			conn.Close()
			continue
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()

		go func(conn net.Conn) {
			defer func() {
				<-s.connSem
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				s.wg.Done()
			}()
			s.handleConn(ctx, conn)
		}(conn)
	}
}

type Opts struct {
	Signer   ssh.Signer
	CAPubKey ssh.PublicKey

	GoNetCtl    ccommon.GoNetCtl
	ListenAddrs []string

	User string
}

func NewServer(opts *Opts) (*Server, error) {

	if cliutils.IsWindows() {
		return nil, errors.Errorf("eSSH is not currently supported on Windows")
	}
	if opts == nil {
		return nil, errors.Errorf("nil eSSH server opts")
	}
	if opts.Signer == nil {
		return nil, errors.Errorf("nil eSSH host signer")
	}
	if opts.CAPubKey == nil {
		return nil, errors.Errorf("nil eSSH CA public key")
	}
	if opts.GoNetCtl == nil {
		return nil, errors.Errorf("nil eSSH GoNet controller")
	}
	if len(opts.ListenAddrs) == 0 {
		return nil, errors.Errorf("empty eSSH listen addresses")
	}
	for _, addr := range opts.ListenAddrs {
		if addr == "" {
			return nil, errors.Errorf("empty eSSH listen address")
		}
	}
	caPubKeyBytes := opts.CAPubKey.Marshal()
	if len(caPubKeyBytes) == 0 {
		return nil, errors.Errorf("empty eSSH CA public key")
	}
	optsCopy := *opts
	optsCopy.ListenAddrs = append([]string(nil), opts.ListenAddrs...)

	server := &Server{
		opts:      &optsCopy,
		sameUser:  true,
		connSem:   make(chan struct{}, maxConcurrentConns),
		conns:     make(map[net.Conn]struct{}),
		closeDone: make(chan struct{}),
	}

	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	if usr.Uid == "0" {
		zap.L().Debug("eSSH server is running as root")

		if server.opts.User != "" {
			usr, err := user.Lookup(server.opts.User)
			if err != nil {
				return nil, errors.Errorf("Could not look up host user: %s. %+v", server.opts.User, err)
			}

			server.usr = usr
			if usr.Uid != "0" {
				server.sameUser = false
			}
		}
	}

	if server.usr == nil {
		server.usr = usr
	}

	zap.L().Debug("Chosen host user", zap.Any("user", server.usr))

	server.sshConfig = &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-Octelium",

		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			checker := &ssh.CertChecker{
				IsUserAuthority: func(auth ssh.PublicKey) bool {
					authBytes := auth.Marshal()
					if len(authBytes) == 0 {
						return false
					}

					return utils.SecureBytesEqual(authBytes, caPubKeyBytes)
				},
			}

			ret, err := checker.Authenticate(conn, key)
			if err != nil {
				zap.L().Debug("Could not authenticate ssh key", zap.Error(err))
				return nil, err
			}

			zap.L().Debug("SSH client successfully authenticated with permissions", zap.Any("perm", ret))
			return ret, nil
		},
	}
	server.sshConfig.AddHostKey(server.opts.Signer)

	return server, nil
}

func (s *Server) getListener(ctx context.Context, listenerAddr string) (net.Listener, error) {
	var err error
	var listener net.Listener
	for i := 0; i < 100; i++ {

		gonet := s.opts.GoNetCtl.GetGoNet()

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

		zap.L().Warn("Could not listen on TCP port", zap.String("addr", listenerAddr), zap.Error(err))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return nil, errors.Wrapf(err, "Could not listen on TCP port on %s", listenerAddr)
}
