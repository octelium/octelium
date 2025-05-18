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

//go:build !windows
// +build !windows


package essh

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"runtime"
	"sync"
	"time"

	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	sshConfig *ssh.ServerConfig
	isClosed  bool
	mu        sync.Mutex

	opts     *Opts
	cancelFn context.CancelFunc

	listeners []net.Listener

	usr      *user.User
	sameUser bool
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	ctx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()

	zap.S().Debugf("New Conn: %s", c.RemoteAddr().String())

	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		c.Close()
		return
	}

	dctx, err := newDctx(c, sshConn, s.usr, s.sameUser)
	if err != nil {
		zap.S().Debugf("Could not create a new dctx: %+v", err)
		return
	}

	defer dctx.close()

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
			go dctx.handleGlobalReq(req)
		case nch, ok := <-chans:
			if !ok || nch == nil {
				zap.L().Debug("eSSH: Nil nch. Exiting handleConn loop")
				return
			}
			go dctx.handleNewChannel(ctx, nch)
		}
	}
}

func (d *dctx) handleGlobalReq(req *ssh.Request) {
	if req == nil {
		return
	}

	zap.S().Debugf("New global req: %s", req.Type)
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
	zap.S().Debugf("New Channel: %s", nch.ChannelType())

	switch nch.ChannelType() {
	case "session":
		go c.handleSessionRequests(ctx, nch)
	case "direct-tcpip":
		go c.handleTCPIPChan(ctx, nch)
	default:
		zap.L().Debug("Unsupported channel", zap.String("channelType", nch.ChannelType()))
		nch.Reject(ssh.UnknownChannelType, fmt.Sprintf("Unsupported channel type: %s", nch.ChannelType()))
	}
}

func (s *Server) Start(ctx context.Context) error {
	ctx, cancelFn := context.WithCancel(ctx)
	s.cancelFn = cancelFn

	for _, listenerAddr := range s.opts.ListenAddrs {

		zap.L().Debug("Starting running eSSH server",
			zap.Any("listenAddr", listenerAddr))

		lis, err := s.getListener(listenerAddr)
		if err != nil {
			return err
		}
		s.listeners = append(s.listeners, lis)

		go func(ctx context.Context) {
			if err := s.doRun(ctx, lis); err != nil {
				zap.L().Debug("essh: Could not doRun ipv4", zap.Error(err))
			}
		}(ctx)
	}

	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}

	zap.L().Debug("Starting closing eSSH server")
	s.isClosed = true
	s.cancelFn()

	for _, lis := range s.listeners {
		lis.Close()
	}

	zap.L().Debug("eSSH server is now closed")

	return nil
}

func (s *Server) doRun(ctx context.Context, lis net.Listener) error {

	for {
		conn, err := lis.Accept()
		if err != nil {
			zap.S().Debugf("Could not accept conn: %+v", err)
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				zap.S().Debugf("Timeout err")
				time.Sleep(100 * time.Millisecond)
				continue
			}

			select {
			case <-ctx.Done():
				zap.S().Debugf("shutting down server")
				return nil
			default:
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		go s.handleConn(ctx, conn)
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

	if runtime.GOOS == "windows" {
		return nil, errors.Errorf("eSSH is not currently supported on Windows")
	}

	server := &Server{
		opts:     opts,
		sameUser: true,
	}

	usr, err := user.Current()
	if err != nil {
		return nil, err
	}

	if usr.Uid == "0" && usr.Username == "root" {
		zap.L().Debug("eSSH server is running as root")

		if opts.User != "" {
			usr, err := user.Lookup(opts.User)
			if err != nil {
				return nil, errors.Errorf("Could not look up host user: %s. %+v", opts.User, err)
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

					return utils.SecureBytesEqual(authBytes, opts.CAPubKey.Marshal())
				},
			}

			ret, err := checker.Authenticate(conn, key)
			if err != nil {
				zap.S().Debugf("Could not authenticate ssh key: %+v : %+v", err, key)
				return nil, err
			}

			zap.S().Debugf("SSH client successfully authenticated with permissions: %+v", ret)
			return ret, nil
		},
	}
	server.sshConfig.AddHostKey(opts.Signer)

	return server, nil
}

func (s *Server) getListener(listenerAddr string) (net.Listener, error) {
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

		zap.S().Warnf("Could not listen on TCP port on %s: %+v. Trying again (attempt %d).", listenerAddr, err, i)
		time.Sleep(250 * time.Millisecond)
	}
	return nil, errors.Errorf("Could not listen on TCP port on %s:.", listenerAddr)
}
