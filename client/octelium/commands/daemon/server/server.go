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

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/client/common/cliutils/vhome"
	"github.com/octelium/octelium/client/octelium/commands/daemon/ipc"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/net/idna"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	apiMajorVersion = 1
	apiMinorVersion = 0
)

const gracefulStopTimeout = 5 * time.Second

type Opts struct {
	ListenAddress string
	StateDir      string
	OwnerID       string
}

type Server struct {
	opts       *Opts
	instanceID string
	stateDir   string

	grpcSrv *grpc.Server
	srvErrC chan error

	ctx      context.Context
	cancelFn context.CancelFunc

	mu        sync.Mutex
	principal *principal
	isClosed  bool
}

func New(o *Opts) (*Server, error) {
	if o == nil {
		o = &Opts{}
	}

	ret := &Server{
		opts:       o,
		instanceID: uuid.NewString(),
		stateDir:   o.StateDir,
		srvErrC:    make(chan error, 1),
	}

	if ret.opts.ListenAddress == "" {
		ret.opts.ListenAddress = ipc.GetDefaultAddress()
	}

	if ret.stateDir == "" {
		ret.stateDir = os.Getenv("OCTELIUM_DAEMON_STATE_DIR")
	}

	return ret, nil
}

func (s *Server) getPrincipalDBDir(pr *ipc.Principal) (string, error) {
	if s.stateDir != "" {
		return filepath.Join(s.stateDir, "users", pr.ID), nil
	}

	return vhome.GetOcteliumHomeFromUserHome(pr.HomeDir)
}

func (s *Server) Run(ctx context.Context) error {
	s.ctx, s.cancelFn = context.WithCancel(ctx)

	if s.stateDir != "" {
		if err := os.MkdirAll(s.stateDir, 0700); err != nil {
			return err
		}
	}

	lis, err := ipc.Listen(s.opts.ListenAddress)
	if err != nil {
		return err
	}

	if s.opts.OwnerID != "" {
		if err := s.bindOwner(); err != nil {
			lis.Close()
			return err
		}
	}

	s.grpcSrv = grpc.NewServer(
		grpc.Creds(ipc.NewTransportCredentials()),
	)

	daemonv1.RegisterMainServiceServer(s.grpcSrv, &service{
		s: s,
	})

	go func() {
		zap.L().Debug("Running the daemon gRPC server",
			zap.String("addr", s.opts.ListenAddress))
		err := s.grpcSrv.Serve(lis)
		zap.L().Debug("The daemon gRPC server is closed", zap.Error(err))
		s.srvErrC <- err
	}()

	return nil
}

func (s *Server) bindOwner() error {
	pr, err := ipc.LookupPrincipal(s.opts.OwnerID)
	if err != nil {
		return err
	}

	if _, err := s.bindPrincipal(pr); err != nil {
		return err
	}

	return nil
}

func (s *Server) Wait() error {
	select {
	case <-s.ctx.Done():
		return nil
	case err := <-s.srvErrC:
		if err == nil || errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return nil
	}
	s.isClosed = true
	p := s.principal
	s.mu.Unlock()

	if s.cancelFn != nil {
		s.cancelFn()
	}

	if s.grpcSrv != nil {
		stoppedCh := make(chan struct{})
		go func() {
			s.grpcSrv.GracefulStop()
			close(stoppedCh)
		}()

		select {
		case <-stoppedCh:
		case <-time.After(gracefulStopTimeout):
			zap.L().Debug("Timed out gracefully stopping the daemon gRPC server")
			s.grpcSrv.Stop()
		}
	}

	if p != nil {
		p.close()
	}

	return nil
}

func (s *Server) bindPrincipal(pr *ipc.Principal) (*principal, error) {
	s.mu.Lock()

	if s.isClosed {
		s.mu.Unlock()
		return nil, status.Error(codes.Unavailable, "The daemon is shutting down")
	}

	if s.principal != nil {
		ret := s.principal
		s.mu.Unlock()

		if ret.id != pr.ID {
			return nil, status.Errorf(codes.PermissionDenied,
				"This Octelium daemon is owned by the OS user %s", ret.displayName())
		}

		return ret, nil
	}

	if s.opts.OwnerID != "" && s.opts.OwnerID != pr.ID {
		s.mu.Unlock()
		return nil, status.Errorf(codes.PermissionDenied,
			"This Octelium daemon is owned by the OS user %s", s.opts.OwnerID)
	}

	ret, err := newPrincipal(s, pr)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	s.principal = ret
	s.mu.Unlock()

	zap.L().Debug("Bound the daemon to its owner",
		zap.String("principal", ret.displayName()))

	ret.startReconcileLoop()

	ret.doAutoConnect()

	return ret, nil
}

func canonicalizeDomain(domain string) (string, error) {
	invalidErr := status.Errorf(codes.InvalidArgument, "Invalid Cluster domain: %s", domain)

	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", status.Error(codes.InvalidArgument, "The Cluster domain is not set")
	}

	domain = strings.TrimSuffix(domain, ".")

	ret, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", invalidErr
	}

	ret = strings.ToLower(ret)

	if len(ret) > 253 || !strings.Contains(ret, ".") ||
		govalidator.IsIP(ret) || !govalidator.IsDNSName(ret) {
		return "", invalidErr
	}

	return ret, nil
}
