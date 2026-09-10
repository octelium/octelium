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
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/asaskevich/govalidator"
	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octelium/commands/daemon/ipc"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	apiMajorVersion = 1
	apiMinorVersion = 0
)

type Opts struct {
	ListenAddress string
	StateDir      string
}

type Server struct {
	opts       *Opts
	instanceID string
	stateDir   string

	grpcSrv *grpc.Server
	lis     net.Listener

	ctx      context.Context
	cancelFn context.CancelFunc

	mu         sync.Mutex
	principals map[string]*principal
	isClosed   bool
}

func New(o *Opts) (*Server, error) {
	if o == nil {
		o = &Opts{}
	}

	ret := &Server{
		opts:       o,
		instanceID: uuid.NewString(),
		principals: make(map[string]*principal),
		stateDir:   o.StateDir,
	}

	if ret.opts.ListenAddress == "" {
		ret.opts.ListenAddress = ipc.GetDefaultAddress()
	}

	if ret.stateDir == "" {
		stateDir, err := getDefaultStateDir()
		if err != nil {
			return nil, err
		}
		ret.stateDir = stateDir
	}

	return ret, nil
}

func getDefaultStateDir() (string, error) {
	if ret := os.Getenv("OCTELIUM_DAEMON_STATE_DIR"); ret != "" {
		return ret, nil
	}

	switch {
	case cliutils.IsLinux():
		return "/var/lib/octelium", nil
	case cliutils.IsDarwin():
		return "/Library/Application Support/Octelium", nil
	case cliutils.IsWindows():
		return filepath.Join(os.Getenv("ProgramData"), "Octelium"), nil
	default:
		return "", errors.Errorf("This OS is not supported currently")
	}
}

func (s *Server) Run(ctx context.Context) error {
	s.ctx, s.cancelFn = context.WithCancel(ctx)

	if err := os.MkdirAll(s.stateDir, 0700); err != nil {
		return err
	}

	lis, err := ipc.Listen(s.opts.ListenAddress)
	if err != nil {
		return err
	}
	s.lis = lis

	s.grpcSrv = grpc.NewServer(
		grpc.Creds(ipc.NewTransportCredentials()),
	)

	daemonv1.RegisterMainServiceServer(s.grpcSrv, &service{
		s: s,
	})

	go func() {
		zap.L().Debug("Running the daemon gRPC server",
			zap.String("addr", s.opts.ListenAddress))
		if err := s.grpcSrv.Serve(lis); err != nil {
			zap.L().Debug("The daemon gRPC server is closed", zap.Error(err))
		}
	}()

	s.doAutoConnect()

	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return nil
	}
	s.isClosed = true
	principals := make([]*principal, 0, len(s.principals))
	for _, p := range s.principals {
		principals = append(principals, p)
	}
	s.mu.Unlock()

	if s.cancelFn != nil {
		s.cancelFn()
	}

	if s.grpcSrv != nil {
		s.grpcSrv.Stop()
	}

	for _, p := range principals {
		p.close()
	}

	return nil
}

func (s *Server) getPrincipal(pr *ipc.Principal) (*principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isClosed {
		return nil, status.Error(codes.Unavailable, "The daemon is shutting down")
	}

	if ret, ok := s.principals[pr.ID]; ok {
		return ret, nil
	}

	ret, err := newPrincipal(s, pr)
	if err != nil {
		return nil, err
	}

	s.principals[pr.ID] = ret

	return ret, nil
}

func (s *Server) doAutoConnect() {
	entries, err := os.ReadDir(filepath.Join(s.stateDir, "users"))
	if err != nil {
		if !os.IsNotExist(err) {
			zap.L().Warn("Could not read the daemon state directory", zap.Error(err))
		}
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		p, err := s.getPrincipal(&ipc.Principal{
			ID: entry.Name(),
		})
		if err != nil {
			zap.L().Warn("Could not load the state of the OS principal",
				zap.String("principal", entry.Name()), zap.Error(err))
			continue
		}

		p.doAutoConnect()
	}
}

func validateDomain(domain string) error {
	if domain == "" {
		return status.Error(codes.InvalidArgument, "The Cluster domain is not set")
	}

	if len(domain) > 255 || !govalidator.IsDNSName(domain) {
		return status.Errorf(codes.InvalidArgument, "Invalid Cluster domain: %s", domain)
	}

	return nil
}
