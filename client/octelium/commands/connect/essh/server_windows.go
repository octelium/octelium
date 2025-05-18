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

	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"golang.org/x/crypto/ssh"
)

type Opts struct {
	Signer   ssh.Signer
	CAPubKey ssh.PublicKey

	GoNetCtl    ccommon.GoNetCtl
	ListenAddrs []string

	User string
}

type Server struct {
}

func NewServer(opts *Opts) (*Server, error) {
	return &Server{}, nil
}

func (s *Server) Start(ctx context.Context) error {
	return nil
}

func (s *Server) Close() error {
	return nil
}
