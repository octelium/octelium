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

package esshws

import (
	"context"
	"crypto/ed25519"
	"os"
	"os/user"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/octelium/octelium/client/octelium/commands/connect/essh"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type ESSHWS struct {
	srv *essh.Server
	c   *cliconfigv1.Connection
}

func New(c *cliconfigv1.Connection, goNetCtl ccommon.GoNetCtl) (*ESSHWS, error) {
	ret := &ESSHWS{
		c: c,
	}
	var err error

	zap.L().Debug("Creating Workspace eSSH server")

	privSigner, err := ssh.NewSignerFromKey(ed25519.PrivateKey(c.Connection.Ed25519Key))
	if err != nil {
		return nil, err
	}

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.Connection.ServiceConfigs[0].GetSsh().AuthorizedKeys[0]))
	if err != nil {
		return nil, err
	}

	usr := func() string {
		if envUsr := os.Getenv("OCTELIUM_WS_ESSH_USER"); envUsr != "" {
			return envUsr
		}
		ret, err := user.LookupId("1000")
		if err != nil {
			return ""
		}
		return ret.Username
	}()

	ret.srv, err = essh.NewServer(&essh.Opts{
		Signer:   privSigner,
		CAPubKey: pubkey,
		ListenAddrs: []string{
			"0.0.0.0:2022",
		},
		User:     usr,
		GoNetCtl: goNetCtl,
	})
	if err != nil {
		return nil, err
	}

	zap.L().Debug("Workspace eSSH server successfully created")

	return ret, nil
}

func (s *ESSHWS) Run(ctx context.Context) error {
	zap.L().Debug("Running Workspace eSSH server")
	return s.srv.Start(ctx)
}

func (s *ESSHWS) Close() error {
	zap.L().Debug("Closing Workspace eSSH server")
	if s.srv == nil {
		return nil
	}
	return s.srv.Close()
}
