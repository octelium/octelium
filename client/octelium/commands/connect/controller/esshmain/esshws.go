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

package esshmain

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/octelium/octelium/client/octelium/commands/connect/essh"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type ESSHMain struct {
	srv *essh.Server
	c   *cliconfigv1.Connection
}

func New(c *cliconfigv1.Connection, goNetCtl ccommon.GoNetCtl,
	ipv4Supported, ipv6Supported bool) (*ESSHMain, error) {
	ret := &ESSHMain{
		c: c,
	}
	var err error

	privSigner, err := ssh.NewSignerFromKey(ed25519.PrivateKey(c.Connection.Ed25519Key))
	if err != nil {
		return nil, err
	}

	if len(c.Connection.ServiceConfigs) == 0 ||
		c.Connection.ServiceConfigs[0].GetSsh() == nil ||
		len(c.Connection.ServiceConfigs[0].GetSsh().AuthorizedKeys) == 0 {
		return nil, errors.Errorf("Could not find the Cluster authorizedKeys in the connection serviceConfigs")
	}

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.Connection.ServiceConfigs[0].GetSsh().AuthorizedKeys[0]))
	if err != nil {
		return nil, err
	}

	var listenAddrs []string
	portStr := fmt.Sprintf("%d", c.Preferences.ESSH.Port)

	if len(c.Preferences.ESSH.ListenIPAddresses) > 0 {
		for _, addr := range c.Preferences.ESSH.ListenIPAddresses {
			listenAddrs = append(listenAddrs, net.JoinHostPort(addr, portStr))
		}
	} else {
		for _, addr := range c.Connection.Addresses {
			if addr.V4 != "" && ipv4Supported {
				listenAddrs = append(listenAddrs,
					net.JoinHostPort(umetav1.ToDualStackNetwork(addr).ToIP().Ipv4, portStr))
			} else if addr.V6 != "" && ipv6Supported {
				listenAddrs = append(listenAddrs,
					net.JoinHostPort(umetav1.ToDualStackNetwork(addr).ToIP().Ipv6, portStr))
			}
		}
	}

	ret.srv, err = essh.NewServer(&essh.Opts{
		Signer:      privSigner,
		CAPubKey:    pubkey,
		ListenAddrs: listenAddrs,
		GoNetCtl:    goNetCtl,
		User:        c.Preferences.ESSH.User,
	})
	if err != nil {
		return nil, err
	}

	zap.L().Debug("Main eSSH server successfully created")

	return ret, nil
}

func (s *ESSHMain) Run(ctx context.Context) error {
	zap.L().Debug("Running Workspace eSSH server")

	return s.srv.Start(ctx)
}

func (s *ESSHMain) Close() error {
	zap.L().Debug("Closing Workspace eSSH server")
	if s.srv == nil {
		return nil
	}
	return s.srv.Close()
}
