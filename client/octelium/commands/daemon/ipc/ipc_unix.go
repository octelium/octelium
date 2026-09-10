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

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const defaultSocketPath = "/var/run/octelium/daemon.sock"

func GetDefaultAddress() string {
	if ret := os.Getenv("OCTELIUM_DAEMON_SOCKET"); ret != "" {
		return ret
	}

	return defaultSocketPath
}

func Listen(addr string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(addr), 0755); err != nil {
		return nil, err
	}

	if _, err := os.Stat(addr); err == nil {
		zap.L().Debug("Removing a stale daemon socket", zap.String("path", addr))
		if err := os.Remove(addr); err != nil {
			return nil, err
		}
	}

	lis, err := net.Listen("unix", addr)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(addr, 0666); err != nil {
		lis.Close()
		return nil, err
	}

	return lis, nil
}

func Dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}

func getPeerPrincipal(conn net.Conn) (*Principal, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.Errorf("The daemon API is only served over local IPC")
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, err
	}

	var cred *peerCred
	var credErr error

	if err := rawConn.Control(func(fd uintptr) {
		cred, credErr = getPeerCred(fd)
	}); err != nil {
		return nil, err
	}
	if credErr != nil {
		return nil, credErr
	}

	ret := &Principal{
		ID:  fmt.Sprintf("%d", cred.uid),
		PID: cred.pid,
	}

	if usr, err := user.LookupId(ret.ID); err == nil {
		ret.Name = usr.Username
	}

	return ret, nil
}

type peerCred struct {
	uid uint32
	gid uint32
	pid int32
}
