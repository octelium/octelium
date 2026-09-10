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
	"time"

	"github.com/gofrs/flock"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const defaultSocketPath = "/var/run/octelium/daemon.sock"

const dialProbeTimeout = 2 * time.Second

func GetDefaultAddress() string {
	if ret := os.Getenv("OCTELIUM_DAEMON_SOCKET"); ret != "" {
		return ret
	}

	return defaultSocketPath
}

type listener struct {
	net.Listener

	lock *flock.Flock
}

func (l *listener) Close() error {
	err := l.Listener.Close()

	if err := l.lock.Unlock(); err != nil {
		zap.L().Debug("Could not release the daemon lock file", zap.Error(err))
	}

	return err
}

func Listen(addr string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(addr), 0755); err != nil {
		return nil, err
	}

	lock, err := acquireLock(addr)
	if err != nil {
		return nil, err
	}

	if err := removeStaleSocket(addr); err != nil {
		lock.Unlock()
		return nil, err
	}

	lis, err := net.Listen("unix", addr)
	if err != nil {
		lock.Unlock()
		return nil, err
	}

	if err := os.Chmod(addr, 0666); err != nil {
		lis.Close()
		lock.Unlock()
		return nil, err
	}

	return &listener{
		Listener: lis,
		lock:     lock,
	}, nil
}

func acquireLock(addr string) (*flock.Flock, error) {
	lock := flock.New(fmt.Sprintf("%s.lock", addr), flock.SetPermissions(0644))

	locked, err := lock.TryLock()
	if err != nil {
		return nil, errors.Errorf("Could not acquire the daemon lock file at %s: %+v",
			lock.Path(), err)
	}
	if !locked {
		return nil, errors.Errorf(
			"Another Octelium daemon is already running. The lock file %s is held by it",
			lock.Path())
	}

	return lock, nil
}

func removeStaleSocket(addr string) error {
	info, err := os.Lstat(addr)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if info.Mode()&os.ModeSocket == 0 {
		return errors.Errorf("The daemon API address %s is not a Unix domain socket", addr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialProbeTimeout)
	defer cancel()

	if conn, err := Dial(ctx, addr); err == nil {
		conn.Close()
		return errors.Errorf("Another Octelium daemon is already serving at %s", addr)
	}

	zap.L().Debug("Removing a stale daemon socket", zap.String("path", addr))

	return os.Remove(addr)
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

	setPrincipalUser(ret)

	return ret, nil
}

func setPrincipalUser(pr *Principal) {
	usr, err := user.LookupId(pr.ID)
	if err != nil {
		zap.L().Debug("Could not look up the OS user of the principal",
			zap.String("principal", pr.ID), zap.Error(err))
		return
	}

	pr.Name = usr.Username
	pr.HomeDir = usr.HomeDir
}

func LookupPrincipal(id string) (*Principal, error) {
	usr, err := user.LookupId(id)
	if err != nil {
		return nil, errors.Errorf("Could not find the OS user: %s. %+v", id, err)
	}

	return &Principal{
		ID:      usr.Uid,
		Name:    usr.Username,
		HomeDir: usr.HomeDir,
	}, nil
}

type peerCred struct {
	uid uint32
	gid uint32
	pid int32
}
