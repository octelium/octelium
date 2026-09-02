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
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const processWaitDelay = 5 * time.Second

func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	pid := cmd.Process.Pid

	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		zap.L().Debug("Could not kill the process group. Killing the process only",
			zap.Int("pid", pid), zap.Error(err))
		cmd.Process.Kill()
	}
}

func signalProcessGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return errors.Errorf("Process is not running")
	}

	pid := cmd.Process.Pid
	if err := syscall.Kill(-pid, sig); err != nil {
		return cmd.Process.Signal(sig)
	}

	return nil
}

func getSSHSignal(sig string) (syscall.Signal, error) {
	switch ssh.Signal(sig) {
	case ssh.SIGABRT:
		return syscall.SIGABRT, nil
	case ssh.SIGALRM:
		return syscall.SIGALRM, nil
	case ssh.SIGFPE:
		return syscall.SIGFPE, nil
	case ssh.SIGHUP:
		return syscall.SIGHUP, nil
	case ssh.SIGILL:
		return syscall.SIGILL, nil
	case ssh.SIGINT:
		return syscall.SIGINT, nil
	case ssh.SIGKILL:
		return syscall.SIGKILL, nil
	case ssh.SIGPIPE:
		return syscall.SIGPIPE, nil
	case ssh.SIGQUIT:
		return syscall.SIGQUIT, nil
	case ssh.SIGSEGV:
		return syscall.SIGSEGV, nil
	case ssh.SIGTERM:
		return syscall.SIGTERM, nil
	case ssh.SIGUSR1:
		return syscall.SIGUSR1, nil
	case ssh.SIGUSR2:
		return syscall.SIGUSR2, nil
	default:
		return 0, errors.Errorf("Unsupported signal: %s", sig)
	}
}

func getSSHSignalName(sig syscall.Signal) (ssh.Signal, error) {
	switch sig {
	case syscall.SIGABRT:
		return ssh.SIGABRT, nil
	case syscall.SIGALRM:
		return ssh.SIGALRM, nil
	case syscall.SIGFPE:
		return ssh.SIGFPE, nil
	case syscall.SIGHUP:
		return ssh.SIGHUP, nil
	case syscall.SIGILL:
		return ssh.SIGILL, nil
	case syscall.SIGINT:
		return ssh.SIGINT, nil
	case syscall.SIGKILL:
		return ssh.SIGKILL, nil
	case syscall.SIGPIPE:
		return ssh.SIGPIPE, nil
	case syscall.SIGQUIT:
		return ssh.SIGQUIT, nil
	case syscall.SIGSEGV:
		return ssh.SIGSEGV, nil
	case syscall.SIGTERM:
		return ssh.SIGTERM, nil
	case syscall.SIGUSR1:
		return ssh.SIGUSR1, nil
	case syscall.SIGUSR2:
		return ssh.SIGUSR2, nil
	default:
		return "", errors.Errorf("Unsupported signal: %d", sig)
	}
}

func getSysProcCredential(usr *user.User) (*syscall.Credential, error) {
	uid, err := strconv.ParseUint(usr.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(usr.Gid, 10, 32)
	if err != nil {
		return nil, err
	}

	groupIDs, err := usr.GroupIds()
	if err != nil {
		return nil, err
	}

	groups := make([]uint32, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		val, err := strconv.ParseUint(groupID, 10, 32)
		if err != nil {
			return nil, err
		}
		groups = append(groups, uint32(val))
	}

	return &syscall.Credential{
		Uid:    uint32(uid),
		Gid:    uint32(gid),
		Groups: groups,
	}, nil
}
