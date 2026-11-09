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

package userexec

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/pkg/errors"
)

const waitDelay = time.Second

func Command(ctx context.Context, cred *syscall.Credential, name string, args ...string) (*exec.Cmd, error) {
	if cred == nil {
		return nil, errors.Errorf("The credential of the internal command is not set")
	}

	executable, err := getExecutable()
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, executable, append([]string{cmdArg, name}, args...)...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: cred,
		Setpgid:    true,
	}
	cmd.WaitDelay = waitDelay

	return cmd, nil
}

func getExecutable() (string, error) {
	if runtime.GOOS == "linux" {
		return "/proc/self/exe", nil
	}

	return os.Executable()
}
