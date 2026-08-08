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

package controller

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const osCmdTimeout = 15 * time.Second

func runOSCmdOutput(name string, args ...string) ([]byte, error) {
	return runOSCmdStdin(nil, name, args...)
}

func runOSCmdStdin(stdin io.Reader, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), osCmdTimeout)
	defer cancel()

	zap.L().Debug("Executing cmd",
		zap.String("cmd", strings.Join(append([]string{name}, args...), " ")))

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin

	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return out, errors.Errorf("Timed out running %s: %+v", name, ctx.Err())
		}
		return out, err
	}

	return out, nil
}

func runOSCmd(name string, args ...string) error {
	out, err := runOSCmdOutput(name, args...)
	if err != nil {
		return errors.Errorf("Could not run %s: %+v. %s", name, err, string(out))
	}

	return nil
}

func runOSCmdInput(input string, name string, args ...string) ([]byte, error) {
	return runOSCmdStdin(bytes.NewReader([]byte(input)), name, args...)
}
