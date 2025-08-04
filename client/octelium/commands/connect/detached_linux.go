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

package connect

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func doRunDetached(args []string) error {

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	octeliumCmd := []string{executable}
	octeliumCmd = append(octeliumCmd, args...)

	zap.L().Debug("running systemd-run")

	cmd := []string{"systemd-run"}
	cmd = append(cmd, "-p", "User=root")
	cmd = append(cmd, "-p", `Restart=on-failure`)

	env := getDetachedModeEnvVars()
	for k, v := range env {
		cmd = append(cmd, "-p", fmt.Sprintf(`Environment="%s=%s"`, k, v))
	}

	cmd = append(cmd, octeliumCmd...)

	zap.L().Debug("running detached octelium ", zap.String("cmd", strings.Join(cmd, " ")))

	if b, err := exec.Command("sudo", cmd...).CombinedOutput(); err != nil {
		return errors.Errorf("Could not execute systemd-run %s. %+v", string(b), err)
	}
	return nil

}
