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
	"maps"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	systemdVersionCollect   = 236
	systemdVersionOOMPolicy = 243
)

const maxSystemdUnitNameLen = 255

func doRunDetached(domain string, args []string) error {

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	octeliumCmd := []string{executable}
	octeliumCmd = append(octeliumCmd, args...)

	zap.L().Debug("running systemd-run")

	cmd := getSystemdRunArgs(getSystemdVersion(), domain, octeliumCmd, getDetachedModeEnvVars())

	zap.L().Debug("running detached octelium ", zap.String("cmd", strings.Join(cmd, " ")))

	if b, err := exec.Command("sudo", cmd...).CombinedOutput(); err != nil {
		return errors.Errorf("Could not execute systemd-run %s. %+v", string(b), err)
	}
	return nil

}

func getSystemdRunArgs(version int, domain string, octeliumCmd []string, env map[string]string) []string {
	ret := []string{"systemd-run"}

	if version >= systemdVersionCollect {
		if unitName := getSystemdUnitName(domain); unitName != "" {
			ret = append(ret, fmt.Sprintf("--unit=%s", unitName))
		}
		ret = append(ret, fmt.Sprintf("--description=Octelium connection for %s", domain), "--collect")
	}

	ret = append(ret, "-p", "User=root")
	ret = append(ret, "-p", `Restart=on-failure`)

	if version >= systemdVersionOOMPolicy {
		ret = append(ret, "-p", "OOMPolicy=continue")
	}

	for _, k := range slices.Sorted(maps.Keys(env)) {
		ret = append(ret, "-p", fmt.Sprintf(`Environment="%s"`, escapeSystemdQuoted(fmt.Sprintf("%s=%s", k, env[k]))))
	}

	return append(ret, octeliumCmd...)
}

func getSystemdUnitName(domain string) string {
	if domain == "" || strings.ContainsFunc(domain, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '-' || r == '_')
	}) {
		return ""
	}

	ret := fmt.Sprintf("octelium-connect-%s.service", strings.ToLower(domain))
	if len(ret) > maxSystemdUnitNameLen {
		return ""
	}

	return ret
}

func escapeSystemdQuoted(arg string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(arg)
}

func getSystemdVersion() int {
	out, err := exec.Command("systemctl", "--version").Output()
	if err != nil {
		zap.L().Debug("Could not get the systemd version", zap.Error(err))
		return 0
	}

	return parseSystemdVersion(string(out))
}

func parseSystemdVersion(arg string) int {
	fields := strings.Fields(arg)
	if len(fields) < 2 || fields[0] != "systemd" {
		return 0
	}

	ret, err := strconv.Atoi(fields[1])
	if err != nil || ret < 0 {
		return 0
	}

	return ret
}
