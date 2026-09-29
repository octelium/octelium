//go:build windows

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

package deviceprobe

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	return token.IsElevated()
}

func readRegistry(probeID string, rr *authv1.DeviceProbe_ReadRegistry) *authv1.DeviceProbeResult {
	hive, path, err := splitHive(rr.Key)
	if err != nil {
		return probeStatus(probeID, authv1.DeviceProbeResult_FAILED, err.Error())
	}
	k, err := registry.OpenKey(hive, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return probeErr(probeID, err)
	}
	defer k.Close()

	_, valType, err := k.GetValue(rr.Name, nil)
	if err != nil && err != registry.ErrShortBuffer {
		return probeErr(probeID, err)
	}

	ret := &authv1.DeviceProbeResult{
		ProbeID: probeID,
		Status:  authv1.DeviceProbeResult_OK,
	}

	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		val, _, err := k.GetStringValue(rr.Name)
		if err != nil {
			return probeErr(probeID, err)
		}
		ret.Value = &authv1.DeviceProbeResult_Text{Text: val}
	case registry.MULTI_SZ:
		val, _, err := k.GetStringsValue(rr.Name)
		if err != nil {
			return probeErr(probeID, err)
		}
		ret.Value = &authv1.DeviceProbeResult_List_{
			List: &authv1.DeviceProbeResult_List{
				Items: val,
			},
		}
	case registry.DWORD, registry.QWORD:
		val, _, err := k.GetIntegerValue(rr.Name)
		if err != nil {
			return probeErr(probeID, err)
		}
		ret.Value = &authv1.DeviceProbeResult_Text{Text: strconv.FormatUint(val, 10)}
	default:
		n, _, err := k.GetValue(rr.Name, nil)
		if err != nil && err != registry.ErrShortBuffer {
			return probeErr(probeID, err)
		}
		if n > defaultMaxOutput {
			return probeStatus(probeID, authv1.DeviceProbeResult_FAILED,
				fmt.Sprintf("registry value is too large: %d bytes", n))
		}

		buf := make([]byte, n)
		if n > 0 {
			n, _, err = k.GetValue(rr.Name, buf)
			if err != nil {
				return probeErr(probeID, err)
			}
		}
		ret.Value = &authv1.DeviceProbeResult_Data{Data: buf[:n]}
	}

	return ret
}

func splitHive(key string) (registry.Key, string, error) {
	key = strings.ReplaceAll(key, "/", `\`)
	parts := strings.SplitN(key, `\`, 2)
	if len(parts) != 2 {
		return 0, "", errors.Errorf("invalid registry key: %s", key)
	}
	switch strings.ToUpper(parts[0]) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, parts[1], nil
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, parts[1], nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, parts[1], nil
	case "HKU", "HKEY_USERS":
		return registry.USERS, parts[1], nil
	default:
		return 0, "", errors.Errorf("unsupported registry hive: %s", parts[0])
	}
}

func openProbeFile(pth string) (*os.File, error) {
	return os.Open(pth)
}

func getCommandEnv() []string {
	var ret []string
	for _, name := range []string{
		"SystemRoot", "SystemDrive", "windir", "PATH", "PATHEXT",
		"TEMP", "TMP", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "CommonProgramFiles",
	} {
		if val, ok := os.LookupEnv(name); ok {
			ret = append(ret, fmt.Sprintf("%s=%s", name, val))
		}
	}
	return ret
}

func setCommandProcAttrs(cmd *exec.Cmd) {
}

func cleanupCommand(cmd *exec.Cmd) {
}
