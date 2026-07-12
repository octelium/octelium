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

func readRegistry(rr *authv1.DeviceProbe_ReadRegistry) ([]byte, error) {
	hive, path, err := splitHive(rr.Key)
	if err != nil {
		return nil, err
	}
	k, err := registry.OpenKey(hive, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	n, _, err := k.GetValue(rr.Name, nil)
	if err != nil && err != registry.ErrShortBuffer {
		return nil, err
	}
	if n > maxOutputBytes {
		return nil, errors.Errorf("registry value is too large: %d bytes", n)
	}
	if n == 0 {
		return nil, nil
	}

	buf := make([]byte, n)
	n, _, err = k.GetValue(rr.Name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
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
