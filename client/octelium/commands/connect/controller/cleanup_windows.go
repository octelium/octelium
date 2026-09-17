//go:build windows
// +build windows

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
	"errors"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func cleanupOwnerRunning(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return !errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	windows.CloseHandle(h)
	return true
}

func reconcilePlatformCleanup(cleanup *cliconfigv1.ConnectionCleanup) error {
	var retErr error
	if cfg := cleanup.GetDns().GetWindows(); cfg != nil {
		retErr = errors.Join(retErr, reconcileWindowsDNS(cfg))
	}
	if cfg := cleanup.GetDevice(); cfg != nil {
		retErr = errors.Join(retErr, reconcileWindowsDevice(cfg))
	}
	return retErr
}

func reconcileWindowsDevice(cfg *cliconfigv1.ConnectionCleanup_Device) error {
	if cfg == nil || cfg.Name == "" {
		return nil
	}
	name := cfg.Name
	if cfg.Guid != "" {
		guid, err := windows.GUIDFromString(cfg.Guid)
		if err != nil {
			return err
		}
		luid, err := winipcfg.LUIDFromGUID(&guid)
		if err != nil {
			if isWindowsNotFound(err) {
				return nil
			}
			return err
		}
		iface, err := luid.Interface()
		if err != nil {
			if isWindowsNotFound(err) {
				return nil
			}
			return err
		}
		name = iface.Alias()
	}
	var err error
	switch cfg.Type {
	case cliconfigv1.ConnectionCleanup_Device_WINDOWS_WIREGUARD:
		var adapter *driver.Adapter
		adapter, err = driver.OpenAdapter(name)
		if err == nil {
			err = adapter.Close()
		}
	case cliconfigv1.ConnectionCleanup_Device_WINDOWS_WINTUN:
		var adapter *wintun.Adapter
		adapter, err = wintun.OpenAdapter(name)
		if err == nil {
			err = adapter.Close()
		}
	default:
		return nil
	}
	if isWindowsNotFound(err) {
		return nil
	}
	return err
}

func isWindowsNotFound(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_NOT_FOUND)
}

func reconcileWindowsDNS(cfg *cliconfigv1.ConnectionCleanup_DNS_Windows) error {
	if cfg == nil || cfg.NrptRulePath == "" || cfg.NrptMarker == "" {
		return nil
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, cfg.NrptRulePath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	comment, _, getErr := key.GetStringValue("Comment")
	closeErr := key.Close()
	if getErr != nil || comment != cfg.NrptMarker {
		return closeErr
	}
	return errors.Join(closeErr, registry.DeleteKey(registry.LOCAL_MACHINE, cfg.NrptRulePath))
}
