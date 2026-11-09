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

package controller

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/octelium/octelium/client/common/cliutils"
)

func isPrivilegedProcess() bool {
	return os.Geteuid() == 0
}

func getCleanupStoreDir() string {
	if cliutils.IsDarwin() {
		return "/Library/Application Support/Octelium/cleanup"
	}

	return "/var/lib/octelium/cleanup"
}

func getOwnedPathMode(filePath string, typ os.FileMode) (os.FileMode, bool) {
	fi, err := os.Lstat(filePath)
	if err != nil || fi.Mode().Type() != typ {
		return 0, false
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return 0, false
	}

	return fi.Mode(), true
}

func isOwnedPath(filePath string, typ os.FileMode) bool {
	mode, ok := getOwnedPathMode(filePath, typ)
	return ok && mode.Perm()&0o022 == 0
}

func isOwnedDBPath(dbPath string) bool {
	if _, err := os.Lstat(dbPath); !os.IsNotExist(err) && !isOwnedPath(dbPath, 0) {
		return false
	}

	dir := filepath.Dir(dbPath)
	if !isOwnedPath(dir, os.ModeDir) {
		return false
	}

	mode, ok := getOwnedPathMode(filepath.Dir(dir), os.ModeDir)
	return ok && (mode.Perm()&0o022 == 0 || mode&os.ModeSticky != 0)
}
