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
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func isPrivilegedProcess() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func getCleanupStoreDir() string {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return ""
	}

	return filepath.Join(programFiles, "Octelium", "cleanup")
}

func isOwnedPath(filePath string, typ os.FileMode) bool {
	fi, err := os.Lstat(filePath)
	if err != nil || fi.Mode().Type() != typ {
		return false
	}

	sd, err := windows.GetNamedSecurityInfo(filePath, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}

	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false
	}

	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return true
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && owner.Equals(user.User.Sid)
}

func isOwnedDBPath(dbPath string) bool {
	if _, err := os.Lstat(dbPath); !os.IsNotExist(err) && !isOwnedPath(dbPath, 0) {
		return false
	}

	return isOwnedPath(filepath.Dir(dbPath), os.ModeDir)
}
