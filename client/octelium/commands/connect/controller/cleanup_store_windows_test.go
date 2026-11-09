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
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func newTestUnownedDir(t *testing.T) string {
	t.Helper()
	target := t.TempDir()
	dir := filepath.Join(t.TempDir(), "octelium")
	out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, target).CombinedOutput()
	require.NoError(t, err, string(out))
	return dir
}

func assertTestCleanupSameOwner(t *testing.T, expected, actual os.FileInfo) {
	t.Helper()
	assert.True(t, os.SameFile(expected, actual))
}

func TestGetCleanupStoreDir(t *testing.T) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(programFiles, "Octelium", "cleanup"), getCleanupStoreDir())
}

func TestIsOwnedPath(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, nil, 0600))
	junction := newTestUnownedDir(t)

	assert.True(t, isOwnedPath(dir, os.ModeDir))
	assert.True(t, isOwnedPath(file, 0))
	assert.False(t, isOwnedPath(file, os.ModeDir))
	assert.False(t, isOwnedPath(dir, 0))
	assert.False(t, isOwnedPath(junction, os.ModeDir))
	assert.False(t, isOwnedPath(filepath.Join(dir, "missing"), os.ModeDir))
}

func TestIsOwnedDBPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "octelium")
	require.NoError(t, os.Mkdir(dir, 0700))
	dbPath := filepath.Join(dir, "octelium.db")
	assert.True(t, isOwnedDBPath(dbPath))
	require.NoError(t, os.WriteFile(dbPath, nil, 0600))
	assert.True(t, isOwnedDBPath(dbPath))
	assert.False(t, isOwnedDBPath(filepath.Join(newTestUnownedDir(t), "octelium.db")))

	fileDir := filepath.Join(t.TempDir(), "octelium")
	require.NoError(t, os.Mkdir(fileDir, 0700))
	require.NoError(t, os.Mkdir(filepath.Join(fileDir, "octelium.db"), 0700))
	assert.False(t, isOwnedDBPath(filepath.Join(fileDir, "octelium.db")))
}
