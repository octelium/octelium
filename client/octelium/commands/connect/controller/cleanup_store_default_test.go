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
	"runtime"
	"syscall"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCleanupNobodyID = 65534

func newTestUnownedDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "octelium")
	require.NoError(t, os.Mkdir(dir, 0700))
	require.NoError(t, os.Chmod(dir, 0777))
	return dir
}

func assertTestCleanupSameOwner(t *testing.T, expected, actual os.FileInfo) {
	t.Helper()
	expectedSt := expected.Sys().(*syscall.Stat_t)
	actualSt := actual.Sys().(*syscall.Stat_t)
	assert.Equal(t, expectedSt.Uid, actualSt.Uid)
	assert.Equal(t, expectedSt.Gid, actualSt.Gid)
}

func newTestCleanupPath(t *testing.T, filePath string, mode os.FileMode) string {
	t.Helper()
	if mode.IsDir() {
		require.NoError(t, os.Mkdir(filePath, 0700))
	} else {
		require.NoError(t, os.WriteFile(filePath, nil, 0600))
	}
	require.NoError(t, os.Chmod(filePath, mode))
	return filePath
}

func TestIsPrivilegedProcess(t *testing.T) {
	assert.Equal(t, os.Geteuid() == 0, isPrivilegedProcess())
}

func TestGetCleanupStoreDir(t *testing.T) {
	switch runtime.GOOS {
	case "darwin":
		assert.Equal(t, "/Library/Application Support/Octelium/cleanup", getCleanupStoreDir())
	default:
		assert.Equal(t, "/var/lib/octelium/cleanup", getCleanupStoreDir())
	}
}

func TestIsOwnedPath(t *testing.T) {
	dir := t.TempDir()
	ownedDir := newTestCleanupPath(t, filepath.Join(dir, "owned"), os.ModeDir|0700)
	ownedFile := newTestCleanupPath(t, filepath.Join(dir, "file"), 0644)
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(ownedDir, link))

	assert.True(t, isOwnedPath(ownedDir, os.ModeDir))
	assert.True(t, isOwnedPath(newTestCleanupPath(t, filepath.Join(dir, "dir-0755"), os.ModeDir|0755), os.ModeDir))
	assert.True(t, isOwnedPath(ownedFile, 0))
	assert.False(t, isOwnedPath(newTestCleanupPath(t, filepath.Join(dir, "dir-0770"), os.ModeDir|0770), os.ModeDir))
	assert.False(t, isOwnedPath(newTestCleanupPath(t, filepath.Join(dir, "dir-0707"), os.ModeDir|0707), os.ModeDir))
	assert.False(t, isOwnedPath(newTestCleanupPath(t, filepath.Join(dir, "dir-1777"), os.ModeDir|os.ModeSticky|0777), os.ModeDir))
	assert.False(t, isOwnedPath(newTestCleanupPath(t, filepath.Join(dir, "file-0664"), 0664), 0))
	assert.False(t, isOwnedPath(ownedFile, os.ModeDir))
	assert.False(t, isOwnedPath(ownedDir, 0))
	assert.False(t, isOwnedPath(link, os.ModeDir))
	assert.False(t, isOwnedPath(filepath.Join(dir, "missing"), os.ModeDir))

	if os.Geteuid() != 0 {
		return
	}
	require.NoError(t, os.Chown(ownedDir, testCleanupNobodyID, testCleanupNobodyID))
	require.NoError(t, os.Chown(ownedFile, testCleanupNobodyID, testCleanupNobodyID))
	assert.False(t, isOwnedPath(ownedDir, os.ModeDir))
	assert.False(t, isOwnedPath(ownedFile, 0))
}

func TestIsOwnedDBPath(t *testing.T) {
	newDBPath := func(t *testing.T, parentMode, dirMode, fileMode os.FileMode) string {
		parent := newTestCleanupPath(t, filepath.Join(t.TempDir(), "parent"), os.ModeDir|parentMode)
		dir := newTestCleanupPath(t, filepath.Join(parent, "octelium"), os.ModeDir|dirMode)
		dbPath := filepath.Join(dir, "octelium.db")
		if fileMode != 0 {
			newTestCleanupPath(t, dbPath, fileMode)
		}
		return dbPath
	}

	assert.True(t, isOwnedDBPath(newDBPath(t, 0700, 0700, 0600)))
	assert.True(t, isOwnedDBPath(newDBPath(t, 0755, 0700, 0)))
	assert.True(t, isOwnedDBPath(newDBPath(t, os.ModeSticky|0777, 0700, 0600)))
	assert.False(t, isOwnedDBPath(newDBPath(t, 0777, 0700, 0600)))
	assert.False(t, isOwnedDBPath(newDBPath(t, 0700, 0777, 0600)))
	assert.False(t, isOwnedDBPath(newDBPath(t, 0700, os.ModeSticky|0777, 0600)))
	assert.False(t, isOwnedDBPath(newDBPath(t, 0700, 0700, 0666)))

	dbPath := newDBPath(t, 0700, 0700, 0)
	target := newTestCleanupPath(t, filepath.Join(t.TempDir(), "target"), 0600)
	require.NoError(t, os.Symlink(target, dbPath))
	assert.False(t, isOwnedDBPath(dbPath))

	dbPath = newDBPath(t, 0700, 0700, 0600)
	link := filepath.Join(filepath.Dir(filepath.Dir(dbPath)), "link")
	require.NoError(t, os.Symlink(filepath.Dir(dbPath), link))
	assert.False(t, isOwnedDBPath(filepath.Join(link, "octelium.db")))

	if os.Geteuid() != 0 {
		return
	}
	for _, idx := range []int{0, 1, 2} {
		dbPath := newDBPath(t, 0755, 0700, 0600)
		filePath := []string{dbPath, filepath.Dir(dbPath), filepath.Dir(filepath.Dir(dbPath))}[idx]
		require.NoError(t, os.Chown(filePath, testCleanupNobodyID, testCleanupNobodyID))
		assert.False(t, isOwnedDBPath(dbPath), filePath)
	}
}

func TestNewCleanupStoreForOtherUserDB(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root to create the database of another OS user")
	}
	dir := filepath.Join(t.TempDir(), "home", "octelium")
	userDB := newTestCleanupStoreDB(t, dir)
	for _, filePath := range []string{userDB.Path(), userDB.Path() + ".lock", dir, filepath.Dir(dir)} {
		require.NoError(t, os.Chown(filePath, testCleanupNobodyID, testCleanupNobodyID))
	}
	storeDir := filepath.Join(t.TempDir(), "cleanup")
	s := newCleanupStore(userDB, &cleanupStoreOpts{dir: storeDir, isPrivileged: true})
	require.NotNil(t, s.dbC)
	assert.Equal(t, userDB, s.userDB)
	assert.True(t, s.isPrivileged)

	require.NoError(t, userDB.SetConnectionCleanup("example.com", &cliconfigv1.ConnectionCleanup{Id: "legacy"}))
	userFI, err := os.Stat(userDB.Path())
	require.NoError(t, err)
	s.reconcile("example.com")
	_, err = userDB.GetConnectionCleanup("example.com")
	assert.True(t, userDB.ErrorIsNotFound(err))
	fi, err := os.Stat(userDB.Path())
	require.NoError(t, err)
	assert.Equal(t, userFI.Mode(), fi.Mode())
	st := fi.Sys().(*syscall.Stat_t)
	assert.Equal(t, uint32(testCleanupNobodyID), st.Uid, "root must not take over the database of the user")
	assert.Equal(t, uint32(testCleanupNobodyID), st.Gid)
}
