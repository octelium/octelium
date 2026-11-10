//go:build unix

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

package cliutils

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenDBAsRootForInvokingUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test needs to run as root")
	}

	usr, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("This test requires the nobody OS user")
	}
	uid, err := strconv.Atoi(usr.Uid)
	require.NoError(t, err)
	gid, err := strconv.Atoi(usr.Gid)
	require.NoError(t, err)

	prev := dbC
	t.Cleanup(func() { dbC = prev })

	for _, key := range []string{"SUDO_USER", "PKEXEC_UID"} {
		t.Setenv(key, "")
	}
	t.Setenv("SUDO_UID", usr.Uid)

	assertOwner := func(t *testing.T, filePath string, uid, gid int) {
		info, err := os.Lstat(filePath)
		require.NoError(t, err)
		st := info.Sys().(*syscall.Stat_t)
		assert.Equal(t, uint32(uid), st.Uid, "path=%s", filePath)
		assert.Equal(t, uint32(gid), st.Gid, "path=%s", filePath)
	}

	dir := t.TempDir()
	usrHome := filepath.Join(dir, "home")
	require.NoError(t, os.Mkdir(usrHome, 0700))
	require.NoError(t, os.Chown(usrHome, uid, gid))
	dbDir := filepath.Join(usrHome, ".config", "octelium")

	require.NoError(t, OpenDB(dbDir))
	require.NoError(t, GetDB().Migrate())
	require.NoError(t, GetDB().SetSessionToken("example.com", &authv1.SessionToken{
		AccessToken: "token",
	}))

	for _, filePath := range []string{
		filepath.Dir(dbDir),
		dbDir,
		filepath.Join(dbDir, "octelium.db"),
		filepath.Join(dbDir, "octelium.db.lock"),
	} {
		assertOwner(t, filePath, uid, gid)
	}

	rootDir := filepath.Join(dir, "root", "octelium")
	require.NoError(t, OpenDB(rootDir))
	require.NoError(t, GetDB().Migrate())

	for _, filePath := range []string{
		filepath.Dir(rootDir),
		rootDir,
		filepath.Join(rootDir, "octelium.db"),
		filepath.Join(rootDir, "octelium.db.lock"),
	} {
		info, err := os.Lstat(filePath)
		require.NoError(t, err)
		assert.Equal(t, uint32(0), info.Sys().(*syscall.Stat_t).Uid, "path=%s", filePath)
	}

	t.Setenv("SUDO_UID", "")
	otherHome := filepath.Join(dir, "other")
	require.NoError(t, os.Mkdir(otherHome, 0700))
	require.NoError(t, os.Chown(otherHome, uid, gid))
	require.NoError(t, OpenDB(filepath.Join(otherHome, "octelium")))
	require.NoError(t, GetDB().Migrate())

	info, err := os.Lstat(filepath.Join(otherHome, "octelium", "octelium.db"))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), info.Sys().(*syscall.Stat_t).Uid)
}
