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

package db

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTestOwner(t *testing.T) *Owner {
	if os.Geteuid() == 0 {
		return &Owner{
			UID: 4321,
			GID: 4322,
		}
	}

	groups, err := os.Getgroups()
	require.NoError(t, err)

	for _, gid := range groups {
		if gid != os.Getgid() {
			return &Owner{
				UID: os.Getuid(),
				GID: gid,
			}
		}
	}

	t.Skip("This test needs to run as root or with a supplementary OS group")
	return nil
}

func getTestFileOwner(t *testing.T, filePath string) (uint32, uint32) {
	info, err := os.Lstat(filePath)
	require.NoError(t, err)

	st := info.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}

func assertTestFileOwner(t *testing.T, filePath string, uid, gid int) {
	fileUID, fileGID := getTestFileOwner(t, filePath)
	assert.Equal(t, uint32(uid), fileUID, "path=%s", filePath)
	assert.Equal(t, uint32(gid), fileGID, "path=%s", filePath)
}

func newTestOwnerHome(t *testing.T, owner *Owner) string {
	ret := filepath.Join(t.TempDir(), "home")
	require.NoError(t, os.Mkdir(ret, 0700))
	require.NoError(t, os.Chown(ret, owner.UID, -1))
	return ret
}

func TestFSDBOwnerNewEntries(t *testing.T) {
	ctx := context.Background()
	owner := getTestOwner(t)

	usrHome := newTestOwnerHome(t, owner)
	homeUID, homeGID := getTestFileOwner(t, usrHome)
	dbDir := filepath.Join(usrHome, ".config", "octelium")
	dbPath := filepath.Join(dbDir, "octelium.db")
	lockPath := filepath.Join(dbDir, "octelium.db.lock")

	db, err := newFSDB(&Opts{
		Path:  dbDir + "/",
		Owner: owner,
	})
	require.NoError(t, err)
	require.NoError(t, db.migrate(ctx))
	require.NoError(t, db.set(ctx, "example.com", &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	}))

	for _, itm := range []struct {
		path string
		mode os.FileMode
	}{
		{path: filepath.Dir(dbDir), mode: 0755},
		{path: dbDir, mode: 0700},
		{path: dbPath, mode: 0600},
		{path: lockPath, mode: 0600},
	} {
		assertTestFileOwner(t, itm.path, owner.UID, owner.GID)
		info, err := os.Stat(itm.path)
		require.NoError(t, err)
		assert.Equal(t, itm.mode, info.Mode().Perm(), "path=%s", itm.path)
	}

	uid, gid := getTestFileOwner(t, usrHome)
	assert.Equal(t, homeUID, uid)
	assert.Equal(t, homeGID, gid)

	require.NoError(t, os.Remove(dbPath))
	sessTkn := &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	}
	require.NoError(t, db.set(ctx, "example.org", sessTkn))
	assertTestFileOwner(t, dbPath, owner.UID, owner.GID)

	itm, err := db.get(ctx, "example.org")
	require.NoError(t, err)
	assert.Equal(t, sessTkn.AccessToken, itm.SessionToken.AccessToken)

	require.NoError(t, os.Remove(dbPath))
	require.NoError(t, os.Remove(lockPath))
	require.NoError(t, os.WriteFile(dbPath, nil, 0600))
	require.NoError(t, os.WriteFile(lockPath, nil, 0600))
	dbUID, dbGID := getTestFileOwner(t, dbPath)
	lockUID, lockGID := getTestFileOwner(t, lockPath)

	db, err = newFSDB(&Opts{
		Path:  dbDir,
		Owner: owner,
	})
	require.NoError(t, err)
	require.NoError(t, db.migrate(ctx))
	require.NoError(t, db.set(ctx, "example.com", sessTkn))

	uid, gid = getTestFileOwner(t, dbPath)
	assert.Equal(t, dbUID, uid)
	assert.Equal(t, dbGID, gid)
	uid, gid = getTestFileOwner(t, lockPath)
	assert.Equal(t, lockUID, uid)
	assert.Equal(t, lockGID, gid)

	itm, err = db.get(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, sessTkn.AccessToken, itm.SessionToken.AccessToken)
}

func TestFSDBOwnerSymlinkedFiles(t *testing.T) {
	ctx := context.Background()
	owner := getTestOwner(t)

	usrHome := newTestOwnerHome(t, owner)
	dbDir := filepath.Join(usrHome, ".config", "octelium")
	dataDir := filepath.Join(usrHome, "data")

	db, err := newFSDB(&Opts{
		Path:  dbDir,
		Owner: owner,
	})
	require.NoError(t, err)
	require.NoError(t, db.migrate(ctx))

	require.NoError(t, os.Mkdir(dataDir, 0700))
	require.NoError(t, os.Chown(dataDir, owner.UID, -1))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "octelium.db"), nil, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "octelium.db.lock"), nil, 0600))
	dbUID, dbGID := getTestFileOwner(t, filepath.Join(dataDir, "octelium.db"))

	for _, name := range []string{"octelium.db", "octelium.db.lock"} {
		require.NoError(t, os.Remove(filepath.Join(dbDir, name)))
		require.NoError(t, os.Symlink(filepath.Join(dataDir, name), filepath.Join(dbDir, name)))
	}

	db, err = newFSDB(&Opts{
		Path:  dbDir,
		Owner: owner,
	})
	require.NoError(t, err)
	require.NoError(t, db.migrate(ctx))

	sessTkn := &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	}
	require.NoError(t, db.set(ctx, "example.com", sessTkn))

	for _, name := range []string{"octelium.db", "octelium.db.lock"} {
		info, err := os.Lstat(filepath.Join(dbDir, name))
		require.NoError(t, err)
		assert.True(t, info.Mode()&os.ModeSymlink != 0)

		uid, gid := getTestFileOwner(t, filepath.Join(dataDir, name))
		assert.Equal(t, dbUID, uid)
		assert.Equal(t, dbGID, gid)
	}

	itm, err := db.get(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, sessTkn.AccessToken, itm.SessionToken.AccessToken)
}

func TestOwnerSetOwnerAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test needs to run as root")
	}

	owner := getTestOwner(t)
	dir := t.TempDir()
	usrHome := newTestOwnerHome(t, owner)
	filePath := filepath.Join(usrHome, "file")
	movedPath := filepath.Join(usrHome, "moved")
	sentinel := filepath.Join(dir, "sentinel")
	require.NoError(t, os.WriteFile(sentinel, nil, 0600))
	require.NoError(t, os.WriteFile(filePath, nil, 0600))

	homeDir, err := os.Open(usrHome)
	require.NoError(t, err)
	defer homeDir.Close()

	f, err := os.Open(filePath)
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, os.Rename(filePath, movedPath))
	require.NoError(t, os.Symlink(sentinel, filePath))

	owner.setOwner(homeDir, f)

	assertTestFileOwner(t, movedPath, owner.UID, owner.GID)
	uid, _ := getTestFileOwner(t, sentinel)
	assert.Equal(t, uint32(0), uid)

	rootDir, err := os.Open(dir)
	require.NoError(t, err)
	defer rootDir.Close()

	f2, err := os.Open(sentinel)
	require.NoError(t, err)
	defer f2.Close()

	owner.setOwner(rootDir, f2)

	uid, _ = getTestFileOwner(t, sentinel)
	assert.Equal(t, uint32(0), uid)
}

func TestFSDBOwnerAsRootDoesNotFollowLinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test needs to run as root")
	}

	ctx := context.Background()
	owner := getTestOwner(t)

	newTestDBDir := func(t *testing.T) (string, string) {
		usrHome := newTestOwnerHome(t, owner)
		dbDir := filepath.Join(usrHome, ".config", "octelium")
		_, err := newFSDB(&Opts{
			Path:  dbDir,
			Owner: owner,
		})
		require.NoError(t, err)
		require.NoError(t, os.Remove(filepath.Join(dbDir, "octelium.db.lock")))
		return filepath.Dir(usrHome), dbDir
	}

	newSentinel := func(t *testing.T, dir string, content string) string {
		ret := filepath.Join(dir, "sentinel")
		require.NoError(t, os.WriteFile(ret, []byte(content), 0640))
		return ret
	}

	assertNotOwned := func(t *testing.T, filePath string) {
		uid, gid := getTestFileOwner(t, filePath)
		assert.Equal(t, uint32(0), uid, "path=%s", filePath)
		assert.NotEqual(t, uint32(owner.GID), gid, "path=%s", filePath)
	}

	assertSentinel := func(t *testing.T, filePath string) {
		assertNotOwned(t, filePath)
		info, err := os.Lstat(filePath)
		require.NoError(t, err)
		assert.True(t, info.Mode().IsRegular())
		assert.Equal(t, os.FileMode(0640), info.Mode().Perm())
	}

	doSet := func(t *testing.T, dbDir string) {
		db, err := newFSDB(&Opts{
			Path:  dbDir,
			Owner: owner,
		})
		require.NoError(t, err)
		require.NoError(t, db.migrate(ctx))

		sessTkn := &authv1.SessionToken{
			AccessToken: utilrand.GetRandomString(32),
		}
		require.NoError(t, db.set(ctx, "example.com", sessTkn))

		itm, err := db.get(ctx, "example.com")
		require.NoError(t, err)
		assert.Equal(t, sessTkn.AccessToken, itm.SessionToken.AccessToken)
	}

	t.Run("lock symlink", func(t *testing.T) {
		dir, dbDir := newTestDBDir(t)
		sentinel := newSentinel(t, dir, "sentinel")
		require.NoError(t, os.Symlink(sentinel, filepath.Join(dbDir, "octelium.db.lock")))

		doSet(t, dbDir)

		assertSentinel(t, sentinel)
		content, err := os.ReadFile(sentinel)
		require.NoError(t, err)
		assert.Equal(t, "sentinel", string(content))
		assertTestFileOwner(t, filepath.Join(dbDir, "octelium.db"), owner.UID, owner.GID)
	})

	t.Run("db symlink", func(t *testing.T) {
		dir, dbDir := newTestDBDir(t)
		sentinel := newSentinel(t, dir, "")
		require.NoError(t, os.Symlink(sentinel, filepath.Join(dbDir, "octelium.db")))

		doSet(t, dbDir)

		assertSentinel(t, sentinel)
		assertTestFileOwner(t, filepath.Join(dbDir, "octelium.db.lock"), owner.UID, owner.GID)
	})

	t.Run("db hard link", func(t *testing.T) {
		dir, dbDir := newTestDBDir(t)
		sentinel := newSentinel(t, dir, "")
		require.NoError(t, os.Link(sentinel, filepath.Join(dbDir, "octelium.db")))

		doSet(t, dbDir)

		assertSentinel(t, sentinel)
	})

	t.Run("dangling db symlink", func(t *testing.T) {
		dir, dbDir := newTestDBDir(t)
		target := filepath.Join(dir, "target")
		require.NoError(t, os.Symlink(target, filepath.Join(dbDir, "octelium.db")))

		doSet(t, dbDir)

		assertNotOwned(t, target)
	})

	t.Run("existing root files", func(t *testing.T) {
		_, dbDir := newTestDBDir(t)
		for _, name := range []string{"octelium.db", "octelium.db.lock"} {
			require.NoError(t, os.WriteFile(filepath.Join(dbDir, name), nil, 0600))
		}

		doSet(t, dbDir)

		for _, name := range []string{"octelium.db", "octelium.db.lock"} {
			assertNotOwned(t, filepath.Join(dbDir, name))
		}
	})

	t.Run("directory symlink", func(t *testing.T) {
		usrHome := newTestOwnerHome(t, owner)
		rootDir := filepath.Join(filepath.Dir(usrHome), "root")
		require.NoError(t, os.Mkdir(rootDir, 0755))
		require.NoError(t, os.Symlink(rootDir, filepath.Join(usrHome, ".config")))
		dbDir := filepath.Join(usrHome, ".config", "octelium")

		doSet(t, dbDir)

		for _, filePath := range []string{
			rootDir,
			filepath.Join(rootDir, "octelium"),
			filepath.Join(rootDir, "octelium", "octelium.db"),
			filepath.Join(rootDir, "octelium", "octelium.db.lock"),
		} {
			assertNotOwned(t, filePath)
		}
	})

	t.Run("root parent", func(t *testing.T) {
		stateDir := t.TempDir()
		dbDir := filepath.Join(stateDir, "users", "4321")

		doSet(t, dbDir)

		for _, filePath := range []string{
			filepath.Dir(dbDir),
			dbDir,
			filepath.Join(dbDir, "octelium.db"),
			filepath.Join(dbDir, "octelium.db.lock"),
		} {
			assertNotOwned(t, filePath)
		}
	})
}
