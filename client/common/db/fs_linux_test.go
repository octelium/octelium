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
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func newTestSessionToken() *authv1.SessionToken {
	return &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	}
}

func TestFSDBPreservesFileAttributes(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "octelium.db")

	db, err := newFSDB(&Opts{Path: tmpDir})
	assert.Nil(t, err)
	assert.Nil(t, db.migrate(ctx))
	assert.Nil(t, os.Chmod(dbPath, 0640))

	before, err := os.Stat(dbPath)
	assert.Nil(t, err)

	assert.Nil(t, db.set(ctx, "example.com", newTestSessionToken()))

	after, err := os.Stat(dbPath)
	assert.Nil(t, err)

	assert.False(t, os.SameFile(before, after))
	assert.Equal(t, before.Mode(), after.Mode())
	assert.Equal(t, before.Sys().(*syscall.Stat_t).Uid, after.Sys().(*syscall.Stat_t).Uid)
	assert.Equal(t, before.Sys().(*syscall.Stat_t).Gid, after.Sys().(*syscall.Stat_t).Gid)

	entries, err := os.ReadDir(tmpDir)
	assert.Nil(t, err)
	for _, entry := range entries {
		assert.False(t, strings.HasPrefix(entry.Name(), "octelium.db.tmp"))
	}
}

func TestReplaceFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "state")

	assert.Nil(t, replaceFile(filePath, []byte("first")))

	fi, err := os.Stat(filePath)
	assert.Nil(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())

	assert.Nil(t, os.Chmod(filePath, 0640))
	assert.Nil(t, replaceFile(filePath, []byte("second")))

	content, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, []byte("second"), content)

	after, err := os.Stat(filePath)
	assert.Nil(t, err)
	assert.False(t, os.SameFile(fi, after))
	assert.Equal(t, os.FileMode(0640), after.Mode().Perm())

	entries, err := os.ReadDir(tmpDir)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(entries))
}

func TestFSDBReplacePreservesMode(t *testing.T) {
	ctx := context.Background()

	for _, key := range [][]byte{nil, utilrand.GetRandomBytesMust(32)} {
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "octelium.db")

		db, err := newFSDB(&Opts{Path: tmpDir, EncryptionKey: key})
		assert.Nil(t, err)
		assert.Nil(t, db.migrate(ctx))
		assert.Nil(t, os.Chmod(dbPath, 0640))

		before, err := os.Stat(dbPath)
		assert.Nil(t, err)

		sessTkn := newTestSessionToken()
		assert.Nil(t, db.set(ctx, "example.com", sessTkn))

		after, err := os.Stat(dbPath)
		assert.Nil(t, err)
		assert.False(t, os.SameFile(before, after))
		assert.Equal(t, os.FileMode(0640), after.Mode().Perm())

		itm, err := db.get(ctx, "example.com")
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(sessTkn, itm.SessionToken))
	}
}

func TestFSDBReplaceFallbackHardLink(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "octelium.db")
	linkPath := filepath.Join(tmpDir, "octelium.db.link")

	db, err := newFSDB(&Opts{Path: tmpDir})
	assert.Nil(t, err)
	assert.Nil(t, db.migrate(ctx))
	assert.Nil(t, os.Link(dbPath, linkPath))

	before, err := os.Stat(dbPath)
	assert.Nil(t, err)

	sessTkn := newTestSessionToken()
	assert.Nil(t, db.set(ctx, "example.com", sessTkn))

	after, err := os.Stat(dbPath)
	assert.Nil(t, err)
	assert.True(t, os.SameFile(before, after))

	dbContent, err := os.ReadFile(dbPath)
	assert.Nil(t, err)
	linkContent, err := os.ReadFile(linkPath)
	assert.Nil(t, err)
	assert.Equal(t, dbContent, linkContent)

	itm, err := db.get(ctx, "example.com")
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(sessTkn, itm.SessionToken))
}

func TestFSDBReplaceFallbackXattr(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "octelium.db")

	db, err := newFSDB(&Opts{Path: tmpDir})
	assert.Nil(t, err)
	assert.Nil(t, db.migrate(ctx))

	if err := unix.Setxattr(dbPath, "user.octelium", []byte("test"), 0); err != nil {
		t.Skipf("Extended attributes are not supported: %+v", err)
	}

	before, err := os.Stat(dbPath)
	assert.Nil(t, err)

	sessTkn := newTestSessionToken()
	assert.Nil(t, db.set(ctx, "example.com", sessTkn))

	after, err := os.Stat(dbPath)
	assert.Nil(t, err)
	assert.True(t, os.SameFile(before, after))

	val := make([]byte, 16)
	sz, err := unix.Getxattr(dbPath, "user.octelium", val)
	assert.Nil(t, err)
	assert.Equal(t, []byte("test"), val[:sz])

	itm, err := db.get(ctx, "example.com")
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(sessTkn, itm.SessionToken))
}

func TestFSDBReplaceFallbackReadOnlyDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("Skipping the read-only directory check as root")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "octelium.db")

	db, err := newFSDB(&Opts{Path: tmpDir})
	assert.Nil(t, err)
	assert.Nil(t, db.migrate(ctx))

	before, err := os.Stat(dbPath)
	assert.Nil(t, err)

	assert.Nil(t, os.Chmod(tmpDir, 0500))
	t.Cleanup(func() {
		os.Chmod(tmpDir, 0700)
	})

	sessTkn := newTestSessionToken()
	assert.Nil(t, db.set(ctx, "example.com", sessTkn))

	after, err := os.Stat(dbPath)
	assert.Nil(t, err)
	assert.True(t, os.SameFile(before, after))

	itm, err := db.get(ctx, "example.com")
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(sessTkn, itm.SessionToken))
}

func TestFSDBReplaceFallbackDanglingSymlink(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	realPath := filepath.Join(tmpDir, "real", "octelium.db")
	linkDir := filepath.Join(tmpDir, "link")
	assert.Nil(t, os.MkdirAll(filepath.Dir(realPath), 0700))
	assert.Nil(t, os.MkdirAll(linkDir, 0700))
	assert.Nil(t, os.Symlink(realPath, filepath.Join(linkDir, "octelium.db")))

	db, err := newFSDB(&Opts{Path: linkDir})
	assert.Nil(t, err)

	sessTkn := newTestSessionToken()
	assert.Nil(t, db.set(ctx, "example.com", sessTkn))

	fi, err := os.Lstat(filepath.Join(linkDir, "octelium.db"))
	assert.Nil(t, err)
	assert.True(t, fi.Mode()&os.ModeSymlink != 0)

	_, err = os.Stat(realPath)
	assert.Nil(t, err)

	itm, err := db.get(ctx, "example.com")
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(sessTkn, itm.SessionToken))
}

func TestFSDBReplaceAsRootPreservesOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test needs to run as root")
	}

	const uid = 1000
	const gid = 1000

	if _, err := user.LookupId(fmt.Sprintf("%d", uid)); err != nil {
		t.Skip("This test needs an unprivileged OS user")
	}

	ctx := context.Background()

	for _, key := range [][]byte{nil, utilrand.GetRandomBytesMust(32)} {
		dbDir := t.TempDir()
		dbPath := filepath.Join(dbDir, "octelium.db")
		assert.Nil(t, os.Chown(dbDir, uid, gid))

		db, err := newFSDB(&Opts{Path: dbDir, EncryptionKey: key})
		assert.Nil(t, err)
		assert.Nil(t, db.migrate(ctx))
		assert.Nil(t, os.Chown(dbPath, uid, gid))

		before, err := os.Stat(dbPath)
		assert.Nil(t, err)

		sessTkn := newTestSessionToken()
		assert.Nil(t, db.set(ctx, "example.com", sessTkn))

		after, err := os.Stat(dbPath)
		assert.Nil(t, err)
		assert.False(t, os.SameFile(before, after))
		assert.Equal(t, uint32(uid), after.Sys().(*syscall.Stat_t).Uid)
		assert.Equal(t, uint32(gid), after.Sys().(*syscall.Stat_t).Gid)
		assert.Equal(t, os.FileMode(0600), after.Mode().Perm())

		itm, err := db.get(ctx, "example.com")
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(sessTkn, itm.SessionToken))
	}
}
