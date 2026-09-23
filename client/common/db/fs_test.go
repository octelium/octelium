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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestFSDB(t *testing.T) {

	{
		tmpDir, err := os.MkdirTemp("", "octeliumdb-*")
		assert.Nil(t, err)
		db, err := newFSDB(&Opts{Path: tmpDir})
		assert.Nil(t, err)

		err = db.migrate(context.Background())
		assert.Nil(t, err)

		domain := "example.com"
		_, err = db.get(context.Background(), domain)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))

		sessTkn := &authv1.SessionToken{
			AccessToken: utilrand.GetRandomString(32),
		}
		err = db.set(context.Background(), domain, sessTkn)
		assert.Nil(t, err)

		state, err := db.get(context.Background(), domain)
		assert.Nil(t, err)
		assert.True(t, state.SessionTokenSetAt.IsValid())
		assert.True(t, time.Now().After(state.SessionTokenSetAt.AsTime()))

		assert.True(t, pbutils.IsEqual(sessTkn, state.SessionToken))

		err = db.delete(context.Background(), domain)
		assert.Nil(t, err)

		_, err = db.get(context.Background(), domain)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))

		os.RemoveAll(tmpDir)
	}

	{
		// No migration
		tmpDir, err := os.MkdirTemp("", "octeliumdb-*")
		assert.Nil(t, err)
		db, err := newFSDB(&Opts{Path: tmpDir})
		assert.Nil(t, err)

		domain := "example.com"

		sessTkn := &authv1.SessionToken{
			AccessToken: utilrand.GetRandomString(32),
		}
		err = db.set(context.Background(), domain, sessTkn)
		assert.Nil(t, err)

		state, err := db.get(context.Background(), domain)
		assert.Nil(t, err)
		assert.True(t, state.SessionTokenSetAt.IsValid())
		assert.True(t, time.Now().After(state.SessionTokenSetAt.AsTime()))

		assert.True(t, pbutils.IsEqual(sessTkn, state.SessionToken))

		err = db.delete(context.Background(), domain)
		assert.Nil(t, err)

		_, err = db.get(context.Background(), domain)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))

		os.RemoveAll(tmpDir)
	}
}

func TestFSDBConnectionCleanup(t *testing.T) {
	db, err := newFSDB(&Opts{Path: t.TempDir()})
	assert.Nil(t, err)
	assert.Nil(t, db.migrate(context.Background()))

	domain := "example.com"
	cleanup := &cliconfigv1.ConnectionCleanup{Id: "cleanup-id"}
	assert.Nil(t, db.setConnectionCleanup(context.Background(), domain, cleanup))
	assert.Nil(t, db.set(context.Background(), domain, &authv1.SessionToken{AccessToken: "token"}))

	state, err := db.get(context.Background(), domain)
	assert.Nil(t, err)
	assert.Equal(t, cleanup.Id, state.GetConnectionCleanup().GetId())
	assert.Nil(t, db.deleteConnectionCleanup(context.Background(), domain))
	state, err = db.get(context.Background(), domain)
	assert.Nil(t, err)
	assert.Equal(t, "token", state.GetSessionToken().GetAccessToken())
	assert.Nil(t, db.setConnectionCleanup(context.Background(), domain, cleanup))

	assert.Nil(t, db.delete(context.Background(), domain))
	state, err = db.get(context.Background(), domain)
	assert.Nil(t, err)
	assert.Nil(t, state.SessionToken)
	assert.Equal(t, cleanup.Id, state.GetConnectionCleanup().GetId())

	assert.Nil(t, db.deleteConnectionCleanup(context.Background(), domain))
	_, err = db.get(context.Background(), domain)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestFSDBConcurrentSameHandle(t *testing.T) {

	tmpDir, err := os.MkdirTemp("", "octeliumdb-*")
	assert.Nil(t, err)
	db, err := newFSDB(&Opts{Path: tmpDir})
	assert.Nil(t, err)

	err = db.migrate(context.Background())
	assert.Nil(t, err)

	n := 24

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sessTkn := &authv1.SessionToken{
				AccessToken: fmt.Sprintf("token-%d", i),
			}
			err := db.set(context.Background(), fmt.Sprintf("domain-%d.example.com", i), sessTkn)
			assert.Nil(t, err)
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		state, err := db.get(context.Background(), fmt.Sprintf("domain-%d.example.com", i))
		assert.Nil(t, err)
		assert.Equal(t, fmt.Sprintf("token-%d", i), state.SessionToken.AccessToken)
	}

	os.RemoveAll(tmpDir)
}

func TestFSDBConcurrentSeparateHandles(t *testing.T) {

	tmpDir, err := os.MkdirTemp("", "octeliumdb-*")
	assert.Nil(t, err)
	initDB, err := newFSDB(&Opts{Path: tmpDir})
	assert.Nil(t, err)

	err = initDB.migrate(context.Background())
	assert.Nil(t, err)

	n := 16

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			db, err := newFSDB(&Opts{Path: tmpDir})
			assert.Nil(t, err)

			sessTkn := &authv1.SessionToken{
				AccessToken: fmt.Sprintf("token-%d", i),
			}
			err = db.set(context.Background(), fmt.Sprintf("domain-%d.example.com", i), sessTkn)
			assert.Nil(t, err)
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		state, err := initDB.get(context.Background(), fmt.Sprintf("domain-%d.example.com", i))
		assert.Nil(t, err)
		assert.Equal(t, fmt.Sprintf("token-%d", i), state.SessionToken.AccessToken)
	}

	os.RemoveAll(tmpDir)
}

func TestFSDBPreservesFileIdentity(t *testing.T) {

	tmpDir, err := os.MkdirTemp("", "octeliumdb-*")
	assert.Nil(t, err)
	db, err := newFSDB(&Opts{Path: tmpDir})
	assert.Nil(t, err)

	err = db.migrate(context.Background())
	assert.Nil(t, err)

	dbPath := filepath.Join(tmpDir, "octelium.db")
	err = os.Chmod(dbPath, 0640)
	assert.Nil(t, err)

	before, err := os.Stat(dbPath)
	assert.Nil(t, err)

	err = db.set(context.Background(), "example.com", &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	})
	assert.Nil(t, err)

	after, err := os.Stat(dbPath)
	assert.Nil(t, err)

	assert.True(t, os.SameFile(before, after))
	assert.Equal(t, before.Mode(), after.Mode())

	entries, err := os.ReadDir(tmpDir)
	assert.Nil(t, err)
	for _, entry := range entries {
		assert.False(t, strings.HasPrefix(entry.Name(), "octelium.db.tmp"))
	}

	os.RemoveAll(tmpDir)
}

func TestFSDBReadNeverSeesPartialWrite(t *testing.T) {

	tmpDir, err := os.MkdirTemp("", "octeliumdb-*")
	assert.Nil(t, err)
	db, err := newFSDB(&Opts{Path: tmpDir})
	assert.Nil(t, err)

	err = db.migrate(context.Background())
	assert.Nil(t, err)

	domain := "stable.example.com"
	err = db.set(context.Background(), domain, &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	})
	assert.Nil(t, err)

	done := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			err := db.set(context.Background(), fmt.Sprintf("churn-%d.example.com", i),
				&authv1.SessionToken{
					AccessToken: utilrand.GetRandomString(4096),
				})
			assert.Nil(t, err)
		}
		close(done)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			_, err := db.get(context.Background(), domain)
			assert.Nil(t, err)
		}
	}()

	wg.Wait()

	os.RemoveAll(tmpDir)
}

func TestFSDBSymlinkedDBFile(t *testing.T) {

	tmpDir, err := os.MkdirTemp("", "octeliumdb-*")
	assert.Nil(t, err)

	realDir := filepath.Join(tmpDir, "real")
	linkDir := filepath.Join(tmpDir, "link")

	err = os.MkdirAll(realDir, 0700)
	assert.Nil(t, err)
	err = os.MkdirAll(linkDir, 0700)
	assert.Nil(t, err)

	realPath := filepath.Join(realDir, "octelium.db")
	err = os.WriteFile(realPath, nil, 0600)
	assert.Nil(t, err)
	err = os.Symlink(realPath, filepath.Join(linkDir, "octelium.db"))
	assert.Nil(t, err)

	db, err := newFSDB(&Opts{Path: linkDir})
	assert.Nil(t, err)

	domain := "example.com"
	sessTkn := &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	}
	err = db.set(context.Background(), domain, sessTkn)
	assert.Nil(t, err)

	state, err := db.get(context.Background(), domain)
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(sessTkn, state.SessionToken))

	fi, err := os.Lstat(filepath.Join(linkDir, "octelium.db"))
	assert.Nil(t, err)
	assert.True(t, fi.Mode()&os.ModeSymlink != 0)

	realBytes, err := os.ReadFile(realPath)
	assert.Nil(t, err)
	assert.True(t, len(realBytes) > 0)

	os.RemoveAll(tmpDir)
}

func TestFSDBOwner(t *testing.T) {
	dbDir := filepath.Join(t.TempDir(), "home", ".config", "octelium")

	db, err := newFSDB(&Opts{
		Path: dbDir,
		Owner: &Owner{
			UID: os.Getuid(),
			GID: os.Getgid(),
		},
	})
	assert.Nil(t, err)
	assert.Nil(t, db.migrate(context.Background()))

	info, err := os.Stat(dbDir)
	assert.Nil(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())

	info, err = os.Stat(filepath.Dir(dbDir))
	assert.Nil(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

	_, err = os.Stat(filepath.Join(dbDir, "octelium.db.lock"))
	assert.Nil(t, err)

	domain := "example.com"
	assert.Nil(t, db.set(context.Background(), domain, &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(8),
	}))

	info, err = os.Stat(filepath.Join(dbDir, "octelium.db"))
	assert.Nil(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	itm, err := db.get(context.Background(), domain)
	assert.Nil(t, err)
	assert.NotNil(t, itm.SessionToken)
}

func TestFSDBOwnerAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test needs to run as root")
	}

	const uid = 1000
	const gid = 1000

	if _, err := user.LookupId(fmt.Sprintf("%d", uid)); err != nil {
		t.Skip("This test needs an unprivileged OS user")
	}

	usrHome := filepath.Join(t.TempDir(), "home")
	assert.Nil(t, os.Mkdir(usrHome, 0700))
	assert.Nil(t, os.Chown(usrHome, uid, gid))

	dbDir := filepath.Join(usrHome, ".config", "octelium")

	db, err := newFSDB(&Opts{
		Path: dbDir,
		Owner: &Owner{
			UID: uid,
			GID: gid,
		},
	})
	assert.Nil(t, err)
	assert.Nil(t, db.migrate(context.Background()))
	assert.Nil(t, db.set(context.Background(), "example.com", &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(8),
	}))

	for _, filePath := range []string{
		filepath.Join(usrHome, ".config"),
		dbDir,
		filepath.Join(dbDir, "octelium.db"),
		filepath.Join(dbDir, "octelium.db.lock"),
	} {
		info, err := os.Stat(filePath)
		assert.Nil(t, err)
		assert.Equal(t, uint32(uid), info.Sys().(*syscall.Stat_t).Uid, "path=%s", filePath)
		assert.Equal(t, uint32(gid), info.Sys().(*syscall.Stat_t).Gid, "path=%s", filePath)
	}
}

func TestGetMissingDirs(t *testing.T) {
	dir := t.TempDir()

	{
		ret, err := getMissingDirs(dir)
		assert.Nil(t, err)
		assert.Equal(t, 0, len(ret))
	}

	{
		ret, err := getMissingDirs(filepath.Join(dir, "a", "b", "c"))
		assert.Nil(t, err)
		assert.Equal(t, []string{
			filepath.Join(dir, "a", "b", "c"),
			filepath.Join(dir, "a", "b"),
			filepath.Join(dir, "a"),
		}, ret)
	}
}

func TestFSDBEncrypted(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "octelium.db")
	key := utilrand.GetRandomBytesMust(32)

	db, err := newFSDB(&Opts{Path: tmpDir, EncryptionKey: key})
	assert.Nil(t, err)

	assert.Nil(t, db.migrate(ctx))

	rawBytes, err := os.ReadFile(dbPath)
	assert.Nil(t, err)
	assert.True(t, bytes.HasPrefix(rawBytes, encryptedStatePrefix))

	_, err = db.get(ctx, "example.com")
	assert.True(t, errors.Is(err, ErrNotFound))

	sessTkn := &authv1.SessionToken{
		AccessToken:  utilrand.GetRandomString(32),
		RefreshToken: utilrand.GetRandomString(32),
	}
	assert.Nil(t, db.set(ctx, "example.com", sessTkn))

	rawBytes, err = os.ReadFile(dbPath)
	assert.Nil(t, err)
	assert.True(t, bytes.HasPrefix(rawBytes, encryptedStatePrefix))
	assert.False(t, bytes.Contains(rawBytes, []byte(sessTkn.AccessToken)))
	assert.False(t, bytes.Contains(rawBytes, []byte(sessTkn.RefreshToken)))
	assert.False(t, bytes.Contains(rawBytes, []byte("example.com")))

	state, err := db.get(ctx, "example.com")
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(sessTkn, state.SessionToken))

	{
		otherDB, err := newFSDB(&Opts{Path: tmpDir, EncryptionKey: key})
		assert.Nil(t, err)

		state, err := otherDB.get(ctx, "example.com")
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(sessTkn, state.SessionToken))

		domainMap, err := otherDB.list(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 1, len(domainMap))
	}

	{
		otherDB, err := newFSDB(&Opts{Path: tmpDir, EncryptionKey: utilrand.GetRandomBytesMust(32)})
		assert.Nil(t, err)

		_, err = otherDB.get(ctx, "example.com")
		assert.NotNil(t, err)
		assert.False(t, errors.Is(err, ErrNotFound))

		err = otherDB.set(ctx, "example.com", sessTkn)
		assert.NotNil(t, err)
	}

	{
		tamperedBytes := slices.Clone(rawBytes)
		tamperedBytes[len(tamperedBytes)-1] ^= 0xff
		assert.Nil(t, os.WriteFile(dbPath, tamperedBytes, 0600))

		_, err = db.get(ctx, "example.com")
		assert.NotNil(t, err)
		assert.False(t, errors.Is(err, ErrNotFound))
	}
}

func TestFSDBEncryptedRejectsPlaintext(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	plainDB, err := newFSDB(&Opts{Path: tmpDir})
	assert.Nil(t, err)
	assert.Nil(t, plainDB.set(ctx, "example.com", &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	}))

	db, err := newFSDB(&Opts{Path: tmpDir, EncryptionKey: utilrand.GetRandomBytesMust(32)})
	assert.Nil(t, err)

	_, err = db.get(ctx, "example.com")
	assert.NotNil(t, err)
	assert.False(t, errors.Is(err, ErrNotFound))
}

func TestFSDBEncryptedEmptyFile(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	assert.Nil(t, os.WriteFile(filepath.Join(tmpDir, "octelium.db"), nil, 0600))

	db, err := newFSDB(&Opts{Path: tmpDir, EncryptionKey: utilrand.GetRandomBytesMust(32)})
	assert.Nil(t, err)

	_, err = db.get(ctx, "example.com")
	assert.True(t, errors.Is(err, ErrNotFound))

	assert.Nil(t, db.set(ctx, "example.com", &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	}))

	_, err = db.get(ctx, "example.com")
	assert.Nil(t, err)
}

func TestFSDBInvalidEncryptionKey(t *testing.T) {
	for _, keyLen := range []int{1, 16, 24, 31, 33, 64} {
		_, err := newFSDB(&Opts{
			Path:          t.TempDir(),
			EncryptionKey: utilrand.GetRandomBytesMust(keyLen),
		})
		assert.NotNil(t, err, "keyLen: %d", keyLen)
	}
}

func TestOpenWithOptsEncrypted(t *testing.T) {
	tmpDir := t.TempDir()
	key := utilrand.GetRandomBytesMust(32)

	dbC, err := OpenWithOpts(&Opts{Path: tmpDir, EncryptionKey: key})
	assert.Nil(t, err)
	assert.Nil(t, dbC.Migrate())

	sessTkn := &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	}
	assert.Nil(t, dbC.SetSessionToken("example.com", sessTkn))

	ret, err := dbC.GetSessionToken("example.com")
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(sessTkn, ret))

	assert.Nil(t, dbC.DeleteSessionToken("example.com"))
	_, err = dbC.GetSessionToken("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))

	assert.Nil(t, dbC.Close())
}

func TestFSDBEncryptedAtomicWrite(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "octelium.db")
	key := utilrand.GetRandomBytesMust(32)

	db, err := newFSDB(&Opts{Path: tmpDir, EncryptionKey: key})
	assert.Nil(t, err)
	assert.Nil(t, db.migrate(ctx))

	sessTkn := &authv1.SessionToken{
		AccessToken: utilrand.GetRandomString(32),
	}

	for i := range 10 {
		assert.Nil(t, db.set(ctx, fmt.Sprintf("d%d.example.com", i), sessTkn))
	}

	fi, err := os.Stat(dbPath)
	assert.Nil(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())

	entries, err := os.ReadDir(tmpDir)
	assert.Nil(t, err)
	for _, entry := range entries {
		assert.False(t, strings.HasPrefix(entry.Name(), "octelium.db.tmp"), entry.Name())
	}

	domainMap, err := db.list(ctx)
	assert.Nil(t, err)
	assert.Equal(t, 10, len(domainMap))

	if os.Geteuid() == 0 {
		t.Skip("Skipping the read-only directory check as root")
	}

	assert.Nil(t, os.Chmod(tmpDir, 0500))
	t.Cleanup(func() {
		os.Chmod(tmpDir, 0700)
	})

	assert.NotNil(t, db.set(ctx, "failed.example.com", sessTkn))

	domainMap, err = db.list(ctx)
	assert.Nil(t, err)
	assert.Equal(t, 10, len(domainMap))
	_, ok := domainMap["failed.example.com"]
	assert.False(t, ok)
}

func TestWriteFileAtomic(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "state")

	assert.Nil(t, writeFileAtomic(filePath, []byte("first")))
	assert.Nil(t, writeFileAtomic(filePath, []byte("second")))

	content, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, []byte("second"), content)

	entries, err := os.ReadDir(tmpDir)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(entries))

	assert.NotNil(t, writeFileAtomic(filepath.Join(tmpDir, "missing", "state"), []byte("third")))
}
