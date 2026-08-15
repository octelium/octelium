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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestFSDB(t *testing.T) {

	{
		tmpDir, err := os.MkdirTemp("", "octeliumdb-*")
		assert.Nil(t, err)
		db, err := newFSDB(tmpDir)
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
		db, err := newFSDB(tmpDir)
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

func TestFSDBConcurrentSameHandle(t *testing.T) {

	tmpDir, err := os.MkdirTemp("", "octeliumdb-*")
	assert.Nil(t, err)
	db, err := newFSDB(tmpDir)
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
	initDB, err := newFSDB(tmpDir)
	assert.Nil(t, err)

	err = initDB.migrate(context.Background())
	assert.Nil(t, err)

	n := 16

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			db, err := newFSDB(tmpDir)
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
	db, err := newFSDB(tmpDir)
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
	db, err := newFSDB(tmpDir)
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

	db, err := newFSDB(linkDir)
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
