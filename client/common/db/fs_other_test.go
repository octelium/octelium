//go:build !linux

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
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

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
