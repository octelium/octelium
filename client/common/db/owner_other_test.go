//go:build !unix

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
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFSDBOwnerIgnored(t *testing.T) {
	ctx := context.Background()
	dbDir := filepath.Join(t.TempDir(), "home", ".config", "octelium")

	db, err := newFSDB(&Opts{
		Path: dbDir,
		Owner: &Owner{
			UID: 1000,
			GID: 1000,
		},
	})
	require.NoError(t, err)
	require.NoError(t, db.migrate(ctx))
	require.NoError(t, db.set(ctx, "example.com", &authv1.SessionToken{
		AccessToken: "token",
	}))

	for _, filePath := range []string{
		dbDir,
		filepath.Join(dbDir, "octelium.db"),
		filepath.Join(dbDir, "octelium.db.lock"),
	} {
		_, err := os.Stat(filePath)
		assert.NoError(t, err)
	}

	itm, err := db.get(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "token", itm.SessionToken.AccessToken)
}
