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
	"os"
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
