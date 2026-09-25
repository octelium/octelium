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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestMemDB(t *testing.T) {

	{

		db, err := newMemDB()
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

	}
}

func TestMemDBConnectionCleanup(t *testing.T) {
	db, err := newMemDB()
	assert.Nil(t, err)

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

func TestMemDBDeleteStaleSessionToken(t *testing.T) {
	db, err := newMemDB()
	assert.Nil(t, err)

	domain := "example.com"
	assert.Nil(t, db.setSettings(context.Background(), domain, &daemonv1.DomainSettings{AutoConnect: true}))
	assert.Nil(t, db.set(context.Background(), domain, &authv1.SessionToken{RefreshToken: "new"}))

	assert.Nil(t, db.deleteStaleSessionToken(context.Background(), domain, "old"))
	state, err := db.get(context.Background(), domain)
	assert.Nil(t, err)
	assert.Equal(t, "new", state.GetSessionToken().GetRefreshToken())

	assert.Nil(t, db.deleteStaleSessionToken(context.Background(), domain, "new"))
	state, err = db.get(context.Background(), domain)
	assert.Nil(t, err)
	assert.Nil(t, state.SessionToken)
	assert.Nil(t, state.SessionTokenSetAt)
	assert.True(t, state.GetSettings().GetAutoConnect())

	assert.Nil(t, db.deleteStaleSessionToken(context.Background(), "other.com", "new"))
}
