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
	"path/filepath"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLockRefresh(t *testing.T) {
	for _, dbPath := range []string{"mem", t.TempDir()} {
		dbC, err := Open(dbPath)
		assert.Nil(t, err)

		unlock, err := dbC.LockRefresh(context.Background())
		assert.Nil(t, err)

		{
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, err := dbC.LockRefresh(ctx)
			cancel()
			assert.ErrorIs(t, err, context.DeadlineExceeded)
		}

		lockedCh := make(chan func())
		go func() {
			unlock, err := dbC.LockRefresh(context.Background())
			assert.Nil(t, err)
			lockedCh <- unlock
		}()

		select {
		case <-lockedCh:
			t.Fatal("The refresh lock was acquired while it was held")
		case <-time.After(100 * time.Millisecond):
		}

		unlock()

		select {
		case unlock := <-lockedCh:
			unlock()
		case <-time.After(5 * time.Second):
			t.Fatal("The refresh lock was not acquired after it was released")
		}

		unlock, err = dbC.LockRefresh(context.Background())
		assert.Nil(t, err)
		unlock()

		assert.Nil(t, dbC.Close())
	}
}

func TestDBDomainLifecycle(t *testing.T) {
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	for _, path := range []string{"mem", "MeMoRy", t.TempDir()} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			d, err := Open(path)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, d.Close()) })
			require.NoError(t, d.Migrate())
			items, err := d.List()
			require.NoError(t, err)
			assert.Empty(t, items)
			_, err = d.GetSessionToken("missing.example")
			assert.True(t, d.ErrorIsNotFound(fmt.Errorf("wrapped: %w", err)))
			_, err = d.GetConnectionCleanup("missing.example")
			assert.ErrorIs(t, err, ErrNotFound)
			assert.False(t, d.ErrorIsNotFound(nil))
			for _, domain := range []string{"one.example", "two.example"} {
				require.NoError(t, d.SetDomainSettings(domain, &daemonv1.DomainSettings{Domain: domain, AutoConnect: true}))
				_, err = d.GetSessionToken(domain)
				assert.ErrorIs(t, err, ErrNotFound)
				_, err = d.GetConnectionCleanup(domain)
				assert.ErrorIs(t, err, ErrNotFound)
				require.NoError(t, d.SetSessionToken(domain, &authv1.SessionToken{AccessToken: domain, RefreshToken: "refresh"}))
				require.NoError(t, d.SetConnectionCleanup(domain, &cliconfigv1.ConnectionCleanup{Id: domain}))
			}
			items, err = d.List()
			require.NoError(t, err)
			require.Len(t, items, 2)
			items["one.example"].SessionToken.AccessToken = "mutated"
			delete(items, "two.example")
			token, err := d.GetSessionToken("one.example")
			require.NoError(t, err)
			assert.Equal(t, "one.example", token.AccessToken)
			token.AccessToken = "mutated-again"
			token, err = d.GetSessionToken("one.example")
			require.NoError(t, err)
			assert.Equal(t, "one.example", token.AccessToken)
			require.NoError(t, d.DeleteSessionToken("one.example"))
			state, err := d.Get("one.example")
			require.NoError(t, err)
			assert.Nil(t, state.SessionToken)
			assert.Nil(t, state.SessionTokenSetAt)
			assert.True(t, state.Settings.AutoConnect)
			require.NoError(t, d.Delete("one.example"))
			cleanup, err := d.GetConnectionCleanup("one.example")
			require.NoError(t, err)
			assert.Equal(t, "one.example", cleanup.Id)
			require.NoError(t, d.SetConnectionCleanup("one.example", nil))
			_, err = d.Get("one.example")
			assert.ErrorIs(t, err, ErrNotFound)
			require.NoError(t, d.DeleteConnectionCleanup("two.example"))
			require.NoError(t, d.Delete("two.example"))
			items, err = d.List()
			require.NoError(t, err)
			assert.Empty(t, items)
			require.NoError(t, d.Delete("missing.example"))
			require.NoError(t, d.DeleteSessionToken("missing.example"))
			require.NoError(t, d.DeleteConnectionCleanup("missing.example"))
		})
	}
}

func TestDBStaticSessionToken(t *testing.T) {
	d, err := Open("mem")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, d.Close()) })
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "static-token")
	token, err := d.GetSessionToken("missing.example")
	require.NoError(t, err)
	assert.Equal(t, "static-token", token.AccessToken)
	assert.Empty(t, token.RefreshToken)
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	_, err = d.GetSessionToken("missing.example")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestDBOpenDefault(t *testing.T) {
	t.Setenv("OCTELIUM_HOME", t.TempDir())
	for _, fn := range []func() (*DB, error){OpenDefault, func() (*DB, error) { return OpenWithOpts(nil) }} {
		d, err := fn()
		require.NoError(t, err)
		assert.NoError(t, d.Close())
	}
}
