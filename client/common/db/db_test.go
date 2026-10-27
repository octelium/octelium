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
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
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

func TestDBSessionTokenInputIsolation(t *testing.T) {
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	for _, path := range []string{"mem", t.TempDir()} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			d, err := Open(path)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, d.Close()) })
			token := &authv1.SessionToken{ExpiresIn: 7200, RefreshTokenExpiresIn: 86400}
			states := make(map[string]*cliconfigv1.State_Domain)
			for _, domain := range []string{"one.example", "two.example"} {
				token.AccessToken = "access-" + domain
				token.RefreshToken = "refresh-" + domain
				require.NoError(t, d.SetSessionToken(domain, token))
				state, err := d.Get(domain)
				require.NoError(t, err)
				require.True(t, pbutils.IsEqual(token, state.SessionToken))
				states[domain] = state
			}
			token.AccessToken = "mutated"
			token.RefreshToken = "mutated"
			token.ExpiresIn = 1
			token.RefreshTokenExpiresIn = 1
			items, err := d.List()
			require.NoError(t, err)
			for domain, want := range states {
				state, err := d.Get(domain)
				require.NoError(t, err)
				assert.True(t, pbutils.IsEqual(want, state), "domain: %s", domain)
				assert.True(t, pbutils.IsEqual(want, items[domain]), "domain: %s", domain)
				stored, err := d.GetSessionToken(domain)
				require.NoError(t, err)
				assert.True(t, pbutils.IsEqual(want.SessionToken, stored), "domain: %s", domain)
			}
		})
	}
}

func TestDBDomainSettingsInputIsolation(t *testing.T) {
	for _, path := range []string{"mem", t.TempDir()} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			d, err := Open(path)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, d.Close()) })
			settings := &daemonv1.DomainSettings{
				AutoConnect: true,
				ConnectionOptions: &daemonv1.ConnectionOptions{
					TunnelMode: daemonv1.ConnectionOptions_QUICV0,
					Mtu:        1280,
					Dns:        &daemonv1.ConnectionOptions_DNS{Mode: daemonv1.ConnectionOptions_DNS_FULL},
					ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
						Serve: []*daemonv1.ConnectionOptions_ServiceReference{{Namespace: "default"}},
						Publish: []*daemonv1.ConnectionOptions_PublishedService{{
							Service: &daemonv1.ConnectionOptions_ServiceReference{Name: "web", Namespace: "default"},
							Address: "127.0.0.1", Port: 8080,
						}},
					},
				},
			}
			states := make(map[string]*cliconfigv1.State_Domain)
			for _, domain := range []string{"one.example", "two.example"} {
				settings.Domain = domain
				settings.ConnectionOptions.ServiceOptions.Serve[0].Name = domain
				require.NoError(t, d.SetSessionToken(domain, &authv1.SessionToken{AccessToken: domain}))
				require.NoError(t, d.SetDomainSettings(domain, settings))
				state, err := d.Get(domain)
				require.NoError(t, err)
				require.True(t, pbutils.IsEqual(settings, state.Settings))
				states[domain] = state
			}
			settings.Domain = "mutated"
			settings.AutoConnect = false
			settings.ConnectionOptions.TunnelMode = daemonv1.ConnectionOptions_WIREGUARD
			settings.ConnectionOptions.Mtu = 1400
			settings.ConnectionOptions.Dns.Mode = daemonv1.ConnectionOptions_DNS_DISABLED
			settings.ConnectionOptions.ServiceOptions.Serve[0].Name = "mutated"
			settings.ConnectionOptions.ServiceOptions.Serve = append(settings.ConnectionOptions.ServiceOptions.Serve,
				&daemonv1.ConnectionOptions_ServiceReference{Name: "extra"})
			settings.ConnectionOptions.ServiceOptions.Publish[0].Service.Namespace = "mutated"
			settings.ConnectionOptions.ServiceOptions.Publish[0].Port = 9090
			items, err := d.List()
			require.NoError(t, err)
			for domain, want := range states {
				state, err := d.Get(domain)
				require.NoError(t, err)
				assert.True(t, pbutils.IsEqual(want, state), "domain: %s", domain)
				assert.True(t, pbutils.IsEqual(want, items[domain]), "domain: %s", domain)
			}
		})
	}
}

func TestDBNilAndEmptyInputs(t *testing.T) {
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	for _, path := range []string{"mem", t.TempDir()} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			d, err := Open(path)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, d.Close()) })
			for _, existing := range []bool{false, true} {
				for _, empty := range []bool{false, true} {
					t.Run(fmt.Sprintf("existing=%t/empty=%t", existing, empty), func(t *testing.T) {
						domain := fmt.Sprintf("%t-%t.example", existing, empty)
						if existing {
							require.NoError(t, d.SetSessionToken(domain, &authv1.SessionToken{AccessToken: "original"}))
							require.NoError(t, d.SetDomainSettings(domain, &daemonv1.DomainSettings{AutoConnect: true}))
							require.NoError(t, d.SetConnectionCleanup(domain, &cliconfigv1.ConnectionCleanup{Id: "cleanup"}))
						}
						var settings *daemonv1.DomainSettings
						if empty {
							settings = &daemonv1.DomainSettings{}
						}
						require.NoError(t, d.SetDomainSettings(domain, settings))
						state, err := d.Get(domain)
						require.NoError(t, err)
						assert.True(t, pbutils.IsEqual(settings, state.Settings))
						if existing {
							assert.Equal(t, "original", state.GetSessionToken().GetAccessToken())
							assert.True(t, state.SessionTokenSetAt.IsValid())
						} else {
							assert.Nil(t, state.SessionToken)
							assert.Nil(t, state.SessionTokenSetAt)
						}
						var token *authv1.SessionToken
						if empty {
							token = &authv1.SessionToken{}
						}
						require.NoError(t, d.SetSessionToken(domain, token))
						state, err = d.Get(domain)
						require.NoError(t, err)
						assert.True(t, pbutils.IsEqual(token, state.SessionToken))
						assert.True(t, state.SessionTokenSetAt.IsValid())
						assert.True(t, pbutils.IsEqual(settings, state.Settings))
						if existing {
							assert.Equal(t, "cleanup", state.GetConnectionCleanup().GetId())
						} else {
							assert.Nil(t, state.ConnectionCleanup)
						}
						stored, err := d.GetSessionToken(domain)
						if empty {
							require.NoError(t, err)
							assert.True(t, pbutils.IsEqual(token, stored))
						} else {
							assert.ErrorIs(t, err, ErrNotFound)
							assert.Nil(t, stored)
						}
					})
				}
			}
		})
	}
}

func TestDBReadsWhileInputsAreMutated(t *testing.T) {
	for _, path := range []string{"mem", t.TempDir()} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			d, err := Open(path)
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, d.Close()) })
			token := &authv1.SessionToken{AccessToken: "original"}
			settings := &daemonv1.DomainSettings{ConnectionOptions: &daemonv1.ConnectionOptions{
				Dns: &daemonv1.ConnectionOptions_DNS{Mode: daemonv1.ConnectionOptions_DNS_FULL},
			}}
			require.NoError(t, d.SetSessionToken("example.com", token))
			require.NoError(t, d.SetDomainSettings("example.com", settings))
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range 1000 {
					token.AccessToken = fmt.Sprintf("mutated-%d", i)
					settings.ConnectionOptions.Dns.Mode = daemonv1.ConnectionOptions_DNS_DISABLED
				}
			}()
			defer wg.Wait()
			for range 100 {
				state, err := d.Get("example.com")
				require.NoError(t, err)
				assert.Equal(t, "original", state.GetSessionToken().GetAccessToken())
				assert.Equal(t, daemonv1.ConnectionOptions_DNS_FULL, state.GetSettings().GetConnectionOptions().GetDns().GetMode())
				items, err := d.List()
				require.NoError(t, err)
				assert.Equal(t, "original", items["example.com"].GetSessionToken().GetAccessToken())
				assert.Equal(t, daemonv1.ConnectionOptions_DNS_FULL, items["example.com"].GetSettings().GetConnectionOptions().GetDns().GetMode())
			}
		})
	}
}
