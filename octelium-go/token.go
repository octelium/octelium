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

package octelium

import (
	"strings"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
)

type tokenSnapshot struct {
	accessToken  string
	refreshToken string
	expiresAt    time.Time
	refreshAt    time.Time
	invalidated  bool
}

type tokenManager struct {
	mu sync.RWMutex

	token             tokenSnapshot
	everAuthenticated bool

	refreshMu sync.Mutex
}

func newTokenManager() *tokenManager {
	return &tokenManager{}
}

func (m *tokenManager) current(now time.Time) (AccessToken, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.token.accessToken == "" || m.token.invalidated {
		return AccessToken{}, false
	}
	if !m.token.refreshAt.IsZero() && !now.Before(m.token.refreshAt) {
		return AccessToken{}, false
	}

	return AccessToken{
		Value:  m.token.accessToken,
		Expiry: m.token.expiresAt,
	}, true
}

func (m *tokenManager) usable(now time.Time) (AccessToken, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.token.accessToken == "" || m.token.invalidated {
		return AccessToken{}, false
	}
	if !m.token.expiresAt.IsZero() && !now.Before(m.token.expiresAt) {
		return AccessToken{}, false
	}

	return AccessToken{
		Value:  m.token.accessToken,
		Expiry: m.token.expiresAt,
	}, true
}

func (m *tokenManager) snapshot() tokenSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.token
}

func (m *tokenManager) refreshToken() (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.token.refreshToken == "" {
		return "", false
	}
	return m.token.refreshToken, true
}

func (m *tokenManager) hasEverAuthenticated() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.everAuthenticated
}

func (m *tokenManager) setSession(
	tkn *authv1.SessionToken,
	now time.Time,
	refreshBefore time.Duration,
	fallbackRefreshToken string,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	refreshToken := strings.TrimSpace(tkn.RefreshToken)
	if refreshToken == "" {
		refreshToken = fallbackRefreshToken
	}

	m.token = newTokenSnapshot(
		strings.TrimSpace(tkn.AccessToken),
		refreshToken,
		now,
		time.Duration(tkn.ExpiresIn)*time.Second,
		refreshBefore,
	)
	m.everAuthenticated = true
}

func (m *tokenManager) setExternal(tkn AccessToken, now time.Time, refreshBefore time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lifetime time.Duration
	if !tkn.Expiry.IsZero() {
		lifetime = tkn.Expiry.Sub(now)
		if lifetime < 0 {
			lifetime = 0
		}
	}

	m.token = newTokenSnapshot(tkn.Value, "", now, lifetime, refreshBefore)
}

func newTokenSnapshot(
	accessToken string,
	refreshToken string,
	now time.Time,
	lifetime time.Duration,
	refreshBefore time.Duration,
) tokenSnapshot {
	ret := tokenSnapshot{
		accessToken:  accessToken,
		refreshToken: refreshToken,
	}

	if lifetime <= 0 {
		return ret
	}

	ret.expiresAt = now.Add(lifetime)

	early := refreshBefore
	if early < 0 {
		early = 0
	}

	// Never consume more than 20% of a short token's lifetime as refresh
	// leeway. This keeps the default useful for both minute-long and hour-long
	// tokens without refreshing the latter excessively early.
	if maxEarly := lifetime / 5; early > maxEarly {
		early = maxEarly
	}

	ret.refreshAt = ret.expiresAt.Add(-early)
	return ret
}

func (m *tokenManager) invalidateAccessToken() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.token.accessToken == "" {
		return
	}
	m.token.invalidated = true
	m.token.refreshAt = time.Unix(1, 0)
}

func (m *tokenManager) clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = tokenSnapshot{}
}
