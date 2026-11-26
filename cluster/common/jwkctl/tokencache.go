/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package jwkctl

import (
	"strings"
	"sync"
	"time"
)

const (
	accessTokenCacheMaxEntries   = 16384
	accessTokenCacheEvictSamples = 8
	accessTokenCacheMaxKeyLength = 300
)

type accessTokenCache struct {
	mu         sync.RWMutex
	m          map[string]*accessTokenCacheEntry
	maxEntries int
}

type accessTokenCacheEntry struct {
	claims    AccessTokenClaims
	keyUID    string
	key       *jwtKey
	expiresAt time.Time
	hasExpiry bool
}

func newAccessTokenCache(maxEntries int) *accessTokenCache {
	return &accessTokenCache{
		m:          make(map[string]*accessTokenCacheEntry),
		maxEntries: maxEntries,
	}
}

func (e *accessTokenCacheEntry) isExpired(now time.Time) bool {
	return e.hasExpiry && now.After(e.expiresAt)
}

func (c *accessTokenCache) get(tknStr string) *accessTokenCacheEntry {
	if len(tknStr) > accessTokenCacheMaxKeyLength {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.m[tknStr]
}

func (c *accessTokenCache) set(tknStr string, e *accessTokenCacheEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.m[tknStr]; !ok && len(c.m) >= c.maxEntries {
		c.evict(now)
	}

	c.m[strings.Clone(tknStr)] = e
}

func (c *accessTokenCache) delete(tknStr string, e *accessTokenCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.m[tknStr] == e {
		delete(c.m, tknStr)
	}
}

func (c *accessTokenCache) evict(now time.Time) {
	var victim string
	i := 0
	for tknStr, e := range c.m {
		if e.isExpired(now) {
			delete(c.m, tknStr)
			return
		}

		if i == 0 {
			victim = tknStr
		}

		i++
		if i >= accessTokenCacheEvictSamples {
			break
		}
	}

	delete(c.m, victim)
}

func (c *accessTokenCache) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.m)
}

func (c *Controller) getCachedAccessToken(tknStr string) (*accessTokenCacheEntry, bool) {
	e := c.accessTokenCache.get(tknStr)
	if e == nil {
		return nil, false
	}

	if e.isExpired(time.Now()) {
		return e, false
	}

	c.ctl.RLock()
	defer c.ctl.RUnlock()

	key, ok := c.ctl.keyMap[e.keyUID]

	return e, ok && key == e.key
}

func (c *Controller) setCachedAccessToken(tknStr string, claims *tokenClaims) {
	keyUID, err := c.getUID(claims.tkn.Content.KeyID)
	if err != nil {
		return
	}

	e := &accessTokenCacheEntry{
		claims: AccessTokenClaims{
			SessionUID: claims.subject,
			TokenID:    claims.tokenID,
		},
		keyUID: keyUID,
		key:    claims.key,
	}

	if claims.tkn.Content.ExpiresAt.IsValid() {
		e.expiresAt = claims.tkn.Content.ExpiresAt.AsTime()
		e.hasExpiry = true
	}

	c.accessTokenCache.set(tknStr, e, time.Now())
}
