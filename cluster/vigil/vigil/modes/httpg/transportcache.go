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

package httpg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
)

const (
	transportUnusedTTL       = 10 * time.Minute
	transportSweepInterval   = 60 * time.Second
	transportCacheMaxEntries = 256
)

type transportEntry struct {
	rt        http.RoundTripper
	closeIdle func()
	lastUsed  time.Time
}

type transportCache struct {
	mu        sync.Mutex
	m         map[string]*transportEntry
	cfgHasher configHasher
}

func newTransportCache() *transportCache {
	return &transportCache{
		m: make(map[string]*transportEntry),
	}
}

type transportBuilderFn func() (http.RoundTripper, func(), error)

func (c *transportCache) getOrCreate(key string, build transportBuilderFn) (http.RoundTripper, error) {

	c.mu.Lock()
	if entry, ok := c.m[key]; ok {
		entry.lastUsed = time.Now()
		rt := entry.rt
		c.mu.Unlock()
		return rt, nil
	}
	c.mu.Unlock()

	rt, closeIdle, err := build()
	if err != nil {
		return nil, err
	}

	c.mu.Lock()

	if entry, ok := c.m[key]; ok {
		entry.lastUsed = time.Now()
		winner := entry.rt
		c.mu.Unlock()

		if closeIdle != nil {
			closeIdle()
		}
		return winner, nil
	}

	if len(c.m) >= transportCacheMaxEntries {
		c.evictOldestLocked()
	}

	c.m[key] = &transportEntry{
		rt:        rt,
		closeIdle: closeIdle,
		lastUsed:  time.Now(),
	}

	c.mu.Unlock()

	return rt, nil
}

func (c *transportCache) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time

	for k, v := range c.m {
		if oldestKey == "" || v.lastUsed.Before(oldest) {
			oldestKey = k
			oldest = v.lastUsed
		}
	}

	if oldestKey == "" {
		return
	}

	entry := c.m[oldestKey]
	delete(c.m, oldestKey)

	zap.L().Debug("Evicting the least recently used upstream transport")

	if entry.closeIdle != nil {
		go entry.closeIdle()
	}
}

func (c *transportCache) sweep() {
	var retired []*transportEntry

	c.mu.Lock()
	for k, v := range c.m {
		if time.Since(v.lastUsed) > transportUnusedTTL {
			retired = append(retired, v)
			delete(c.m, k)
		}
	}
	c.mu.Unlock()

	for _, entry := range retired {
		if entry.closeIdle != nil {
			entry.closeIdle()
		}
	}
}

func (c *transportCache) closeAll() {
	c.mu.Lock()
	retired := make([]*transportEntry, 0, len(c.m))
	for k, v := range c.m {
		retired = append(retired, v)
		delete(c.m, k)
	}
	c.mu.Unlock()

	if len(retired) == 0 {
		return
	}

	zap.L().Debug("Closing all the cached upstream transports",
		zap.Int("entries", len(retired)))

	for _, entry := range retired {
		if entry.closeIdle != nil {
			entry.closeIdle()
		}
	}
}

func (c *transportCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

func (c *transportCache) startSweepLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(transportSweepInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				c.closeAll()
				return
			case <-ticker.C:
				c.sweep()
			}
		}
	}()
}

type configHasher struct {
	mu   sync.Mutex
	last *corev1.Service_Spec_Config
	hash string
}

func (h *configHasher) get(cfg *corev1.Service_Spec_Config) (string, error) {
	if cfg == nil {
		return "no-cfg", nil
	}

	h.mu.Lock()
	if h.last == cfg {
		ret := h.hash
		h.mu.Unlock()
		return ret, nil
	}
	h.mu.Unlock()

	b, err := pbutils.Marshal(cfg)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(b)
	ret := hex.EncodeToString(sum[:])

	h.mu.Lock()
	h.last = cfg
	h.hash = ret
	h.mu.Unlock()

	return ret, nil
}
