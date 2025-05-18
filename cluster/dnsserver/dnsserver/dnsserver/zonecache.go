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

package dnsserver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type zoneCache struct {
	sync.RWMutex
	cMap     map[string]*zoneCacheVal
	duration time.Duration
}

type zoneCacheVal struct {
	r   *dns.Msg
	exp time.Time
}

func newZoneCache(duration time.Duration) *zoneCache {
	if duration == 0 {
		duration = 30 * time.Second
	}

	return &zoneCache{
		cMap:     make(map[string]*zoneCacheVal),
		duration: duration,
	}
}

func (c *zoneCache) getCacheKey(domain string, typ uint16) string {
	return fmt.Sprintf("%s:%d", domain, typ)
}

func (c *zoneCache) get(domain string, typ uint16) *dns.Msg {
	c.RLock()
	defer c.RUnlock()
	val, ok := c.cMap[c.getCacheKey(domain, typ)]
	if !ok {
		return nil
	}

	if time.Now().After(val.exp) {
		return nil
	}

	return val.r
}

func (c *zoneCache) set(domain string, typ uint16, r *dns.Msg) {
	if r.Rcode != dns.RcodeSuccess {
		return
	}

	switch typ {
	case dns.TypeA, dns.TypeAAAA:
	default:
		return
	}

	c.Lock()
	c.cMap[c.getCacheKey(domain, typ)] = &zoneCacheVal{
		r:   r,
		exp: time.Now().Add(c.duration),
	}
	c.Unlock()
}

func (c *zoneCache) startCleanupLoop(ctx context.Context) {
	tickerCh := time.NewTicker(6 * time.Minute)
	defer tickerCh.Stop()

	cleanAllCh := time.NewTicker(60 * time.Minute)
	defer cleanAllCh.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tickerCh.C:
			c.doCleanup()
		case <-cleanAllCh.C:
			c.Lock()
			c.cMap = make(map[string]*zoneCacheVal)
			c.Unlock()
		}
	}
}

func (c *zoneCache) doCleanup() {
	c.Lock()
	defer c.Unlock()
	for k, v := range c.cMap {
		if time.Now().After(v.exp) {
			delete(c.cMap, k)
		}
	}
}

func (c *zoneCache) setDuration(duration time.Duration) {
	c.Lock()
	if duration == 0 {
		duration = 30 * time.Second
	}
	c.duration = duration
	c.Unlock()
}
