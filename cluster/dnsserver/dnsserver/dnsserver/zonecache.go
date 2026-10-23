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
	r         *dns.Msg
	createdAt time.Time
	exp       time.Time
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

	now := time.Now()
	if !now.Before(val.exp) {
		return nil
	}

	ret := val.r.Copy()
	age := uint32(now.Sub(val.createdAt) / time.Second)
	for _, section := range [][]dns.RR{ret.Answer, ret.Ns, ret.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype != dns.TypeOPT {
				hdr.Ttl -= min(hdr.Ttl, age)
			}
		}
	}
	return ret
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

	now := time.Now()
	c.Lock()
	defer c.Unlock()

	duration := c.duration
	for _, section := range [][]dns.RR{r.Answer, r.Ns, r.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Rrtype == dns.TypeOPT {
				continue
			}
			ttl := hdr.Ttl
			if ttl > 0x7fffffff {
				ttl = 0
			}
			duration = min(duration, time.Duration(ttl)*time.Second)
		}
	}
	if duration <= 0 {
		delete(c.cMap, c.getCacheKey(domain, typ))
		return
	}
	c.cMap[c.getCacheKey(domain, typ)] = &zoneCacheVal{
		r:         r.Copy(),
		createdAt: now,
		exp:       now.Add(duration),
	}
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
	now := time.Now()
	for k, v := range c.cMap {
		if !now.Before(v.exp) {
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
