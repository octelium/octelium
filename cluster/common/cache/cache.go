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

package cache

import (
	"hash/maphash"
	"iter"
	"maps"
	"math"
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	NoExpiration time.Duration = math.MaxInt64

	defaultCleanupInterval = 1 * time.Minute
	maxShards              = 256
	shrinkMinPeak          = 256
)

type Opts[K comparable, V any] struct {
	DefaultTTL      time.Duration
	CleanupInterval time.Duration
	Shards          int
}

type Cache[K comparable, V any] struct {
	*cache[K, V]
}

type cache[K comparable, V any] struct {
	shards           []shard[K, V]
	mask             uint64
	seed             maphash.Seed
	epoch            time.Time
	defaultTTL       time.Duration
	cleanupInterval  time.Duration
	janitorScheduled atomic.Bool
	closed           atomic.Bool
}

type shard[K comparable, V any] struct {
	m    map[K]entry[V]
	peak int
	_    [64]byte
	mu   sync.RWMutex
	_    [64]byte
}

type entry[V any] struct {
	val V
	exp int64
}

type item[K comparable, V any] struct {
	key K
	val V
}

func New[K comparable, V any](o *Opts[K, V]) *Cache[K, V] {
	if o == nil {
		o = &Opts[K, V]{}
	}

	shardCount := getShardCount(o.Shards)

	c := &cache[K, V]{
		shards:          make([]shard[K, V], shardCount),
		mask:            uint64(shardCount - 1),
		seed:            maphash.MakeSeed(),
		epoch:           time.Now(),
		defaultTTL:      o.DefaultTTL,
		cleanupInterval: o.CleanupInterval,
	}

	if c.defaultTTL <= 0 {
		c.defaultTTL = NoExpiration
	}

	if c.cleanupInterval == 0 {
		c.cleanupInterval = defaultCleanupInterval
	}

	ret := &Cache[K, V]{
		cache: c,
	}

	runtime.AddCleanup(ret, (*cache[K, V]).Close, c)

	return ret
}

func GetAs[T any, K comparable](c *Cache[K, any], key K) (T, bool) {
	val, found := c.Get(key)
	if !found {
		var zero T
		return zero, false
	}

	ret, ok := val.(T)
	return ret, ok
}

func (c *cache[K, V]) Get(key K) (V, bool) {
	e, found := c.get(key)
	return e.val, found
}

func (c *cache[K, V]) GetWithExpiration(key K) (V, time.Time, bool) {
	e, found := c.get(key)
	if !found || e.exp == 0 {
		return e.val, time.Time{}, found
	}

	return e.val, c.epoch.Add(time.Duration(e.exp)), true
}

func (c *cache[K, V]) Set(key K, val V) {
	c.SetWithTTL(key, val, c.defaultTTL)
}

func (c *cache[K, V]) SetWithTTL(key K, val V, ttl time.Duration) {
	if ttl <= 0 {
		c.Delete(key)
		return
	}

	e := entry[V]{
		val: val,
	}
	if ttl != NoExpiration {
		e.exp = getExpiration(c.now(), ttl)
	}

	c.getShard(key).set(key, e)

	if e.exp != 0 {
		c.startJanitor()
	}
}

func (c *cache[K, V]) Upsert(key K, fn func(val V, found bool) V) V {
	e := c.getShard(key).upsert(key, c.now(), c.defaultTTL, fn)

	if e.exp != 0 {
		c.startJanitor()
	}

	return e.val
}

func (c *cache[K, V]) Delete(key K) {
	c.getShard(key).delete(key)
}

func (c *cache[K, V]) DeleteExpired() {
	c.deleteExpired()
}

func (c *cache[K, V]) Clear() {
	for i := range c.shards {
		c.shards[i].clear()
	}
}

func (c *cache[K, V]) Len() int {
	now := c.now()
	ret := 0
	for i := range c.shards {
		ret += c.shards[i].len(now)
	}

	return ret
}

func (c *cache[K, V]) All() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		var items []item[K, V]
		for i := range c.shards {
			items = c.shards[i].appendItems(items[:0], c.now())
			for _, itm := range items {
				if !yield(itm.key, itm.val) {
					return
				}
			}
		}
	}
}

func (c *cache[K, V]) Close() {
	c.closed.Store(true)
}

func (c *cache[K, V]) get(key K) (entry[V], bool) {
	s := c.getShard(key)

	s.mu.RLock()
	defer s.mu.RUnlock()

	e, found := s.m[key]
	if !found || (e.exp != 0 && c.now() >= e.exp) {
		return entry[V]{}, false
	}

	return e, true
}

func (c *cache[K, V]) getShard(key K) *shard[K, V] {
	if c.mask == 0 {
		return &c.shards[0]
	}

	return &c.shards[maphash.Comparable(c.seed, key)&c.mask]
}

func (c *cache[K, V]) now() int64 {
	return int64(time.Since(c.epoch))
}

func (c *cache[K, V]) deleteExpired() bool {
	hasExpiring := false
	for i := range c.shards {
		if c.shards[i].deleteExpired(c.now()) {
			hasExpiring = true
		}
	}

	return hasExpiring
}

func (c *cache[K, V]) startJanitor() {
	if c.cleanupInterval <= 0 || c.janitorScheduled.Load() || c.closed.Load() {
		return
	}

	if c.janitorScheduled.CompareAndSwap(false, true) {
		time.AfterFunc(c.cleanupInterval, c.runJanitor)
	}
}

func (c *cache[K, V]) runJanitor() {
	if c.closed.Load() {
		return
	}

	c.janitorScheduled.Store(false)

	if c.deleteExpired() {
		c.startJanitor()
	}
}

func (s *shard[K, V]) set(key K, e entry[V]) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.doSet(key, e)
}

func (s *shard[K, V]) doSet(key K, e entry[V]) {
	if s.m == nil {
		s.m = make(map[K]entry[V])
	}

	s.m[key] = e
	if n := len(s.m); n > s.peak {
		s.peak = n
	}
}

func (s *shard[K, V]) upsert(key K, now int64, ttl time.Duration, fn func(val V, found bool) V) entry[V] {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, found := s.m[key]
	if found && e.isExpired(now) {
		found = false
	}

	if !found {
		e = entry[V]{}
		if ttl != NoExpiration {
			e.exp = getExpiration(now, ttl)
		}
	}

	e.val = fn(e.val, found)
	s.doSet(key, e)

	return e
}

func (s *shard[K, V]) delete(key K) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.m, key)
}

func (s *shard[K, V]) deleteExpired(now int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	hasExpiring := false
	for key, e := range s.m {
		switch {
		case e.exp == 0:
		case now >= e.exp:
			delete(s.m, key)
		default:
			hasExpiring = true
		}
	}

	if s.peak >= shrinkMinPeak && len(s.m) <= s.peak/4 {
		m := make(map[K]entry[V], len(s.m))
		maps.Copy(m, s.m)
		s.m = m
		s.peak = len(m)
	}

	return hasExpiring
}

func (s *shard[K, V]) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.m = nil
	s.peak = 0
}

func (s *shard[K, V]) len(now int64) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ret := 0
	for _, e := range s.m {
		if !e.isExpired(now) {
			ret++
		}
	}

	return ret
}

func (s *shard[K, V]) appendItems(items []item[K, V], now int64) []item[K, V] {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for key, e := range s.m {
		if !e.isExpired(now) {
			items = append(items, item[K, V]{
				key: key,
				val: e.val,
			})
		}
	}

	return items
}

func (e entry[V]) isExpired(now int64) bool {
	return e.exp != 0 && now >= e.exp
}

func getExpiration(now int64, ttl time.Duration) int64 {
	if ttl >= NoExpiration-time.Duration(now) {
		return 0
	}

	return now + int64(ttl)
}

func getShardCount(n int) int {
	if n <= 0 {
		n = 4 * runtime.GOMAXPROCS(0)
	}

	return 1 << bits.Len(uint(min(n, maxShards)-1))
}
