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
	"fmt"
	"maps"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tstRawLen[K comparable, V any](c *cache[K, V]) int {
	ret := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.RLock()
		ret += len(s.m)
		s.mu.RUnlock()
	}

	return ret
}

func TestCache(t *testing.T) {
	c := New[string, int](nil)
	defer c.Close()

	_, found := c.Get("k1")
	assert.False(t, found)
	assert.Equal(t, 0, c.Len())

	c.Set("k1", 1)
	c.Set("k2", 2)

	val, found := c.Get("k1")
	assert.True(t, found)
	assert.Equal(t, 1, val)
	assert.Equal(t, 2, c.Len())

	c.Set("k1", 10)
	val, found = c.Get("k1")
	assert.True(t, found)
	assert.Equal(t, 10, val)
	assert.Equal(t, 2, c.Len())

	val, exp, found := c.GetWithExpiration("k1")
	assert.True(t, found)
	assert.Equal(t, 10, val)
	assert.True(t, exp.IsZero())

	c.Delete("k1")
	_, found = c.Get("k1")
	assert.False(t, found)
	assert.Equal(t, 1, c.Len())

	c.Delete("k1")
	c.Delete("unknown")
	assert.Equal(t, 1, c.Len())

	c.Clear()
	_, found = c.Get("k2")
	assert.False(t, found)
	assert.Equal(t, 0, c.Len())
	assert.Equal(t, 0, tstRawLen(c.cache))

	c.Set("k2", 20)
	val, found = c.Get("k2")
	assert.True(t, found)
	assert.Equal(t, 20, val)
}

func TestCacheExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, string]{
			DefaultTTL: 10 * time.Second,
		})
		defer c.Close()

		startedAt := time.Now()

		c.Set("default", "v1")
		c.SetWithTTL("short", "v2", 2*time.Second)
		c.SetWithTTL("long", "v3", time.Minute)
		c.SetWithTTL("forever", "v4", NoExpiration)

		_, exp, found := c.GetWithExpiration("default")
		assert.True(t, found)
		assert.True(t, exp.Equal(startedAt.Add(10*time.Second)))

		_, exp, found = c.GetWithExpiration("short")
		assert.True(t, found)
		assert.True(t, exp.Equal(startedAt.Add(2*time.Second)))

		_, exp, found = c.GetWithExpiration("forever")
		assert.True(t, found)
		assert.True(t, exp.IsZero())

		assert.Equal(t, 4, c.Len())

		time.Sleep(2*time.Second - time.Nanosecond)
		val, found := c.Get("short")
		assert.True(t, found)
		assert.Equal(t, "v2", val)

		time.Sleep(time.Nanosecond)
		_, found = c.Get("short")
		assert.False(t, found)
		_, _, found = c.GetWithExpiration("short")
		assert.False(t, found)
		assert.Equal(t, 3, c.Len())
		assert.Equal(t, 4, tstRawLen(c.cache))

		time.Sleep(8 * time.Second)
		_, found = c.Get("default")
		assert.False(t, found)
		assert.Equal(t, 2, c.Len())

		c.DeleteExpired()
		assert.Equal(t, 2, tstRawLen(c.cache))

		time.Sleep(time.Hour)
		_, found = c.Get("long")
		assert.False(t, found)

		val, found = c.Get("forever")
		assert.True(t, found)
		assert.Equal(t, "v4", val)
		assert.Equal(t, 1, c.Len())

		c.SetWithTTL("long", "v5", time.Minute)
		val, found = c.Get("long")
		assert.True(t, found)
		assert.Equal(t, "v5", val)
	})
}

func TestCacheSetNonPositiveTTL(t *testing.T) {
	c := New[string, int](nil)
	defer c.Close()

	c.Set("k1", 1)
	c.SetWithTTL("k1", 2, 0)
	_, found := c.Get("k1")
	assert.False(t, found)

	c.Set("k1", 1)
	c.SetWithTTL("k1", 2, -time.Second)
	_, found = c.Get("k1")
	assert.False(t, found)

	c.SetWithTTL("k2", 2, -time.Second)
	assert.Equal(t, 0, c.Len())
	assert.Equal(t, 0, tstRawLen(c.cache))
}

func TestCacheDefaultTTL(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, ttl := range []time.Duration{0, -time.Second, NoExpiration} {
			c := New(&Opts[string, int]{
				DefaultTTL: ttl,
			})
			assert.Equal(t, NoExpiration, c.defaultTTL)

			c.Set("k1", 1)
			c.Upsert("k2", func(val int, found bool) int {
				return 2
			})

			time.Sleep(10 * 365 * 24 * time.Hour)
			val, exp, found := c.GetWithExpiration("k1")
			assert.True(t, found)
			assert.Equal(t, 1, val)
			assert.True(t, exp.IsZero())

			val, exp, found = c.GetWithExpiration("k2")
			assert.True(t, found)
			assert.Equal(t, 2, val)
			assert.True(t, exp.IsZero())
		}
	})
}

func TestCacheUpsert(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, int]{
			DefaultTTL: time.Minute,
		})
		defer c.Close()

		incr := func(val int, found bool) int {
			return val + 1
		}

		startedAt := time.Now()

		assert.Equal(t, 1, c.Upsert("k1", incr))

		time.Sleep(30 * time.Second)
		assert.Equal(t, 2, c.Upsert("k1", incr))
		assert.Equal(t, 3, c.Upsert("k1", incr))

		val, exp, found := c.GetWithExpiration("k1")
		assert.True(t, found)
		assert.Equal(t, 3, val)
		assert.True(t, exp.Equal(startedAt.Add(time.Minute)))

		time.Sleep(30 * time.Second)
		_, found = c.Get("k1")
		assert.False(t, found)

		assert.Equal(t, 1, c.Upsert("k1", func(val int, found bool) int {
			assert.False(t, found)
			assert.Equal(t, 0, val)
			return val + 1
		}))

		_, exp, found = c.GetWithExpiration("k1")
		assert.True(t, found)
		assert.True(t, exp.Equal(time.Now().Add(time.Minute)))

		c.SetWithTTL("k2", 10, NoExpiration)
		assert.Equal(t, 11, c.Upsert("k2", func(val int, found bool) int {
			assert.True(t, found)
			return val + 1
		}))

		time.Sleep(time.Hour)
		val, exp, found = c.GetWithExpiration("k2")
		assert.True(t, found)
		assert.Equal(t, 11, val)
		assert.True(t, exp.IsZero())
	})
}

func TestCacheUpsertPanic(t *testing.T) {
	c := New(&Opts[string, int]{
		Shards: 1,
	})
	defer c.Close()

	assert.Panics(t, func() {
		c.Upsert("k1", func(val int, found bool) int {
			panic("upsert")
		})
	})

	_, found := c.Get("k1")
	assert.False(t, found)

	c.Set("k1", 1)
	val, found := c.Get("k1")
	assert.True(t, found)
	assert.Equal(t, 1, val)
}

func TestCacheJanitor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, int]{
			CleanupInterval: time.Minute,
		})

		for i := range 100 {
			c.Set(fmt.Sprintf("forever-%d", i), i)
		}
		assert.False(t, c.janitorScheduled.Load())

		time.Sleep(time.Hour)
		synctest.Wait()
		assert.Equal(t, 100, tstRawLen(c.cache))
	})

	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, int]{
			DefaultTTL:      10 * time.Second,
			CleanupInterval: time.Minute,
		})
		defer c.Close()

		c.SetWithTTL("forever", 1, NoExpiration)
		assert.False(t, c.janitorScheduled.Load())

		for i := range 100 {
			c.Set(fmt.Sprintf("k-%d", i), i)
		}
		c.SetWithTTL("long", 1, 90*time.Second)
		assert.True(t, c.janitorScheduled.Load())
		assert.Equal(t, 102, tstRawLen(c.cache))

		time.Sleep(59 * time.Second)
		synctest.Wait()
		assert.Equal(t, 2, c.Len())
		assert.Equal(t, 102, tstRawLen(c.cache))

		time.Sleep(time.Second)
		synctest.Wait()
		assert.Equal(t, 2, tstRawLen(c.cache))
		assert.True(t, c.janitorScheduled.Load())

		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, 1, tstRawLen(c.cache))
		assert.False(t, c.janitorScheduled.Load())

		time.Sleep(time.Hour)
		synctest.Wait()
		assert.False(t, c.janitorScheduled.Load())

		c.Upsert("k-0", func(val int, found bool) int {
			return 1
		})
		assert.True(t, c.janitorScheduled.Load())

		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, 1, tstRawLen(c.cache))
		assert.False(t, c.janitorScheduled.Load())
	})

	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, int]{
			DefaultTTL:      10 * time.Second,
			CleanupInterval: time.Minute,
		})

		for i := range 100 {
			c.Set(fmt.Sprintf("k-%d", i), i)
		}
		assert.True(t, c.janitorScheduled.Load())
	})

	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, int]{
			DefaultTTL: 10 * time.Second,
		})
		defer c.Close()

		assert.Equal(t, defaultCleanupInterval, c.cleanupInterval)

		c.Set("k1", 1)
		time.Sleep(defaultCleanupInterval)
		synctest.Wait()
		assert.Equal(t, 0, tstRawLen(c.cache))
	})

	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, int]{
			DefaultTTL:      10 * time.Second,
			CleanupInterval: -1,
		})

		c.Set("k1", 1)
		time.Sleep(time.Hour)
		synctest.Wait()
		_, found := c.Get("k1")
		assert.False(t, found)
		assert.Equal(t, 1, tstRawLen(c.cache))

		c.DeleteExpired()
		assert.Equal(t, 0, tstRawLen(c.cache))
	})
}

func TestCacheClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, int]{
			DefaultTTL:      time.Second,
			CleanupInterval: time.Minute,
		})

		c.Close()
		c.Close()

		c.Set("k1", 1)
		val, found := c.Get("k1")
		assert.True(t, found)
		assert.Equal(t, 1, val)
		assert.False(t, c.janitorScheduled.Load())

		time.Sleep(time.Hour)
		synctest.Wait()
		assert.Equal(t, 1, tstRawLen(c.cache))
	})

	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, int]{
			DefaultTTL:      time.Second,
			CleanupInterval: time.Minute,
		})

		c.Set("k1", 1)
		time.Sleep(time.Minute)
		synctest.Wait()
		assert.Equal(t, 0, tstRawLen(c.cache))

		c.Close()
		c.Set("k1", 1)
		assert.False(t, c.janitorScheduled.Load())
		time.Sleep(time.Hour)
		synctest.Wait()
		assert.Equal(t, 1, tstRawLen(c.cache))
	})

	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, int]{
			DefaultTTL:      time.Second,
			CleanupInterval: time.Minute,
		})

		c.Set("k1", 1)
		assert.True(t, c.janitorScheduled.Load())

		c.Close()
		time.Sleep(time.Hour)
		synctest.Wait()
		assert.Equal(t, 1, tstRawLen(c.cache))
	})
}

func TestCacheCloseUnreachable(t *testing.T) {
	inner := func() *cache[string, int] {
		c := New(&Opts[string, int]{
			DefaultTTL:      time.Minute,
			CleanupInterval: time.Minute,
		})
		c.Set("k1", 1)
		return c.cache
	}()

	assert.True(t, inner.janitorScheduled.Load())
	assert.Eventually(t, func() bool {
		runtime.GC()
		return inner.closed.Load()
	}, 10*time.Second, 10*time.Millisecond)

	synctest.Test(t, func(t *testing.T) {
		inner := func() *cache[string, int] {
			c := New(&Opts[string, int]{
				DefaultTTL: time.Minute,
			})
			c.Set("k1", 1)
			return c.cache
		}()

		for i := 0; i < 1000 && !inner.closed.Load(); i++ {
			runtime.GC()
			runtime.Gosched()
		}
		assert.True(t, inner.closed.Load())

		time.Sleep(time.Hour)
		synctest.Wait()
		assert.Equal(t, 1, tstRawLen(inner))
	})
}

func TestCacheShrink(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[int, int]{
			DefaultTTL:      time.Second,
			CleanupInterval: -1,
			Shards:          1,
		})

		for i := range 4 * shrinkMinPeak {
			c.Set(i, i)
		}
		for i := range shrinkMinPeak / 2 {
			c.SetWithTTL(-i-1, i, NoExpiration)
		}

		s := &c.shards[0]
		assert.Equal(t, 4*shrinkMinPeak+shrinkMinPeak/2, s.peak)

		time.Sleep(time.Second)
		c.DeleteExpired()
		assert.Equal(t, shrinkMinPeak/2, len(s.m))
		assert.Equal(t, shrinkMinPeak/2, s.peak)
		assert.Equal(t, shrinkMinPeak/2, c.Len())

		for i := range shrinkMinPeak / 2 {
			val, found := c.Get(-i - 1)
			assert.True(t, found)
			assert.Equal(t, i, val)
		}

		for i := range shrinkMinPeak {
			c.Set(i, i)
		}
		assert.Equal(t, shrinkMinPeak+shrinkMinPeak/2, s.peak)

		time.Sleep(time.Second)
		c.DeleteExpired()
		assert.Equal(t, shrinkMinPeak+shrinkMinPeak/2, s.peak)
		assert.Equal(t, shrinkMinPeak/2, len(s.m))
	})
}

func TestCacheAll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(&Opts[string, int]{
			DefaultTTL: time.Minute,
		})
		defer c.Close()

		assert.Empty(t, maps.Collect(c.All()))

		expected := map[string]int{}
		for i := range 100 {
			key := fmt.Sprintf("k-%d", i)
			if i%2 == 0 {
				c.Set(key, i)
			} else {
				c.SetWithTTL(key, i, NoExpiration)
				expected[key] = i
			}
		}

		assert.Len(t, maps.Collect(c.All()), 100)

		time.Sleep(time.Minute)
		assert.Equal(t, expected, maps.Collect(c.All()))

		count := 0
		for key := range c.All() {
			c.Delete(key)
			c.Set(key+"-new", 1)
			count++
			if count == 10 {
				break
			}
		}
		assert.Equal(t, 10, count)
		assert.Len(t, maps.Collect(c.All()), 50)
	})
}

func TestGetAs(t *testing.T) {
	type tstVal struct {
		val string
	}

	c := New[string, any](nil)
	defer c.Close()

	c.Set("str", "val")
	c.Set("int", 10)
	c.Set("ptr", &tstVal{val: "val"})
	c.Set("slice", []string{"a", "b"})
	c.Set("nil", nil)

	strVal, ok := GetAs[string](c, "str")
	assert.True(t, ok)
	assert.Equal(t, "val", strVal)

	intVal, ok := GetAs[int](c, "int")
	assert.True(t, ok)
	assert.Equal(t, 10, intVal)

	ptrVal, ok := GetAs[*tstVal](c, "ptr")
	assert.True(t, ok)
	assert.Equal(t, "val", ptrVal.val)

	sliceVal, ok := GetAs[[]string](c, "slice")
	assert.True(t, ok)
	assert.Equal(t, []string{"a", "b"}, sliceVal)

	anyVal, ok := GetAs[any](c, "int")
	assert.True(t, ok)
	assert.Equal(t, 10, anyVal)

	_, ok = GetAs[string](c, "int")
	assert.False(t, ok)

	_, ok = GetAs[*tstVal](c, "nil")
	assert.False(t, ok)

	strVal, ok = GetAs[string](c, "unknown")
	assert.False(t, ok)
	assert.Equal(t, "", strVal)
}

func TestCacheKeyTypes(t *testing.T) {
	type tstKey struct {
		kind string
		id   int
	}

	c := New(&Opts[tstKey, string]{
		Shards: 16,
	})
	defer c.Close()

	for i := range 1000 {
		c.Set(tstKey{kind: "a", id: i}, strconv.Itoa(i))
	}

	for i := range 1000 {
		val, found := c.Get(tstKey{kind: "a", id: i})
		assert.True(t, found)
		assert.Equal(t, strconv.Itoa(i), val)

		_, found = c.Get(tstKey{kind: "b", id: i})
		assert.False(t, found)
	}

	assert.Equal(t, 1000, c.Len())

	nonEmpty := 0
	for i := range c.shards {
		if len(c.shards[i].m) > 0 {
			nonEmpty++
		}
	}
	assert.Equal(t, len(c.shards), nonEmpty)
}

func TestGetShardCount(t *testing.T) {
	assert.Equal(t, 1, getShardCount(1))
	assert.Equal(t, 2, getShardCount(2))
	assert.Equal(t, 4, getShardCount(3))
	assert.Equal(t, 64, getShardCount(64))
	assert.Equal(t, 128, getShardCount(65))
	assert.Equal(t, maxShards, getShardCount(maxShards))
	assert.Equal(t, maxShards, getShardCount(100000))

	defaultCount := getShardCount(0)
	assert.Equal(t, defaultCount, getShardCount(-1))
	assert.GreaterOrEqual(t, defaultCount, min(4*runtime.GOMAXPROCS(0), maxShards))
	assert.Equal(t, 0, defaultCount&(defaultCount-1))

	c := New(&Opts[string, int]{
		Shards: 1,
	})
	assert.Len(t, c.shards, 1)
	assert.Equal(t, uint64(0), c.mask)

	c = New(&Opts[string, int]{
		Shards: 5,
	})
	assert.Len(t, c.shards, 8)
	assert.Equal(t, uint64(7), c.mask)
}

func TestCacheConcurrency(t *testing.T) {
	for _, shards := range []int{1, 0} {
		t.Run(fmt.Sprintf("shards-%d", shards), func(t *testing.T) {
			c := New(&Opts[string, int]{
				DefaultTTL:      time.Hour,
				CleanupInterval: time.Millisecond,
				Shards:          shards,
			})
			defer c.Close()

			const workers = 16
			const iterations = 2000
			const keys = 10

			var wg sync.WaitGroup
			for i := range workers {
				wg.Go(func() {
					for j := range iterations {
						key := fmt.Sprintf("counter-%d", j%keys)
						c.Upsert(key, func(val int, found bool) int {
							return val + 1
						})

						tmpKey := fmt.Sprintf("tmp-%d-%d", i, j)
						c.SetWithTTL(tmpKey, j, time.Millisecond)
						c.Get(tmpKey)
						c.Get(key)
						if j%100 == 0 {
							c.Len()
							for range c.All() {
							}
						}
						c.Delete(tmpKey)
					}
				})
			}
			wg.Wait()

			for i := range keys {
				val, found := c.Get(fmt.Sprintf("counter-%d", i))
				require.True(t, found)
				assert.Equal(t, workers*iterations/keys, val)
			}
			assert.Equal(t, keys, c.Len())
		})
	}
}

func BenchmarkCacheGet(b *testing.B) {
	c := New[string, int](nil)
	defer c.Close()

	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
		c.Set(keys[i], i)
	}

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		c.Get(keys[i&1023])
		i++
	}
}

func BenchmarkCacheGetTTL(b *testing.B) {
	c := New(&Opts[string, int]{
		DefaultTTL: time.Hour,
	})
	defer c.Close()

	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
		c.Set(keys[i], i)
	}

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		c.Get(keys[i&1023])
		i++
	}
}

func BenchmarkCacheSet(b *testing.B) {
	c := New(&Opts[string, int]{
		DefaultTTL: time.Hour,
	})
	defer c.Close()

	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
	}

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		c.Set(keys[i&1023], i)
		i++
	}
}

func BenchmarkCacheUpsert(b *testing.B) {
	c := New(&Opts[string, int]{
		DefaultTTL: time.Hour,
	})
	defer c.Close()

	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
	}

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		c.Upsert(keys[i&1023], func(val int, found bool) int {
			return val + 1
		})
		i++
	}
}

func BenchmarkCacheGetParallel(b *testing.B) {
	c := New(&Opts[string, int]{
		DefaultTTL: time.Hour,
	})
	defer c.Close()

	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
		c.Set(keys[i], i)
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Get(keys[i&1023])
			i++
		}
	})
}

func BenchmarkCacheMixedParallel(b *testing.B) {
	c := New(&Opts[string, int]{
		DefaultTTL: time.Hour,
	})
	defer c.Close()

	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
		c.Set(keys[i], i)
	}

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%10 == 0 {
				c.Set(keys[i&1023], i)
			} else {
				c.Get(keys[i&1023])
			}
			i++
		}
	})
}
