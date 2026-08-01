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
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type tstRoundTripper struct {
	id     int
	closed atomic.Int32
}

func (t *tstRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.Errorf("tstRoundTripper does not perform requests")
}

func (t *tstRoundTripper) doCloseIdle() {
	t.closed.Add(1)
}

func (t *tstRoundTripper) closedCount() int {
	return int(t.closed.Load())
}

type tstTransportBuilder struct {
	mu           sync.Mutex
	calls        int
	built        []*tstRoundTripper
	err          error
	delay        time.Duration
	nilCloseIdle bool
}

func (b *tstTransportBuilder) build() (http.RoundTripper, func(), error) {
	b.mu.Lock()
	b.calls++
	id := b.calls
	err := b.err
	delay := b.delay
	nilCloseIdle := b.nilCloseIdle
	b.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	if err != nil {
		return nil, nil, err
	}

	ret := &tstRoundTripper{id: id}

	b.mu.Lock()
	b.built = append(b.built, ret)
	b.mu.Unlock()

	if nilCloseIdle {
		return ret, nil, nil
	}

	return ret, ret.doCloseIdle, nil
}

func (b *tstTransportBuilder) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func (b *tstTransportBuilder) allBuilt() []*tstRoundTripper {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*tstRoundTripper(nil), b.built...)
}

func (b *tstTransportBuilder) setErr(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.err = err
}

func (b *tstTransportBuilder) totalClosed() int {
	var ret int
	for _, rt := range b.allBuilt() {
		ret += rt.closedCount()
	}
	return ret
}

func (c *transportCache) tstGetEntry(key string) (*transportEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.m[key]
	return entry, ok
}

func (c *transportCache) tstSetLastUsed(key string, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.m[key]; ok {
		entry.lastUsed = at
	}
}

func TestTransportCacheReusesEntry(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	rt1, err := c.getOrCreate("k1", b.build)
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, rt1)

	for i := 0; i < 10; i++ {
		rt, err := c.getOrCreate("k1", b.build)
		assert.Nil(t, err, "%+v", err)
		assert.Same(t, rt1, rt)
	}

	assert.Equal(t, 1, b.callCount())
	assert.Equal(t, 1, c.Len())
	assert.Equal(t, 0, b.totalClosed())
}

func TestTransportCacheDistinctKeys(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	rt1, err := c.getOrCreate("k1", b.build)
	assert.Nil(t, err, "%+v", err)

	rt2, err := c.getOrCreate("k2", b.build)
	assert.Nil(t, err, "%+v", err)

	assert.NotSame(t, rt1, rt2)
	assert.Equal(t, 2, b.callCount())
	assert.Equal(t, 2, c.Len())
}

func TestTransportCacheUpdatesLastUsedOnHit(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	_, err := c.getOrCreate("k1", b.build)
	assert.Nil(t, err, "%+v", err)

	past := time.Now().Add(-1 * time.Hour)
	c.tstSetLastUsed("k1", past)

	_, err = c.getOrCreate("k1", b.build)
	assert.Nil(t, err, "%+v", err)

	entry, ok := c.tstGetEntry("k1")
	assert.True(t, ok)
	assert.True(t, entry.lastUsed.After(past))
}

func TestTransportCacheBuildError(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{
		err: errors.Errorf("could not resolve the upstream TLS material"),
	}

	rt, err := c.getOrCreate("k1", b.build)
	assert.NotNil(t, err)
	assert.Nil(t, rt)
	assert.Equal(t, 0, c.Len())

	b.setErr(nil)

	rt, err = c.getOrCreate("k1", b.build)
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, rt)
	assert.Equal(t, 1, c.Len())
	assert.Equal(t, 2, b.callCount())
}

func TestTransportCacheConcurrentSameKey(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{
		delay: 50 * time.Millisecond,
	}

	const n = 32

	results := make([]http.RoundTripper, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = c.getOrCreate("k1", b.build)
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		assert.Nil(t, errs[i], "%+v", errs[i])
		assert.NotNil(t, results[i])
		assert.Same(t, results[0], results[i])
	}

	assert.Equal(t, 1, c.Len())
	assert.Equal(t, b.callCount()-1, b.totalClosed())
}

func TestTransportCacheConcurrentDistinctKeys(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	const n = 16

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := c.getOrCreate(fmt.Sprintf("k-%d", i), b.build)
			assert.Nil(t, err, "%+v", err)
		}(i)
	}
	wg.Wait()

	assert.Equal(t, n, c.Len())
	assert.Equal(t, n, b.callCount())
	assert.Equal(t, 0, b.totalClosed())
}

func TestTransportCacheEvictsLeastRecentlyUsed(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	for i := 0; i < transportCacheMaxEntries; i++ {
		_, err := c.getOrCreate(fmt.Sprintf("k-%d", i), b.build)
		assert.Nil(t, err, "%+v", err)
	}

	assert.Equal(t, transportCacheMaxEntries, c.Len())

	victim, ok := c.tstGetEntry("k-7")
	assert.True(t, ok)
	c.tstSetLastUsed("k-7", time.Now().Add(-1*time.Hour))

	_, err := c.getOrCreate("k-new", b.build)
	assert.Nil(t, err, "%+v", err)

	assert.Equal(t, transportCacheMaxEntries, c.Len())

	_, ok = c.tstGetEntry("k-7")
	assert.False(t, ok)

	_, ok = c.tstGetEntry("k-new")
	assert.True(t, ok)

	assert.Eventually(t, func() bool {
		return victim.rt.(*tstRoundTripper).closedCount() == 1
	}, 5*time.Second, 10*time.Millisecond)
}

func TestTransportCacheSweepRemovesUnused(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	_, err := c.getOrCreate("k-stale", b.build)
	assert.Nil(t, err, "%+v", err)

	_, err = c.getOrCreate("k-fresh", b.build)
	assert.Nil(t, err, "%+v", err)

	stale, ok := c.tstGetEntry("k-stale")
	assert.True(t, ok)

	c.tstSetLastUsed("k-stale", time.Now().Add(-2*transportUnusedTTL))

	c.sweep()

	assert.Equal(t, 1, c.Len())

	_, ok = c.tstGetEntry("k-stale")
	assert.False(t, ok)

	_, ok = c.tstGetEntry("k-fresh")
	assert.True(t, ok)

	assert.Equal(t, 1, stale.rt.(*tstRoundTripper).closedCount())
}

func TestTransportCacheSweepKeepsFresh(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	for i := 0; i < 5; i++ {
		_, err := c.getOrCreate(fmt.Sprintf("k-%d", i), b.build)
		assert.Nil(t, err, "%+v", err)
	}

	c.sweep()

	assert.Equal(t, 5, c.Len())
	assert.Equal(t, 0, b.totalClosed())
}

func TestTransportCacheSweepRebuildsAfterRemoval(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	rt1, err := c.getOrCreate("k1", b.build)
	assert.Nil(t, err, "%+v", err)

	c.tstSetLastUsed("k1", time.Now().Add(-2*transportUnusedTTL))
	c.sweep()

	rt2, err := c.getOrCreate("k1", b.build)
	assert.Nil(t, err, "%+v", err)

	assert.NotSame(t, rt1, rt2)
	assert.Equal(t, 2, b.callCount())
	assert.Equal(t, 1, c.Len())
}

func TestTransportCacheCloseAll(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	for i := 0; i < 5; i++ {
		_, err := c.getOrCreate(fmt.Sprintf("k-%d", i), b.build)
		assert.Nil(t, err, "%+v", err)
	}
	assert.Equal(t, 5, c.Len())

	c.closeAll()

	assert.Equal(t, 0, c.Len())
	for _, rt := range b.allBuilt() {
		assert.Equal(t, 1, rt.closedCount())
	}

	assert.NotPanics(t, func() {
		c.closeAll()
	})
	assert.Equal(t, 0, c.Len())
}

func TestTransportCacheSweepLoopClosesOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	c := newTransportCache()
	b := &tstTransportBuilder{}

	c.startSweepLoop(ctx)

	_, err := c.getOrCreate("k1", b.build)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 1, c.Len())

	cancel()

	assert.Eventually(t, func() bool {
		return c.Len() == 0
	}, 5*time.Second, 10*time.Millisecond)

	for _, rt := range b.allBuilt() {
		assert.Equal(t, 1, rt.closedCount())
	}
}

func TestTransportCacheNilCloseIdle(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{
		nilCloseIdle: true,
	}

	_, err := c.getOrCreate("k1", b.build)
	assert.Nil(t, err, "%+v", err)

	c.tstSetLastUsed("k1", time.Now().Add(-2*transportUnusedTTL))

	assert.NotPanics(t, func() {
		c.sweep()
	})
	assert.Equal(t, 0, c.Len())

	_, err = c.getOrCreate("k2", b.build)
	assert.Nil(t, err, "%+v", err)

	assert.NotPanics(t, func() {
		c.closeAll()
	})
	assert.Equal(t, 0, c.Len())
}

func TestTransportCacheRace(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	var wg sync.WaitGroup

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, err := c.getOrCreate(fmt.Sprintf("k-%d", j%8), b.build)
				assert.Nil(t, err, "%+v", err)
				c.Len()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			c.sweep()
			time.Sleep(time.Millisecond)
		}
	}()

	wg.Wait()

	c.closeAll()
	assert.Equal(t, 0, c.Len())
}

func TestConfigHasherNil(t *testing.T) {
	h := &configHasher{}

	ret, err := h.get(nil)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, "no-cfg", ret)
}

func TestConfigHasherDistinctContent(t *testing.T) {
	h := &configHasher{}

	h1, err := h.get(&corev1.Service_Spec_Config{Name: "cfg-1"})
	assert.Nil(t, err, "%+v", err)

	h2, err := h.get(&corev1.Service_Spec_Config{Name: "cfg-2"})
	assert.Nil(t, err, "%+v", err)

	assert.NotEqual(t, h1, h2)
	assert.NotEqual(t, "no-cfg", h1)
}

func TestConfigHasherEqualContentDistinctPointers(t *testing.T) {
	h := &configHasher{}

	h1, err := h.get(&corev1.Service_Spec_Config{Name: "cfg"})
	assert.Nil(t, err, "%+v", err)

	h2, err := h.get(&corev1.Service_Spec_Config{Name: "cfg"})
	assert.Nil(t, err, "%+v", err)

	assert.Equal(t, h1, h2)
}

func TestConfigHasherIsStableAcrossCalls(t *testing.T) {
	h := &configHasher{}

	newCfg := func() *corev1.Service_Spec_Config {

		return &corev1.Service_Spec_Config{
			Name: "cfg",
			Upstream: &corev1.Service_Spec_Config_Upstream{
				Type: &corev1.Service_Spec_Config_Upstream_Url{
					Url: "https://example.com",
				},
			},
		}
	}

	first, err := h.get(newCfg())
	assert.Nil(t, err, "%+v", err)

	for i := 0; i < 50; i++ {
		ret, err := h.get(newCfg())
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, first, ret)
	}
}

func TestConfigHasherMemoizesByPointer(t *testing.T) {
	h := &configHasher{}

	cfg := &corev1.Service_Spec_Config{Name: "cfg-1"}

	h1, err := h.get(cfg)
	assert.Nil(t, err, "%+v", err)

	cfg.Name = "cfg-2"

	h2, err := h.get(cfg)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, h1, h2)

	h3, err := h.get(&corev1.Service_Spec_Config{Name: "cfg-2"})
	assert.Nil(t, err, "%+v", err)
	assert.NotEqual(t, h1, h3)
}

func TestConfigHasherAlternatingPointers(t *testing.T) {
	h := &configHasher{}

	cfg1 := &corev1.Service_Spec_Config{Name: "cfg-1"}
	cfg2 := &corev1.Service_Spec_Config{Name: "cfg-2"}

	first1, err := h.get(cfg1)
	assert.Nil(t, err, "%+v", err)
	first2, err := h.get(cfg2)
	assert.Nil(t, err, "%+v", err)

	for i := 0; i < 20; i++ {
		ret1, err := h.get(cfg1)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, first1, ret1)

		ret2, err := h.get(cfg2)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, first2, ret2)
	}

	assert.NotEqual(t, first1, first2)
}

func TestConfigHasherRace(t *testing.T) {
	h := &configHasher{}

	cfgs := []*corev1.Service_Spec_Config{
		{Name: "cfg-1"},
		{Name: "cfg-2"},
		{Name: "cfg-3"},
		{Name: "cfg-4"},
	}

	expected := make([]string, len(cfgs))
	for i, cfg := range cfgs {
		ret, err := h.get(cfg)
		assert.Nil(t, err, "%+v", err)
		expected[i] = ret
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				idx := j % len(cfgs)
				ret, err := h.get(cfgs[idx])
				assert.Nil(t, err, "%+v", err)
				assert.Equal(t, expected[idx], ret)
			}
		}()
	}
	wg.Wait()
}

func TestTransportCacheKeyDrivenInvalidation(t *testing.T) {
	c := newTransportCache()
	b := &tstTransportBuilder{}

	keyGen1 := fmt.Sprintf("svc=%s;secretManGen=1", utilrand.GetRandomStringCanonical(8))
	keyGen2 := strings.Replace(keyGen1, "secretManGen=1", "secretManGen=2", 1)

	rt1, err := c.getOrCreate(keyGen1, b.build)
	assert.Nil(t, err, "%+v", err)

	rt2, err := c.getOrCreate(keyGen2, b.build)
	assert.Nil(t, err, "%+v", err)

	assert.NotSame(t, rt1, rt2)
	assert.Equal(t, 2, c.Len())

	c.tstSetLastUsed(keyGen1, time.Now().Add(-2*transportUnusedTTL))
	c.sweep()

	assert.Equal(t, 1, c.Len())
	_, ok := c.tstGetEntry(keyGen2)
	assert.True(t, ok)
}
