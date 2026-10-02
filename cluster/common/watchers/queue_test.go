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

package watchers

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func isTstQueueEmpty(q *keyedQueue) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	return len(q.queues) == 0
}

func TestKeyedQueueOrder(t *testing.T) {

	ctx := context.Background()

	q := &keyedQueue{}

	var mu sync.Mutex
	res := make(map[string][]int)

	keys := []string{"a", "b", "c", "d"}

	for i := range 200 {
		for _, key := range keys {
			q.enqueue(ctx, key, func(ctx context.Context) {
				time.Sleep(time.Duration(utilrand.GetRandomRangeMath(0, 200)) * time.Microsecond)
				mu.Lock()
				res[key] = append(res[key], i)
				mu.Unlock()
			})
		}
	}

	assert.Eventually(t, func() bool {
		return isTstQueueEmpty(q)
	}, 30*time.Second, 10*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	for _, key := range keys {
		assert.Equal(t, 200, len(res[key]), key)
		for i, val := range res[key] {
			assert.Equal(t, i, val, key)
		}
	}
}

func TestKeyedQueueConcurrentKeys(t *testing.T) {

	ctx := context.Background()

	q := &keyedQueue{}

	releaseCh := make(chan struct{})
	startedCh := make(chan struct{})
	doneCh := make(chan string, 16)

	q.enqueue(ctx, "blocked", func(ctx context.Context) {
		close(startedCh)
		<-releaseCh
		doneCh <- "blocked-0"
	})

	q.enqueue(ctx, "blocked", func(ctx context.Context) {
		doneCh <- "blocked-1"
	})

	<-startedCh

	for i := range 5 {
		q.enqueue(ctx, fmt.Sprintf("other-%d", i), func(ctx context.Context) {
			doneCh <- fmt.Sprintf("other-%d", i)
		})
	}

	others := make(map[string]bool)
	for range 5 {
		select {
		case res := <-doneCh:
			others[res] = true
		case <-time.After(5 * time.Second):
			t.Fatal("other keys are blocked by a slow key")
		}
	}

	for i := range 5 {
		assert.True(t, others[fmt.Sprintf("other-%d", i)])
	}

	select {
	case res := <-doneCh:
		t.Fatalf("Unexpected task completion while the key is blocked: %s", res)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseCh)

	assert.Equal(t, "blocked-0", <-doneCh)
	assert.Equal(t, "blocked-1", <-doneCh)

	assert.Eventually(t, func() bool {
		return isTstQueueEmpty(q)
	}, 5*time.Second, 10*time.Millisecond)
}

func TestKeyedQueueRestart(t *testing.T) {

	ctx := context.Background()

	q := &keyedQueue{}

	for i := range 3 {
		doneCh := make(chan struct{})
		q.enqueue(ctx, "key", func(ctx context.Context) {
			close(doneCh)
		})

		select {
		case <-doneCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("Task %d did not run", i)
		}

		assert.Eventually(t, func() bool {
			return isTstQueueEmpty(q)
		}, 5*time.Second, 10*time.Millisecond)
	}
}

func TestKeyedQueueCancel(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())

	q := &keyedQueue{}

	releaseCh := make(chan struct{})
	startedCh := make(chan struct{})

	var mu sync.Mutex
	ran := 0

	q.enqueue(ctx, "key", func(ctx context.Context) {
		close(startedCh)
		<-releaseCh
		assert.NotNil(t, ctx.Err())
	})

	for range 10 {
		q.enqueue(ctx, "key", func(ctx context.Context) {
			mu.Lock()
			ran++
			mu.Unlock()
		})
	}

	<-startedCh
	cancel()
	close(releaseCh)

	assert.Eventually(t, func() bool {
		return isTstQueueEmpty(q)
	}, 5*time.Second, 10*time.Millisecond)

	mu.Lock()
	assert.Equal(t, 0, ran)
	mu.Unlock()
}
