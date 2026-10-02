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
	"sync"
)

type keyedQueue struct {
	mu     sync.Mutex
	queues map[string][]func(ctx context.Context)
}

func (q *keyedQueue) enqueue(ctx context.Context, key string, fn func(ctx context.Context)) {
	q.mu.Lock()
	if q.queues == nil {
		q.queues = make(map[string][]func(ctx context.Context))
	}

	pending, isRunning := q.queues[key]
	q.queues[key] = append(pending, fn)
	q.mu.Unlock()

	if !isRunning {
		go q.run(ctx, key)
	}
}

func (q *keyedQueue) next(key string) (func(ctx context.Context), bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.queues[key]
	if len(pending) == 0 {
		delete(q.queues, key)
		return nil, false
	}

	fn := pending[0]
	pending[0] = nil
	q.queues[key] = pending[1:]

	return fn, true
}

func (q *keyedQueue) run(ctx context.Context, key string) {
	for {
		fn, ok := q.next(key)
		if !ok {
			return
		}

		if ctx.Err() == nil {
			fn(ctx)
		}
	}
}
