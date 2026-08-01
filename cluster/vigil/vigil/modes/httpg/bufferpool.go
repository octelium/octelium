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

import "sync"

const bufferPoolSize = 32 * 1024

var sharedBufferPool = newBufferPool()

func newBufferPool() *bufferPool {
	return &bufferPool{
		pool: sync.Pool{
			New: func() any {
				buf := make([]byte, bufferPoolSize)
				return &buf
			},
		},
	}
}

type bufferPool struct {
	pool sync.Pool
}

func (b *bufferPool) Get() []byte {
	return *(b.pool.Get().(*[]byte))
}

func (b *bufferPool) Put(buf []byte) {
	if cap(buf) != bufferPoolSize {
		return
	}

	buf = buf[:bufferPoolSize]
	b.pool.Put(&buf)
}
