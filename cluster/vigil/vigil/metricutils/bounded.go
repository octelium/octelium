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

package metricutils

import (
	"slices"
	"sync"
)

const (
	ValueUnset   = "UNSET"
	ValueOther   = "OTHER"
	ValueUnknown = "UNKNOWN"
	ValueNone    = "NONE"
)

const maxBoundedValueLen = 128

func Bounded(arg string, allowed map[string]struct{}) string {
	if arg == "" {
		return ValueUnset
	}
	if _, ok := allowed[arg]; ok {
		return arg
	}
	return ValueOther
}

func BoundedSlice(arg string, allowed []string) string {
	if arg == "" {
		return ValueUnset
	}
	if slices.Contains(allowed, arg) {
		return arg
	}
	return ValueOther
}

type BoundedValues struct {
	mu   sync.RWMutex
	max  int
	vals map[string]struct{}
}

func NewBoundedValues(max int) *BoundedValues {
	if max <= 0 {
		max = 1
	}
	return &BoundedValues{
		max:  max,
		vals: make(map[string]struct{}, max),
	}
}

func (b *BoundedValues) Get(arg string) string {
	if arg == "" {
		return ValueUnset
	}
	if len(arg) > maxBoundedValueLen {
		return ValueOther
	}

	b.mu.RLock()
	_, ok := b.vals[arg]
	isFull := len(b.vals) >= b.max
	b.mu.RUnlock()

	if ok {
		return arg
	}
	if isFull {
		return ValueOther
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.vals[arg]; ok {
		return arg
	}
	if len(b.vals) >= b.max {
		return ValueOther
	}

	b.vals[arg] = struct{}{}
	return arg
}
