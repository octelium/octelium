// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package liboctelium

import (
	"context"
	"sync"
	"time"

	"github.com/octelium/octelium/pkg/utils/utilrand"
)

const (
	reconnectBackoffMin = 2 * time.Second
	reconnectBackoffMax = 2 * time.Minute
)

type network struct {
	mu          sync.Mutex
	isAvailable bool
	id          string
	changeCh    chan struct{}
	watchers    map[chan struct{}]struct{}
}

func newNetwork() *network {
	return &network{
		isAvailable: true,
		changeCh:    make(chan struct{}),
		watchers:    make(map[chan struct{}]struct{}),
	}
}

func (n *network) set(isAvailable bool, id string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.isAvailable == isAvailable && n.id == id {
		return
	}

	n.isAvailable = isAvailable
	n.id = id

	close(n.changeCh)
	n.changeCh = make(chan struct{})

	if !isAvailable {
		return
	}

	for w := range n.watchers {
		select {
		case w <- struct{}{}:
		default:
		}
	}
}

func (n *network) get() (bool, chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.isAvailable, n.changeCh
}

func (n *network) getIsAvailable() bool {
	isAvailable, _ := n.get()
	return isAvailable
}

func (n *network) watch(ctx context.Context) <-chan struct{} {
	ret := make(chan struct{}, 1)

	n.mu.Lock()
	n.watchers[ret] = struct{}{}
	n.mu.Unlock()

	go func() {
		<-ctx.Done()

		n.mu.Lock()
		delete(n.watchers, ret)
		n.mu.Unlock()
	}()

	return ret
}

func (n *network) waitReconnect(ctx context.Context, attempt int) error {
	timer := time.NewTimer(getReconnectBackoff(attempt))
	defer timer.Stop()

	for {
		isAvailable, changeCh := n.get()

		var timerCh <-chan time.Time
		if isAvailable {
			timerCh = timer.C
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timerCh:
			return nil
		case <-changeCh:
			if n.getIsAvailable() {
				return nil
			}
		}
	}
}

func getReconnectBackoff(attempt int) time.Duration {
	ret := reconnectBackoffMin << min(max(attempt-1, 0), 6)
	if ret > reconnectBackoffMax {
		ret = reconnectBackoffMax
	}

	jitterMax := min(ret/2, reconnectBackoffMax-ret)
	return ret + time.Duration(utilrand.GetRandomRangeMath(0,
		int(jitterMax/time.Millisecond)))*time.Millisecond
}
