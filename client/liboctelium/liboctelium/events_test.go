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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/stretchr/testify/assert"
)

type fakeHost struct {
	mu       sync.Mutex
	events   []*mobilev1.Event
	requests map[uint64]*mobilev1.PlatformRequest
	onReq    func(id uint64, req *mobilev1.PlatformRequest)
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		requests: make(map[uint64]*mobilev1.PlatformRequest),
	}
}

func (h *fakeHost) SendEvent(ev *mobilev1.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.events = append(h.events, ev)
}

func (h *fakeHost) SendPlatformRequest(id uint64, req *mobilev1.PlatformRequest) {
	h.mu.Lock()
	h.requests[id] = req
	onReq := h.onReq
	h.mu.Unlock()

	if onReq != nil {
		onReq(id, req)
	}
}

func (h *fakeHost) getStatusEvents() []*daemonv1.GetStatusResponse {
	h.mu.Lock()
	defer h.mu.Unlock()

	var ret []*daemonv1.GetStatusResponse
	for _, ev := range h.events {
		if ev.GetStatus() != nil {
			ret = append(ret, ev.GetStatus())
		}
	}

	return ret
}

func (h *fakeHost) getLogEvents() []*mobilev1.Log {
	h.mu.Lock()
	defer h.mu.Unlock()

	var ret []*mobilev1.Log
	for _, ev := range h.events {
		if ev.GetLog() != nil {
			ret = append(ret, ev.GetLog())
		}
	}

	return ret
}

func (h *fakeHost) getRequestCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.requests)
}

func TestEventDispatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	host := newFakeHost()

	var revision uint64
	var mu sync.Mutex

	d := newEventDispatcher(host, func() *daemonv1.GetStatusResponse {
		mu.Lock()
		defer mu.Unlock()
		return &daemonv1.GetStatusResponse{
			Revision: revision,
		}
	})

	for range 10 {
		d.notifyStatus()
	}

	for i := range logQueueSize + 10 {
		d.sendLog(&mobilev1.Log{
			Message: string(rune('a' + i%26)),
		})
	}

	go d.run(ctx)

	assert.Eventually(t, func() bool {
		return len(host.getStatusEvents()) == 1 && len(host.getLogEvents()) == logQueueSize
	}, 5*time.Second, 10*time.Millisecond)

	mu.Lock()
	revision = 5
	mu.Unlock()
	d.notifyStatus()

	assert.Eventually(t, func() bool {
		statuses := host.getStatusEvents()
		return len(statuses) == 2 && statuses[1].Revision == 5
	}, 5*time.Second, 10*time.Millisecond)

	cancel()
	d.wait()

	d.notifyStatus()
	d.sendLog(&mobilev1.Log{})
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 2, len(host.getStatusEvents()))
	assert.Equal(t, logQueueSize, len(host.getLogEvents()))
}
