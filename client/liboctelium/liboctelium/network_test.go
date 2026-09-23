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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNetwork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	n := newNetwork()
	assert.True(t, n.getIsAvailable())

	watchCh := n.watch(ctx)

	isNotified := func() bool {
		select {
		case <-watchCh:
			return true
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}

	{
		_, changeCh := n.get()
		n.set(true, "")
		assert.False(t, isNotified())

		select {
		case <-changeCh:
			t.Fatal("changeCh must not be closed")
		default:
		}
	}

	{
		_, changeCh := n.get()
		n.set(true, "wifi")
		assert.True(t, isNotified())
		<-changeCh
	}

	{
		n.set(true, "wifi")
		assert.False(t, isNotified())
	}

	{
		n.set(false, "")
		assert.False(t, n.getIsAvailable())
		assert.False(t, isNotified())
	}

	{
		n.set(true, "cellular")
		assert.True(t, n.getIsAvailable())
		assert.True(t, isNotified())
	}

	{
		n.set(true, "wifi")
		n.set(true, "cellular")
		assert.True(t, isNotified())
		assert.False(t, isNotified())
	}

	cancel()

	assert.Eventually(t, func() bool {
		n.mu.Lock()
		defer n.mu.Unlock()
		return len(n.watchers) == 0
	}, 5*time.Second, 10*time.Millisecond)
}

func TestNetworkWaitReconnect(t *testing.T) {

	{
		n := newNetwork()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		assert.ErrorIs(t, n.waitReconnect(ctx, 1), context.Canceled)
	}

	{
		n := newNetwork()
		n.set(false, "")

		doneCh := make(chan error, 1)
		go func() {
			doneCh <- n.waitReconnect(context.Background(), 100)
		}()

		select {
		case <-doneCh:
			t.Fatal("waitReconnect must block while the network is unavailable")
		case <-time.After(100 * time.Millisecond):
		}

		n.set(false, "other")

		select {
		case <-doneCh:
			t.Fatal("waitReconnect must block while the network is unavailable")
		case <-time.After(100 * time.Millisecond):
		}

		n.set(true, "wifi")

		select {
		case err := <-doneCh:
			assert.Nil(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("waitReconnect did not return after the network became available")
		}
	}

	{
		n := newNetwork()
		n.set(true, "wifi")

		doneCh := make(chan error, 1)
		go func() {
			doneCh <- n.waitReconnect(context.Background(), 100)
		}()

		time.Sleep(50 * time.Millisecond)
		n.set(true, "cellular")

		select {
		case err := <-doneCh:
			assert.Nil(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("waitReconnect did not return after the network changed")
		}
	}

	{
		n := newNetwork()

		ctx, cancel := context.WithCancel(context.Background())

		doneCh := make(chan error, 1)
		go func() {
			doneCh <- n.waitReconnect(ctx, 100)
		}()

		time.Sleep(50 * time.Millisecond)
		cancel()

		select {
		case err := <-doneCh:
			assert.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Fatal("waitReconnect did not return after the context was canceled")
		}
	}
}

func TestGetReconnectBackoff(t *testing.T) {
	for range 100 {
		var prev time.Duration

		for attempt := 1; attempt < 20; attempt++ {
			ret := getReconnectBackoff(attempt)

			assert.GreaterOrEqual(t, ret, reconnectBackoffMin)
			assert.LessOrEqual(t, ret, reconnectBackoffMax)
			assert.GreaterOrEqual(t, ret, prev)

			prev = ret
		}
	}

	assert.Equal(t, reconnectBackoffMax, getReconnectBackoff(20))

	ret := getReconnectBackoff(0)
	assert.GreaterOrEqual(t, ret, reconnectBackoffMin)
	assert.LessOrEqual(t, ret, reconnectBackoffMin+reconnectBackoffMin/2)
}
