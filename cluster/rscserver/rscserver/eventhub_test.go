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

package rscserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func newTestKind() string {
	return fmt.Sprintf("Tst%s", utilrand.GetRandomStringCanonical(10))
}

func newTestWatchEvent(api, version, kind, name string) *rmetav1.WatchEvent {
	return &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			ApiVersion: vutils.GetApiVersion(api, version),
			Kind:       kind,
			Type: &rmetav1.WatchEvent_Event_Create_{
				Create: &rmetav1.WatchEvent_Event_Create{
					Item: pbutils.MessageToAnyMust(&corev1.User{
						Metadata: &metav1.Metadata{
							Name: name,
							Uid:  vutils.UUIDv4(),
						},
						Spec:   &corev1.User_Spec{},
						Status: &corev1.User_Status{},
					}),
				},
			},
		},
	}
}

func waitForEvent(sub *eventSubscriber, d time.Duration) *rmetav1.WatchEvent {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case ev := <-sub.ch:
		return ev
	case <-timer.C:
		return nil
	}
}

func waitForDone(sub *eventSubscriber, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-sub.Done():
		return true
	case <-timer.C:
		return false
	}
}

func getEventName(ev *rmetav1.WatchEvent) string {
	usr := &corev1.User{}
	if err := ev.GetEvent().GetCreate().GetItem().UnmarshalTo(usr); err != nil {
		return ""
	}
	return usr.Metadata.Name
}

func TestStreamID(t *testing.T) {
	{
		ms, seq, err := parseStreamID("1700000000000-7")
		assert.Nil(t, err)
		assert.Equal(t, uint64(1700000000000), ms)
		assert.Equal(t, uint64(7), seq)
	}
	{
		ms, seq, err := parseStreamID("1700000000000")
		assert.Nil(t, err)
		assert.Equal(t, uint64(1700000000000), ms)
		assert.Equal(t, uint64(0), seq)
	}
	{
		ms, seq, err := parseStreamID(streamIDZero)
		assert.Nil(t, err)
		assert.Equal(t, uint64(0), ms)
		assert.Equal(t, uint64(0), seq)
	}
	{
		_, _, err := parseStreamID("")
		assert.NotNil(t, err)
	}
	{
		_, _, err := parseStreamID("abc-1")
		assert.NotNil(t, err)
	}
	{
		_, _, err := parseStreamID("100-abc")
		assert.NotNil(t, err)
	}

	assert.Equal(t, 1, compareStreamIDs("1700000000000-10", "1700000000000-5"))
	assert.Equal(t, -1, compareStreamIDs("1700000000000-5", "1700000000000-10"))
	assert.Equal(t, 0, compareStreamIDs("1700000000000-5", "1700000000000-5"))
	assert.Equal(t, 1, compareStreamIDs("1700000000001-0", "1700000000000-999"))
	assert.Equal(t, -1, compareStreamIDs("1700000000000-999", "1700000000001-0"))
	assert.Equal(t, 1, compareStreamIDs("1-0", streamIDZero))
	assert.Equal(t, -1, compareStreamIDs(streamIDZero, "1-0"))
	assert.Equal(t, 0, compareStreamIDs(streamIDZero, streamIDZero))
}

func TestRscStreamKey(t *testing.T) {
	type entry struct {
		api     string
		version string
		kind    string
	}

	entries := []entry{
		{"core", "v1", ucorev1.KindSession},
		{"core", "v1", ucorev1.KindClusterConfig},
		{"access", "v1", "Request"},
		{"enterprise", "v1", "SecretStore"},
	}

	for _, e := range entries {
		streamKey := getRscStreamKey(e.api, e.version, e.kind)

		api, version, kind, err := parseRscStreamKey(streamKey)
		assert.Nil(t, err)
		assert.Equal(t, e.api, api)
		assert.Equal(t, e.version, version)
		assert.Equal(t, e.kind, kind)
	}

	assert.NotEqual(t,
		getRscStreamKey("core", "v1", ucorev1.KindUser),
		getRscStreamKey("core", "v1", ucorev1.KindGroup))

	assert.NotEqual(t,
		getRscStreamKey("core", "v1", ucorev1.KindUser),
		getRscStreamKey("core", "v2", ucorev1.KindUser))

	invalids := []string{
		"",
		"octelium:rsc:stream:core:v1",
		"octelium:rsc:stream:core:v1:Session:extra",
		"octelium:rsc:stream:",
		"octelium:rsc:stream:::Session",
		utilrand.GetRandomStringCanonical(16),
	}

	for _, invalid := range invalids {
		_, _, _, err := parseRscStreamKey(invalid)
		assert.NotNil(t, err, "%s", invalid)
	}
}

func TestEventHubDispatchBarrier(t *testing.T) {
	ctx := context.Background()

	h := newEventHub(redisutils.NewClient())

	api := "core"
	version := "v1"
	kind := newTestKind()
	streamKey := getRscStreamKey(api, version, kind)

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sub := &eventSubscriber{
		streamKey: streamKey,
		barrierID: "1000-5",
		ch:        make(chan *rmetav1.WatchEvent, watchQueueSize),
		ctx:       subCtx,
		cancel:    cancel,
	}

	h.mu.Lock()
	h.subs[streamKey] = map[*eventSubscriber]struct{}{sub: {}}
	h.cursors[streamKey] = "1000-5"
	h.mu.Unlock()

	h.dispatch(streamKey, "999-0", newTestWatchEvent(api, version, kind, "older"))
	assert.Nil(t, waitForEvent(sub, 200*time.Millisecond))

	h.dispatch(streamKey, "1000-5", newTestWatchEvent(api, version, kind, "equal"))
	assert.Nil(t, waitForEvent(sub, 200*time.Millisecond))

	h.dispatch(streamKey, "1000-4", newTestWatchEvent(api, version, kind, "olderSeq"))
	assert.Nil(t, waitForEvent(sub, 200*time.Millisecond))

	h.dispatch(streamKey, "1000-6", newTestWatchEvent(api, version, kind, "newerSeq"))
	ev := waitForEvent(sub, 2*time.Second)
	assert.NotNil(t, ev)
	assert.Equal(t, "newerSeq", getEventName(ev))

	h.dispatch(streamKey, "1001-0", newTestWatchEvent(api, version, kind, "newerMS"))
	ev = waitForEvent(sub, 2*time.Second)
	assert.NotNil(t, ev)
	assert.Equal(t, "newerMS", getEventName(ev))
}

func TestEventHubDispatchOverflow(t *testing.T) {
	ctx := context.Background()

	h := newEventHub(redisutils.NewClient())

	api := "core"
	version := "v1"
	kind := newTestKind()
	streamKey := getRscStreamKey(api, version, kind)

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sub := &eventSubscriber{
		streamKey: streamKey,
		barrierID: streamIDZero,
		ch:        make(chan *rmetav1.WatchEvent, watchQueueSize),
		ctx:       subCtx,
		cancel:    cancel,
	}

	h.mu.Lock()
	h.subs[streamKey] = map[*eventSubscriber]struct{}{sub: {}}
	h.cursors[streamKey] = streamIDZero
	h.mu.Unlock()

	for i := range watchQueueSize {
		h.dispatch(streamKey, fmt.Sprintf("1-%d", i+1),
			newTestWatchEvent(api, version, kind, fmt.Sprintf("ev-%d", i)))
	}

	assert.False(t, waitForDone(sub, 200*time.Millisecond))
	assert.True(t, h.hasSubscribers(streamKey))

	for i := range 10 {
		h.dispatch(streamKey, fmt.Sprintf("2-%d", i+1),
			newTestWatchEvent(api, version, kind, fmt.Sprintf("overflow-%d", i)))
	}

	assert.True(t, waitForDone(sub, 2*time.Second))
	assert.False(t, h.hasSubscribers(streamKey))
}

func TestEventHubLive(t *testing.T) {
	ctx := context.Background()

	redisC := redisutils.NewClient()
	srv := &Server{redisC: redisC}

	h := newEventHub(redisC)
	assert.Nil(t, h.Start(ctx))
	defer h.Stop()

	api := "core"
	version := "v1"
	kind := newTestKind()

	t.Cleanup(func() {
		redisC.Del(context.Background(), getRscStreamKey(api, version, kind))
	})

	for i := range 3 {
		assert.Nil(t, srv.publishMessage(ctx, api, version, kind,
			newTestWatchEvent(api, version, kind, fmt.Sprintf("before-%d", i))))
	}

	sub, err := h.subscribe(ctx, api, version, kind)
	assert.Nil(t, err)

	assert.Nil(t, waitForEvent(sub, 1*time.Second))

	for i := range 5 {
		assert.Nil(t, srv.publishMessage(ctx, api, version, kind,
			newTestWatchEvent(api, version, kind, fmt.Sprintf("after-%d", i))))
	}

	for i := range 5 {
		ev := waitForEvent(sub, 10*time.Second)
		assert.NotNil(t, ev)
		assert.Equal(t, fmt.Sprintf("after-%d", i), getEventName(ev))
	}

	h.unsubscribe(sub)

	assert.Nil(t, srv.publishMessage(ctx, api, version, kind,
		newTestWatchEvent(api, version, kind, "post-unsubscribe")))

	assert.Nil(t, waitForEvent(sub, 1*time.Second))

	h.mu.RLock()
	_, hasCursor := h.cursors[getRscStreamKey(api, version, kind)]
	h.mu.RUnlock()
	assert.False(t, hasCursor)
}

func TestEventHubMultipleSubscribers(t *testing.T) {
	ctx := context.Background()

	redisC := redisutils.NewClient()
	srv := &Server{redisC: redisC}

	h := newEventHub(redisC)
	assert.Nil(t, h.Start(ctx))
	defer h.Stop()

	api := "core"
	version := "v1"
	kindA := newTestKind()
	kindB := newTestKind()

	t.Cleanup(func() {
		redisC.Del(context.Background(),
			getRscStreamKey(api, version, kindA), getRscStreamKey(api, version, kindB))
	})

	subA1, err := h.subscribe(ctx, api, version, kindA)
	assert.Nil(t, err)
	subA2, err := h.subscribe(ctx, api, version, kindA)
	assert.Nil(t, err)
	subB, err := h.subscribe(ctx, api, version, kindB)
	assert.Nil(t, err)

	assert.Nil(t, srv.publishMessage(ctx, api, version, kindA,
		newTestWatchEvent(api, version, kindA, "onA")))

	evA1 := waitForEvent(subA1, 10*time.Second)
	assert.NotNil(t, evA1)
	assert.Equal(t, "onA", getEventName(evA1))

	evA2 := waitForEvent(subA2, 10*time.Second)
	assert.NotNil(t, evA2)
	assert.Equal(t, "onA", getEventName(evA2))

	assert.Nil(t, waitForEvent(subB, 1*time.Second))

	assert.Nil(t, srv.publishMessage(ctx, api, version, kindB,
		newTestWatchEvent(api, version, kindB, "onB")))

	evB := waitForEvent(subB, 10*time.Second)
	assert.NotNil(t, evB)
	assert.Equal(t, "onB", getEventName(evB))

	assert.Nil(t, waitForEvent(subA1, 1*time.Second))
}

func TestEventHubWakeOnNewKind(t *testing.T) {
	ctx := context.Background()

	redisC := redisutils.NewClient()
	srv := &Server{redisC: redisC}

	h := newEventHub(redisC)
	assert.Nil(t, h.Start(ctx))
	defer h.Stop()

	api := "core"
	version := "v1"
	kindA := newTestKind()
	kindB := newTestKind()

	t.Cleanup(func() {
		redisC.Del(context.Background(),
			getRscStreamKey(api, version, kindA), getRscStreamKey(api, version, kindB))
	})

	subA, err := h.subscribe(ctx, api, version, kindA)
	assert.Nil(t, err)
	assert.NotNil(t, subA)

	time.Sleep(1 * time.Second)

	subB, err := h.subscribe(ctx, api, version, kindB)
	assert.Nil(t, err)

	assert.Nil(t, srv.publishMessage(ctx, api, version, kindB,
		newTestWatchEvent(api, version, kindB, "wake")))

	ev := waitForEvent(subB, 10*time.Second)
	assert.NotNil(t, ev)
	assert.Equal(t, "wake", getEventName(ev))
}

func TestEventHubMalformedEntry(t *testing.T) {
	ctx := context.Background()

	redisC := redisutils.NewClient()

	h := newEventHub(redisC)
	assert.Nil(t, h.Start(ctx))
	defer h.Stop()

	api := "core"
	version := "v1"
	kind := newTestKind()
	streamKey := getRscStreamKey(api, version, kind)

	t.Cleanup(func() {
		redisC.Del(context.Background(), streamKey)
	})

	sub, err := h.subscribe(ctx, api, version, kind)
	assert.Nil(t, err)

	assert.Nil(t, redisC.XAdd(ctx, &redis.XAddArgs{
		Stream: streamKey,
		Values: map[string]any{
			"unexpected": "field",
		},
	}).Err())

	assert.True(t, waitForDone(sub, 15*time.Second))
	assert.False(t, h.hasSubscribers(streamKey))
}

func TestEventHubMismatchedKind(t *testing.T) {
	ctx := context.Background()

	redisC := redisutils.NewClient()
	srv := &Server{redisC: redisC}

	h := newEventHub(redisC)
	assert.Nil(t, h.Start(ctx))
	defer h.Stop()

	api := "core"
	version := "v1"
	kind := newTestKind()
	otherKind := newTestKind()
	streamKey := getRscStreamKey(api, version, kind)

	t.Cleanup(func() {
		redisC.Del(context.Background(), streamKey)
	})

	sub, err := h.subscribe(ctx, api, version, kind)
	assert.Nil(t, err)

	assert.Nil(t, srv.publishMessage(ctx, api, version, kind,
		newTestWatchEvent(api, version, otherKind, "mismatched")))

	assert.True(t, waitForDone(sub, 15*time.Second))
	assert.False(t, h.hasSubscribers(streamKey))
}

func TestEventHubLifecycle(t *testing.T) {
	ctx := context.Background()

	redisC := redisutils.NewClient()

	h := newEventHub(redisC)

	assert.Nil(t, h.Start(ctx))
	assert.Nil(t, h.Start(ctx))

	api := "core"
	version := "v1"
	kind := newTestKind()

	t.Cleanup(func() {
		redisC.Del(context.Background(), getRscStreamKey(api, version, kind))
	})

	sub, err := h.subscribe(ctx, api, version, kind)
	assert.Nil(t, err)

	h.Stop()
	h.Stop()

	assert.True(t, waitForDone(sub, 2*time.Second))

	select {
	case <-h.doneCh:
	case <-time.After(2 * time.Second):
		assert.True(t, false)
	}

	assert.False(t, h.hasSubscribers(getRscStreamKey(api, version, kind)))
}

func TestEventHubStopWithoutStart(t *testing.T) {
	h := newEventHub(redisutils.NewClient())
	h.Stop()
	h.Stop()
}
