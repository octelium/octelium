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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	watchQueueSize = 4096

	streamReadCount    = 500
	streamReadBlock    = 30 * time.Second
	streamRetryBackoff = 500 * time.Millisecond
	streamStopTimeout  = 10 * time.Second

	streamIDZero = "0-0"
)

func parseStreamID(id string) (uint64, uint64, error) {
	ms, seq, found := strings.Cut(id, "-")

	msVal, err := strconv.ParseUint(ms, 10, 64)
	if err != nil {
		return 0, 0, errors.Errorf("Invalid stream ID: %s", id)
	}

	if !found {
		return msVal, 0, nil
	}

	seqVal, err := strconv.ParseUint(seq, 10, 64)
	if err != nil {
		return 0, 0, errors.Errorf("Invalid stream ID: %s", id)
	}

	return msVal, seqVal, nil
}

func compareStreamIDs(a, b string) int {
	aMS, aSeq, err := parseStreamID(a)
	if err != nil {
		return 0
	}

	bMS, bSeq, err := parseStreamID(b)
	if err != nil {
		return 0
	}

	switch {
	case aMS > bMS:
		return 1
	case aMS < bMS:
		return -1
	case aSeq > bSeq:
		return 1
	case aSeq < bSeq:
		return -1
	default:
		return 0
	}
}

type eventSubscriber struct {
	streamKey string
	barrierID string

	ch chan *rmetav1.WatchEvent

	ctx    context.Context
	cancel context.CancelFunc
}

func (sub *eventSubscriber) Done() <-chan struct{} {
	return sub.ctx.Done()
}

func (sub *eventSubscriber) enqueue(ev *rmetav1.WatchEvent) bool {
	if sub.ctx.Err() != nil {
		return true
	}

	select {
	case sub.ch <- ev:
		return true
	default:
		return false
	}
}

type eventHub struct {
	redisC *redis.Client

	mu      sync.RWMutex
	subs    map[string]map[*eventSubscriber]struct{}
	cursors map[string]string

	readMu     sync.Mutex
	readCancel context.CancelFunc

	readGeneration atomic.Uint64

	startOnce sync.Once
	stopOnce  sync.Once
	startErr  error

	cancel context.CancelFunc
	doneCh chan struct{}
}

func newEventHub(redisC *redis.Client) *eventHub {
	return &eventHub{
		redisC:  redisC,
		subs:    make(map[string]map[*eventSubscriber]struct{}),
		cursors: make(map[string]string),
		doneCh:  make(chan struct{}),
	}
}

func (h *eventHub) Start(ctx context.Context) error {
	h.startOnce.Do(func() {
		if err := h.redisC.Ping(ctx).Err(); err != nil {
			h.startErr = errors.Errorf("Could not reach Redis to start the rsc event hub: %+v", err)
			return
		}

		hubCtx, cancel := context.WithCancel(ctx)
		h.cancel = cancel

		go h.run(hubCtx)

		zap.L().Debug("The rsc event hub is now running")
	})

	return h.startErr
}

func (h *eventHub) Stop() {
	h.stopOnce.Do(func() {
		if h.cancel == nil {
			h.closeAll()
			return
		}

		h.cancel()
		h.wakeReader()

		timer := time.NewTimer(streamStopTimeout)
		defer timer.Stop()

		select {
		case <-h.doneCh:
		case <-timer.C:
			zap.L().Warn("Timed out while waiting for the rsc event hub to exit")
		}

		h.closeAll()
	})
}

func (h *eventHub) getLastID(ctx context.Context, streamKey string) (string, error) {
	res, err := h.redisC.XRevRangeN(ctx, streamKey, "+", "-", 1).Result()
	if err != nil {
		if err == redis.Nil {
			return streamIDZero, nil
		}
		return "", err
	}

	if len(res) == 0 {
		return streamIDZero, nil
	}

	return res[0].ID, nil
}

func (h *eventHub) getFirstID(ctx context.Context, streamKey string) (string, error) {
	res, err := h.redisC.XRangeN(ctx, streamKey, "-", "+", 1).Result()
	if err != nil {
		if err == redis.Nil {
			return "", nil
		}
		return "", err
	}

	if len(res) == 0 {
		return "", nil
	}

	return res[0].ID, nil
}

func (h *eventHub) wakeReader() {
	h.readGeneration.Add(1)

	h.readMu.Lock()
	cancel := h.readCancel
	h.readMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (h *eventHub) subscribe(ctx context.Context, api, version, kind string) (*eventSubscriber, error) {
	streamKey := getRscStreamKey(api, version, kind)

	barrierID, err := h.getLastID(ctx, streamKey)
	if err != nil {
		return nil, errors.Errorf("Could not get the current stream position: %+v", err)
	}

	subCtx, cancel := context.WithCancel(ctx)

	sub := &eventSubscriber{
		streamKey: streamKey,
		barrierID: barrierID,
		ch:        make(chan *rmetav1.WatchEvent, watchQueueSize),
		ctx:       subCtx,
		cancel:    cancel,
	}

	h.mu.Lock()
	if _, ok := h.subs[streamKey]; !ok {
		h.subs[streamKey] = make(map[*eventSubscriber]struct{})
	}
	h.subs[streamKey][sub] = struct{}{}

	_, hasCursor := h.cursors[streamKey]
	if !hasCursor {
		h.cursors[streamKey] = barrierID
	}
	h.mu.Unlock()

	if !hasCursor {
		h.wakeReader()
	}

	zap.L().Debug("Registered a new Watch subscriber",
		zap.String("stream", streamKey), zap.String("barrier", barrierID))

	return sub, nil
}

func (h *eventHub) unsubscribe(sub *eventSubscriber) {
	h.mu.Lock()
	if subs, ok := h.subs[sub.streamKey]; ok {
		delete(subs, sub)
		if len(subs) == 0 {
			delete(h.subs, sub.streamKey)
			delete(h.cursors, sub.streamKey)
		}
	}
	h.mu.Unlock()

	sub.cancel()

	zap.L().Debug("Removed a Watch subscriber", zap.String("stream", sub.streamKey))
}

func (h *eventHub) hasSubscribers(streamKey string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return len(h.subs[streamKey]) > 0
}

func (h *eventHub) dispatch(streamKey, id string, ev *rmetav1.WatchEvent) {
	var overflowed []*eventSubscriber

	h.mu.RLock()
	for sub := range h.subs[streamKey] {
		if compareStreamIDs(id, sub.barrierID) <= 0 {
			continue
		}

		if !sub.enqueue(ev) {
			overflowed = append(overflowed, sub)
		}
	}
	h.mu.RUnlock()

	for _, sub := range overflowed {
		zap.L().Warn("Watch subscriber queue is full. Closing the subscriber",
			zap.String("stream", streamKey))
		h.unsubscribe(sub)
	}
}

func (h *eventHub) handleMessage(streamKey, api, version, kind string, msg redis.XMessage) error {
	dataI, ok := msg.Values[rscStreamFieldData]
	if !ok {
		return errors.Errorf("The stream entry has no data field")
	}

	data, ok := dataI.(string)
	if !ok {
		return errors.Errorf("The stream entry data field is not a string")
	}

	ev := &rmetav1.WatchEvent{}
	if err := pbutils.Unmarshal([]byte(data), ev); err != nil {
		return errors.Errorf("Could not unmarshal the Watch event: %+v", err)
	}

	if ev.Event == nil {
		return errors.Errorf("The Watch event has no event")
	}

	if ev.Event.ApiVersion != vutils.GetApiVersion(api, version) {
		return errors.Errorf("Mismatched Watch event apiVersion: %s", ev.Event.ApiVersion)
	}

	if ev.Event.Kind != kind {
		return errors.Errorf("Mismatched Watch event kind: %s", ev.Event.Kind)
	}

	h.dispatch(streamKey, msg.ID, ev)

	return nil
}

func (h *eventHub) getReadArgs() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if len(h.cursors) == 0 {
		return nil
	}

	keys := make([]string, 0, len(h.cursors))
	ids := make([]string, 0, len(h.cursors))

	for streamKey, id := range h.cursors {
		keys = append(keys, streamKey)
		ids = append(ids, id)
	}

	return append(keys, ids...)
}

func (h *eventHub) setCursor(streamKey, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.cursors[streamKey]; ok {
		h.cursors[streamKey] = id
	}
}

func (h *eventHub) getCursor(streamKey string) (string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	id, ok := h.cursors[streamKey]
	return id, ok
}

func (h *eventHub) checkGaps(ctx context.Context) {
	h.mu.RLock()
	streamKeys := make([]string, 0, len(h.cursors))
	for streamKey := range h.cursors {
		streamKeys = append(streamKeys, streamKey)
	}
	h.mu.RUnlock()

	for _, streamKey := range streamKeys {
		cursor, ok := h.getCursor(streamKey)
		if !ok || cursor == streamIDZero {
			continue
		}

		firstID, err := h.getFirstID(ctx, streamKey)
		if err != nil || firstID == "" {
			continue
		}

		if compareStreamIDs(firstID, cursor) <= 0 {
			continue
		}

		zap.L().Warn("The Watch stream was trimmed past the current position. Closing all its subscribers",
			zap.String("stream", streamKey),
			zap.String("cursor", cursor), zap.String("firstID", firstID))

		h.closeStream(streamKey)
	}
}

func (h *eventHub) closeStream(streamKey string) {
	h.mu.Lock()
	subs := h.subs[streamKey]
	delete(h.subs, streamKey)
	delete(h.cursors, streamKey)
	h.mu.Unlock()

	for sub := range subs {
		sub.cancel()
	}
}

func (h *eventHub) sleep(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (h *eventHub) doRead(ctx context.Context) error {
	generation := h.readGeneration.Load()

	args := h.getReadArgs()
	if len(args) == 0 {
		h.sleep(ctx, streamRetryBackoff)
		return nil
	}

	readCtx, readCancel := context.WithCancel(ctx)

	h.readMu.Lock()
	h.readCancel = readCancel
	h.readMu.Unlock()

	defer func() {
		readCancel()

		h.readMu.Lock()
		h.readCancel = nil
		h.readMu.Unlock()
	}()

	if h.readGeneration.Load() != generation {
		return nil
	}

	res, err := h.redisC.XRead(readCtx, &redis.XReadArgs{
		Streams: args,
		Count:   streamReadCount,
		Block:   streamReadBlock,
	}).Result()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if readCtx.Err() != nil {
			return nil
		}

		return err
	}

	for _, stream := range res {
		api, version, kind, err := parseRscStreamKey(stream.Stream)
		if err != nil {
			zap.L().Error("Could not parse the Watch stream key",
				zap.String("stream", stream.Stream), zap.Error(err))
			h.closeStream(stream.Stream)
			continue
		}

		for _, msg := range stream.Messages {
			if err := h.handleMessage(stream.Stream, api, version, kind, msg); err != nil {
				zap.L().Error("Invalid Watch stream entry. Closing all its subscribers",
					zap.String("stream", stream.Stream),
					zap.String("id", msg.ID), zap.Error(err))
				h.closeStream(stream.Stream)
				break
			}

			h.setCursor(stream.Stream, msg.ID)
		}
	}

	return nil
}

func (h *eventHub) run(ctx context.Context) {
	defer close(h.doneCh)
	defer h.closeAll()

	zap.L().Debug("Starting the rsc event hub loop")

	for {
		select {
		case <-ctx.Done():
			zap.L().Debug("Exiting the rsc event hub loop")
			return
		default:
		}

		if err := h.doRead(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}

			zap.L().Warn("Could not read from the rsc streams", zap.Error(err))

			h.sleep(ctx, streamRetryBackoff)

			if ctx.Err() != nil {
				return
			}

			h.checkGaps(ctx)
		}
	}
}

func (h *eventHub) closeAll() {
	h.mu.Lock()
	subs := h.subs
	h.subs = make(map[string]map[*eventSubscriber]struct{})
	h.cursors = make(map[string]string)
	h.mu.Unlock()

	for _, streamSubs := range subs {
		for sub := range streamSubs {
			sub.cancel()
		}
	}
}
