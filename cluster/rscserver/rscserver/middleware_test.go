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
	"testing"

	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"

	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

func TestGetRequestInfo(t *testing.T) {
	type validEntry struct {
		arg      string
		expected *regexResult
	}

	valids := []validEntry{
		{
			arg: "/octelium.api.rsc.core.v1.ResourceService/GetService",
			expected: &regexResult{
				api:     "core",
				version: "v1",
				verb:    "Get",
				kind:    "Service",
			},
		},
		{
			arg: "/octelium.api.rsc.core.v1.ResourceService/UpdateService",
			expected: &regexResult{
				api:     "core",
				version: "v1",
				verb:    "Update",
				kind:    "Service",
			},
		},
		{
			arg: "/octelium.api.rsc.core.v1.ResourceService/DeleteService",
			expected: &regexResult{
				api:     "core",
				version: "v1",
				verb:    "Delete",
				kind:    "Service",
			},
		},
		{
			arg: "/octelium.api.rsc.core.v1.ResourceService/WatchClusterConfig",
			expected: &regexResult{
				api:     "core",
				version: "v1",
				verb:    "Watch",
				kind:    "ClusterConfig",
			},
		},
	}

	for _, valid := range valids {
		res, err := getRequestInfo(valid.arg)
		assert.Nil(t, err)
		assert.Equal(t, res, valid.expected)
	}

	invalids := []string{
		"",
		utilrand.GetRandomString(6),
		utilrand.GetRandomString(60),
		"/octelium.api.rsc.cluster2.v1.ResourceService/WatchClusterConfig",
		"/octelium.api.rsc.core.v1.ResourceService/InvokeService",
		"/octelium.api.rsc.core.v1.ResourceService/UpdateService/",
		"/octelium.internal.core.v1.ResourceService/UpdateService",
		"/octelium.api.rsc.v1.ResourceService/UpdateService",
	}

	for _, invalid := range invalids {
		_, err := getRequestInfo(invalid)
		assert.NotNil(t, err)
	}
}

type fakeStream struct {
	ctx context.Context

	mu   sync.Mutex
	msgs []*rmetav1.WatchEvent
}

func newFakeStream(ctx context.Context) *fakeStream {
	return &fakeStream{
		ctx: ctx,
	}
}

func (s *fakeStream) SetHeader(metadata.MD) error {
	return nil
}

func (s *fakeStream) SendHeader(metadata.MD) error {
	return nil
}

func (s *fakeStream) SetTrailer(metadata.MD) {
}

func (s *fakeStream) Context() context.Context {
	return s.ctx
}

func (s *fakeStream) SendMsg(m any) error {
	ev, ok := m.(*rmetav1.WatchEvent)
	if !ok {
		return io.ErrUnexpectedEOF
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, ev)

	return nil
}

func (s *fakeStream) RecvMsg(m any) error {
	return io.EOF
}

func (s *fakeStream) getMsgs() []*rmetav1.WatchEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]*rmetav1.WatchEvent{}, s.msgs...)
}

func (s *fakeStream) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.msgs)
}

func (s *fakeStream) waitForCount(n int, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if s.count() >= n {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}

	return s.count() >= n
}

func getEventItemUID(ev *rmetav1.WatchEvent, obj proto.Message) string {
	var err error

	switch {
	case ev.GetEvent().GetCreate() != nil:
		err = ev.GetEvent().GetCreate().GetItem().UnmarshalTo(obj)
	case ev.GetEvent().GetUpdate() != nil:
		err = ev.GetEvent().GetUpdate().GetNewItem().UnmarshalTo(obj)
	case ev.GetEvent().GetDelete() != nil:
		err = ev.GetEvent().GetDelete().GetItem().UnmarshalTo(obj)
	default:
		return ""
	}

	if err != nil {
		return ""
	}

	rsc, ok := obj.(umetav1.ResourceObjectI)
	if !ok {
		return ""
	}

	return rsc.GetMetadata().Uid
}

func TestWatchInitialAndLive(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	api := "core"
	version := "v1"
	kind := ucorev1.KindUser

	srv.redisC.Del(ctx, getRscStreamKey(api, version, kind))

	assert.Nil(t, srv.eventHub.Start(ctx))
	defer srv.eventHub.Stop()

	initialCount := 5
	var initialUIDs []string

	for range initialCount {
		obj := newTestResource(kind)
		obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
		out, err := srv.doCreate(ctx, obj, api, version, kind)
		assert.Nil(t, err)
		initialUIDs = append(initialUIDs, out.GetMetadata().Uid)
	}

	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	stream := newFakeStream(streamCtx)

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.doHandleStreamRequest(&rmetav1.WatchOptions{}, stream, api, version, kind)
	}()

	assert.True(t, stream.waitForCount(initialCount, 30*time.Second))

	gotInitial := make(map[string]bool)
	for _, ev := range stream.getMsgs() {
		assert.NotNil(t, ev.GetEvent().GetCreate())
		gotInitial[getEventItemUID(ev, &corev1.User{})] = true
	}

	for _, uid := range initialUIDs {
		assert.True(t, gotInitial[uid])
	}

	liveObj := newTestResource(kind)
	liveObj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
	liveOut, err := srv.doCreate(ctx, liveObj, api, version, kind)
	assert.Nil(t, err)

	assert.True(t, stream.waitForCount(initialCount+1, 30*time.Second))

	liveEv := stream.getMsgs()[initialCount]
	assert.NotNil(t, liveEv.GetEvent().GetCreate())
	assert.Equal(t, liveOut.GetMetadata().Uid, getEventItemUID(liveEv, &corev1.User{}))

	liveOut.GetMetadata().Labels = map[string]string{
		"key": "val",
	}
	updated, _, err := srv.doUpdate(ctx, liveOut, api, version, kind)
	assert.Nil(t, err)

	assert.True(t, stream.waitForCount(initialCount+2, 30*time.Second))

	updateEv := stream.getMsgs()[initialCount+1]
	assert.NotNil(t, updateEv.GetEvent().GetUpdate())
	assert.Equal(t, updated.GetMetadata().Uid, getEventItemUID(updateEv, &corev1.User{}))

	_, err = srv.doDelete(ctx, &rmetav1.DeleteOptions{
		Uid: updated.GetMetadata().Uid,
	}, api, version, kind)
	assert.Nil(t, err)

	assert.True(t, stream.waitForCount(initialCount+3, 30*time.Second))

	deleteEv := stream.getMsgs()[initialCount+2]
	assert.NotNil(t, deleteEv.GetEvent().GetDelete())
	assert.Equal(t, updated.GetMetadata().Uid, getEventItemUID(deleteEv, &corev1.User{}))

	for _, ev := range stream.getMsgs() {
		assert.Equal(t, kind, ev.GetEvent().Kind)
	}

	cancelStream()

	select {
	case err := <-errCh:
		assert.Nil(t, err)
	case <-time.After(10 * time.Second):
		assert.True(t, false)
	}
}

func TestWatchSkipInitial(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	api := "core"
	version := "v1"
	kind := ucorev1.KindGroup

	srv.redisC.Del(ctx, getRscStreamKey(api, version, kind))

	assert.Nil(t, srv.eventHub.Start(ctx))
	defer srv.eventHub.Stop()

	for range 3 {
		obj := newTestResource(kind)
		obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
		_, err := srv.doCreate(ctx, obj, api, version, kind)
		assert.Nil(t, err)
	}

	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	stream := newFakeStream(streamCtx)

	go func() {
		srv.doHandleStreamRequest(&rmetav1.WatchOptions{
			SkipInitial: true,
		}, stream, api, version, kind)
	}()

	time.Sleep(3 * time.Second)

	assert.Equal(t, 0, stream.count())

	obj := newTestResource(kind)
	obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
	out, err := srv.doCreate(ctx, obj, api, version, kind)
	assert.Nil(t, err)

	assert.True(t, stream.waitForCount(1, 30*time.Second))

	ev := stream.getMsgs()[0]
	assert.NotNil(t, ev.GetEvent().GetCreate())

	grp := &corev1.Group{}
	assert.Nil(t, ev.GetEvent().GetCreate().GetItem().UnmarshalTo(grp))
	assert.Equal(t, out.GetMetadata().Uid, grp.Metadata.Uid)
}

func TestWatchKindIsolation(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	api := "core"
	version := "v1"

	srv.redisC.Del(ctx,
		getRscStreamKey(api, version, ucorev1.KindUser),
		getRscStreamKey(api, version, ucorev1.KindService))

	assert.Nil(t, srv.eventHub.Start(ctx))
	defer srv.eventHub.Stop()

	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	usrStream := newFakeStream(streamCtx)
	svcStream := newFakeStream(streamCtx)

	go func() {
		srv.doHandleStreamRequest(&rmetav1.WatchOptions{
			SkipInitial: true,
		}, usrStream, api, version, ucorev1.KindUser)
	}()

	go func() {
		srv.doHandleStreamRequest(&rmetav1.WatchOptions{
			SkipInitial: true,
		}, svcStream, api, version, ucorev1.KindService)
	}()

	time.Sleep(3 * time.Second)

	svcObj := newTestResource(ucorev1.KindService)
	svcObj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
	_, err = srv.doCreate(ctx, svcObj, api, version, ucorev1.KindService)
	assert.Nil(t, err)

	assert.True(t, svcStream.waitForCount(1, 30*time.Second))
	assert.Equal(t, 0, usrStream.count())

	usrObj := newTestResource(ucorev1.KindUser)
	usrObj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
	_, err = srv.doCreate(ctx, usrObj, api, version, ucorev1.KindUser)
	assert.Nil(t, err)

	assert.True(t, usrStream.waitForCount(1, 30*time.Second))
	assert.Equal(t, 1, svcStream.count())

	assert.Equal(t, ucorev1.KindService, svcStream.getMsgs()[0].GetEvent().Kind)
	assert.Equal(t, ucorev1.KindUser, usrStream.getMsgs()[0].GetEvent().Kind)
}

func TestWatchNoPreSubscriptionReplay(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	api := "core"
	version := "v1"
	kind := ucorev1.KindPolicy

	srv.redisC.Del(ctx, getRscStreamKey(api, version, kind))

	assert.Nil(t, srv.eventHub.Start(ctx))
	defer srv.eventHub.Stop()

	var preUIDs []string
	for range 4 {
		obj := newTestResource(kind)
		obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
		out, err := srv.doCreate(ctx, obj, api, version, kind)
		assert.Nil(t, err)
		preUIDs = append(preUIDs, out.GetMetadata().Uid)
	}

	for _, uid := range preUIDs {
		_, err := srv.doDelete(ctx, &rmetav1.DeleteOptions{Uid: uid}, api, version, kind)
		assert.Nil(t, err)
	}

	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	stream := newFakeStream(streamCtx)

	go func() {
		srv.doHandleStreamRequest(&rmetav1.WatchOptions{}, stream, api, version, kind)
	}()

	time.Sleep(5 * time.Second)

	for _, ev := range stream.getMsgs() {
		assert.Nil(t, ev.GetEvent().GetDelete())
	}

	obj := newTestResource(kind)
	obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
	out, err := srv.doCreate(ctx, obj, api, version, kind)
	assert.Nil(t, err)

	assert.True(t, stream.waitForCount(1, 30*time.Second))

	msgs := stream.getMsgs()
	assert.Equal(t, out.GetMetadata().Uid, getEventItemUID(msgs[len(msgs)-1], &corev1.Policy{}))
}

func TestWatchSubscriberOverflowAborts(t *testing.T) {

	tst, err := initTest()
	assert.Nil(t, err)

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	t.Cleanup(func() {
		tst.Destroy()
	})

	api := "core"
	version := "v1"
	kind := ucorev1.KindDevice
	streamKey := getRscStreamKey(api, version, kind)

	srv.redisC.Del(ctx, streamKey)

	assert.Nil(t, srv.eventHub.Start(ctx))
	defer srv.eventHub.Stop()

	sub, err := srv.eventHub.subscribe(ctx, api, version, kind)
	assert.Nil(t, err)

	for i := range watchQueueSize + 100 {
		srv.eventHub.dispatch(streamKey, fmt.Sprintf("9%d-%d", i, i+1),
			newTestWatchEvent(api, version, kind, "flood"))
	}

	assert.True(t, waitForDone(sub, 5*time.Second))
	assert.False(t, srv.eventHub.hasSubscribers(streamKey))
}
