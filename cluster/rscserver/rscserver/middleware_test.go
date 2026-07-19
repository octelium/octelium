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

	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/cluster/common/vutils"
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

const (
	eventTypeCreate = "create"
	eventTypeUpdate = "update"
	eventTypeDelete = "delete"
)

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

func (s *fakeStream) find(typ, uid string, newObj func() proto.Message) *rmetav1.WatchEvent {
	for _, ev := range s.getMsgs() {
		if getEventType(ev) != typ {
			continue
		}
		if getEventItemUID(ev, newObj()) == uid {
			return ev
		}
	}

	return nil
}

func (s *fakeStream) waitFor(typ, uid string,
	newObj func() proto.Message, d time.Duration) *rmetav1.WatchEvent {

	deadline := time.Now().Add(d)

	for {
		if ev := s.find(typ, uid, newObj); ev != nil {
			return ev
		}

		if !time.Now().Before(deadline) {
			return nil
		}

		time.Sleep(50 * time.Millisecond)
	}
}

func (s *fakeStream) getKinds() map[string]bool {
	ret := make(map[string]bool)

	for _, ev := range s.getMsgs() {
		ret[ev.GetEvent().Kind] = true
	}

	return ret
}

func getEventType(ev *rmetav1.WatchEvent) string {
	switch {
	case ev.GetEvent().GetCreate() != nil:
		return eventTypeCreate
	case ev.GetEvent().GetUpdate() != nil:
		return eventTypeUpdate
	case ev.GetEvent().GetDelete() != nil:
		return eventTypeDelete
	default:
		return ""
	}
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

func newUserMsg() proto.Message {
	return &corev1.User{}
}

func newGroupMsg() proto.Message {
	return &corev1.Group{}
}

func newServiceMsg() proto.Message {
	return &corev1.Service{}
}

func newPolicyMsg() proto.Message {
	return &corev1.Policy{}
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

	assert.Nil(t, srv.eventHub.Start(ctx))
	defer srv.eventHub.Stop()

	var initialUIDs []string

	for range 5 {
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

	for _, uid := range initialUIDs {
		assert.NotNil(t, stream.waitFor(eventTypeCreate, uid, newUserMsg, 30*time.Second), uid)
	}

	liveObj := newTestResource(kind)
	liveObj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
	liveOut, err := srv.doCreate(ctx, liveObj, api, version, kind)
	assert.Nil(t, err)

	liveUID := liveOut.GetMetadata().Uid

	assert.NotNil(t, stream.waitFor(eventTypeCreate, liveUID, newUserMsg, 30*time.Second))

	liveOut.GetMetadata().Labels = map[string]string{
		"key": "val",
	}
	updated, _, err := srv.doUpdate(ctx, liveOut, api, version, kind)
	assert.Nil(t, err)
	assert.Equal(t, liveUID, updated.GetMetadata().Uid)

	updateEv := stream.waitFor(eventTypeUpdate, liveUID, newUserMsg, 30*time.Second)
	assert.NotNil(t, updateEv)

	oldItem := &corev1.User{}
	assert.Nil(t, updateEv.GetEvent().GetUpdate().GetOldItem().UnmarshalTo(oldItem))
	assert.Equal(t, liveUID, oldItem.Metadata.Uid)

	_, err = srv.doDelete(ctx, &rmetav1.DeleteOptions{
		Uid: liveUID,
	}, api, version, kind)
	assert.Nil(t, err)

	assert.NotNil(t, stream.waitFor(eventTypeDelete, liveUID, newUserMsg, 30*time.Second))

	for _, ev := range stream.getMsgs() {
		assert.Equal(t, kind, ev.GetEvent().Kind)
		assert.Equal(t, vutils.GetApiVersion(api, version), ev.GetEvent().ApiVersion)
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

	assert.Nil(t, srv.eventHub.Start(ctx))
	defer srv.eventHub.Stop()

	var preUIDs []string

	for range 3 {
		obj := newTestResource(kind)
		obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
		out, err := srv.doCreate(ctx, obj, api, version, kind)
		assert.Nil(t, err)
		preUIDs = append(preUIDs, out.GetMetadata().Uid)
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

	for _, uid := range preUIDs {
		assert.Nil(t, stream.find(eventTypeCreate, uid, newGroupMsg), uid)
	}

	obj := newTestResource(kind)
	obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
	out, err := srv.doCreate(ctx, obj, api, version, kind)
	assert.Nil(t, err)

	assert.NotNil(t, stream.waitFor(eventTypeCreate,
		out.GetMetadata().Uid, newGroupMsg, 30*time.Second))

	for _, uid := range preUIDs {
		assert.Nil(t, stream.find(eventTypeCreate, uid, newGroupMsg), uid)
	}
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
	svcOut, err := srv.doCreate(ctx, svcObj, api, version, ucorev1.KindService)
	assert.Nil(t, err)

	svcUID := svcOut.GetMetadata().Uid

	assert.NotNil(t, svcStream.waitFor(eventTypeCreate, svcUID, newServiceMsg, 30*time.Second))

	usrObj := newTestResource(ucorev1.KindUser)
	usrObj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
	usrOut, err := srv.doCreate(ctx, usrObj, api, version, ucorev1.KindUser)
	assert.Nil(t, err)

	usrUID := usrOut.GetMetadata().Uid

	assert.NotNil(t, usrStream.waitFor(eventTypeCreate, usrUID, newUserMsg, 30*time.Second))

	assert.Nil(t, usrStream.find(eventTypeCreate, svcUID, newServiceMsg))
	assert.Nil(t, svcStream.find(eventTypeCreate, usrUID, newUserMsg))

	usrKinds := usrStream.getKinds()
	assert.True(t, usrKinds[ucorev1.KindUser])
	assert.False(t, usrKinds[ucorev1.KindService])

	svcKinds := svcStream.getKinds()
	assert.True(t, svcKinds[ucorev1.KindService])
	assert.False(t, svcKinds[ucorev1.KindUser])
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

	obj := newTestResource(kind)
	obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
	out, err := srv.doCreate(ctx, obj, api, version, kind)
	assert.Nil(t, err)

	assert.NotNil(t, stream.waitFor(eventTypeCreate,
		out.GetMetadata().Uid, newPolicyMsg, 30*time.Second))

	for _, uid := range preUIDs {
		assert.Nil(t, stream.find(eventTypeDelete, uid, newPolicyMsg), uid)
		assert.Nil(t, stream.find(eventTypeCreate, uid, newPolicyMsg), uid)
	}
}

func TestWatchSubscriberOverflowAborts(t *testing.T) {
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

	for i := range watchQueueSize + 100 {
		h.dispatch(streamKey, fmt.Sprintf("%d-1", i+1),
			newTestWatchEvent(api, version, kind, "flood"))
	}

	assert.True(t, waitForDone(sub, 5*time.Second))
	assert.False(t, h.hasSubscribers(streamKey))
}
