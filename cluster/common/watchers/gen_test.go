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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestDoProcess(t *testing.T) {

	ctx := context.Background()

	rscUid := vutils.UUIDv4()

	watchObjList := []*rmetav1.WatchEvent{
		{
			Event: &rmetav1.WatchEvent_Event{
				ApiVersion: "core/v1",
				Kind:       "Service",
				Type: &rmetav1.WatchEvent_Event_Create_{
					Create: &rmetav1.WatchEvent_Event_Create{
						Item: pbutils.MessageToAnyMust(&corev1.Service{
							Metadata: &metav1.Metadata{
								Uid: rscUid,
							},
						}),
					},
				},
			},
		},
		{
			Event: &rmetav1.WatchEvent_Event{
				ApiVersion: "core/v1",
				Kind:       "Service",
				Type: &rmetav1.WatchEvent_Event_Delete_{
					Delete: &rmetav1.WatchEvent_Event_Delete{
						Item: pbutils.MessageToAnyMust(&corev1.Service{
							Metadata: &metav1.Metadata{
								Uid: rscUid,
							},
						}),
					},
				},
			},
		},
		{
			Event: &rmetav1.WatchEvent_Event{
				ApiVersion: "core/v1",
				Kind:       "Service",
				Type: &rmetav1.WatchEvent_Event_Update_{
					Update: &rmetav1.WatchEvent_Event_Update{
						NewItem: pbutils.MessageToAnyMust(&corev1.Service{
							Metadata: &metav1.Metadata{
								Uid: rscUid,
							},
						}),
						OldItem: pbutils.MessageToAnyMust(&corev1.Service{
							Metadata: &metav1.Metadata{
								Uid: rscUid,
							},
						}),
					},
				},
			},
		},
	}

	watcher := &Watcher{
		api:     "core",
		version: "v1",
		kind:    ucorev1.KindService,
		onCreate: func(ctx context.Context, item umetav1.ResourceObjectI) error {
			fmt.Printf("Create: %+v", item.(*corev1.Service))
			assert.Equal(t, item.GetMetadata().Uid, rscUid)
			return nil
		},
		onUpdate: func(ctx context.Context, newItem, oldItem umetav1.ResourceObjectI) error {
			fmt.Printf("Update new: %+v", newItem.(*corev1.Service))
			fmt.Printf("Update old: %+v", oldItem.(*corev1.Service))
			assert.Equal(t, newItem.GetMetadata().Uid, oldItem.GetMetadata().Uid)
			return nil
		},
		onDelete: func(ctx context.Context, item umetav1.ResourceObjectI) error {
			assert.Equal(t, item.GetMetadata().Uid, rscUid)
			fmt.Printf("Delete: %+v", item.(*corev1.Service))
			return nil
		},
		newObjFn: func() (umetav1.ResourceObjectI, error) {
			return ucorev1.NewObject(ucorev1.KindService)
		},
	}

	for _, watchObj := range watchObjList {
		err := watcher.doProcess(ctx, watchObj)
		assert.Nil(t, err)
	}
}

func newTstWatcher() *Watcher {
	return &Watcher{
		api:     "core",
		version: "v1",
		kind:    ucorev1.KindService,
		newObjFn: func() (umetav1.ResourceObjectI, error) {
			return ucorev1.NewObject(ucorev1.KindService)
		},
	}
}

type tstBadClient struct{}

func TestNewWatcher(t *testing.T) {

	w, err := NewWatcher("core", "v1", ucorev1.KindService, nil, nil, nil, nil,
		func() (umetav1.ResourceObjectI, error) {
			return ucorev1.NewObject(ucorev1.KindService)
		})
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, w)

	assert.Equal(t, "core", w.api)
	assert.Equal(t, "v1", w.version)
	assert.Equal(t, ucorev1.KindService, w.kind)
	assert.Nil(t, w.onCreate)
	assert.Nil(t, w.onUpdate)
	assert.Nil(t, w.onDelete)
	assert.False(t, w.isClosed)
	assert.Nil(t, w.cancelFn)
}

func TestWatcherClose(t *testing.T) {

	{
		w := newTstWatcher()
		w.Close()
		assert.True(t, w.isClosed)

		w.Close()
		assert.True(t, w.isClosed)
	}

	{
		w := newTstWatcher()

		called := false
		w.cancelFn = func() {
			called = true
		}

		w.Close()
		assert.True(t, called)
		assert.True(t, w.isClosed)
	}

	{
		w := newTstWatcher()

		count := 0
		w.cancelFn = func() {
			count = count + 1
		}

		w.Close()
		w.Close()
		w.Close()
		assert.Equal(t, 1, count)
	}
}

func TestWatcherGetObject(t *testing.T) {

	w := newTstWatcher()

	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Uid:  vutils.UUIDv4(),
				Name: "svc.default",
			},
		}

		obj, err := w.getObject(pbutils.MessageToAnyMust(svc))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, svc.Metadata.Uid, obj.GetMetadata().Uid)

		res, ok := obj.(*corev1.Service)
		assert.True(t, ok)
		assert.Equal(t, "svc.default", res.Metadata.Name)
	}

	{
		_, err := w.getObject(pbutils.MessageToAnyMust(&corev1.User{
			Metadata: &metav1.Metadata{
				Uid: vutils.UUIDv4(),
			},
		}))
		assert.NotNil(t, err)
	}

	{
		_, err := w.getObject(&anypb.Any{})
		assert.NotNil(t, err)
	}

	{
		wBad := newTstWatcher()
		wBad.newObjFn = func() (umetav1.ResourceObjectI, error) {
			return nil, errors.Errorf("no object")
		}

		_, err := wBad.getObject(pbutils.MessageToAnyMust(&corev1.Service{
			Metadata: &metav1.Metadata{Uid: vutils.UUIDv4()},
		}))
		assert.NotNil(t, err)
	}
}

func TestWatcherDoProcessNilAndUnknown(t *testing.T) {

	ctx := context.Background()

	w := newTstWatcher()

	assert.Nil(t, w.doProcess(ctx, nil))
	assert.Nil(t, w.doProcess(ctx, &rmetav1.WatchEvent{}))
	assert.Nil(t, w.doProcess(ctx, &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{},
	}))
}

func TestWatcherDoProcessNilHandlers(t *testing.T) {

	ctx := context.Background()

	w := newTstWatcher()

	svcAny := pbutils.MessageToAnyMust(&corev1.Service{
		Metadata: &metav1.Metadata{
			Uid: vutils.UUIDv4(),
		},
	})

	events := []*rmetav1.WatchEvent{
		{
			Event: &rmetav1.WatchEvent_Event{
				Type: &rmetav1.WatchEvent_Event_Create_{
					Create: &rmetav1.WatchEvent_Event_Create{Item: svcAny},
				},
			},
		},
		{
			Event: &rmetav1.WatchEvent_Event{
				Type: &rmetav1.WatchEvent_Event_Update_{
					Update: &rmetav1.WatchEvent_Event_Update{
						NewItem: svcAny,
						OldItem: svcAny,
					},
				},
			},
		},
		{
			Event: &rmetav1.WatchEvent_Event{
				Type: &rmetav1.WatchEvent_Event_Delete_{
					Delete: &rmetav1.WatchEvent_Event_Delete{Item: svcAny},
				},
			},
		},
	}

	for _, ev := range events {
		assert.Nil(t, w.doProcess(ctx, ev))
	}
}

func TestWatcherDoProcessBadItem(t *testing.T) {

	ctx := context.Background()

	w := newTstWatcher()
	w.onCreate = func(ctx context.Context, item umetav1.ResourceObjectI) error {
		return nil
	}
	w.onUpdate = func(ctx context.Context, newItem, oldItem umetav1.ResourceObjectI) error {
		return nil
	}
	w.onDelete = func(ctx context.Context, item umetav1.ResourceObjectI) error {
		return nil
	}

	badAny := pbutils.MessageToAnyMust(&corev1.User{
		Metadata: &metav1.Metadata{Uid: vutils.UUIDv4()},
	})

	{
		err := w.doProcess(ctx, &rmetav1.WatchEvent{
			Event: &rmetav1.WatchEvent_Event{
				Type: &rmetav1.WatchEvent_Event_Create_{
					Create: &rmetav1.WatchEvent_Event_Create{Item: badAny},
				},
			},
		})
		assert.NotNil(t, err)
	}

	{
		err := w.doProcess(ctx, &rmetav1.WatchEvent{
			Event: &rmetav1.WatchEvent_Event{
				Type: &rmetav1.WatchEvent_Event_Update_{
					Update: &rmetav1.WatchEvent_Event_Update{
						NewItem: badAny,
						OldItem: badAny,
					},
				},
			},
		})
		assert.NotNil(t, err)
	}

	{
		err := w.doProcess(ctx, &rmetav1.WatchEvent{
			Event: &rmetav1.WatchEvent_Event{
				Type: &rmetav1.WatchEvent_Event_Delete_{
					Delete: &rmetav1.WatchEvent_Event_Delete{Item: badAny},
				},
			},
		})
		assert.NotNil(t, err)
	}
}

func TestWatcherRunFn(t *testing.T) {

	ctx := context.Background()

	w := newTstWatcher()

	assert.Nil(t, w.runFn(ctx, nil))

	{
		count := 0
		err := w.runFn(ctx, func(ctx context.Context) error {
			count++
			deadline, ok := ctx.Deadline()
			assert.True(t, ok)
			assert.True(t, time.Until(deadline) <= runFnTimeout)
			return nil
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, count)
	}

	{
		count := 0
		err := w.runFn(ctx, func(ctx context.Context) error {
			count++
			return errors.Errorf("always fails")
		})
		assert.NotNil(t, err)
		assert.Equal(t, runFnMaxAttempts, count)
	}

	{
		count := 0
		err := w.runFn(ctx, func(ctx context.Context) error {
			count++
			if count < 3 {
				return errors.Errorf("fails")
			}
			return nil
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 3, count)
	}

	{
		cctx, cancel := context.WithCancel(ctx)
		count := 0
		err := w.runFn(cctx, func(ctx context.Context) error {
			count++
			cancel()
			return errors.Errorf("fails")
		})
		assert.NotNil(t, err)
		assert.Equal(t, 1, count)
	}
}

func TestGetReconnectBackoff(t *testing.T) {

	type entry struct {
		attempt int
		min     time.Duration
	}

	entries := []entry{
		{attempt: 0, min: reconnectBackoff},
		{attempt: 1, min: reconnectBackoff},
		{attempt: 2, min: 2 * reconnectBackoff},
		{attempt: 3, min: 4 * reconnectBackoff},
		{attempt: 5, min: reconnectMaxBackoff},
		{attempt: 1000, min: reconnectMaxBackoff},
	}

	for _, e := range entries {
		for range 20 {
			res := getReconnectBackoff(e.attempt)
			assert.True(t, res >= e.min, "%d %s", e.attempt, res)
			assert.True(t, res <= e.min+e.min/2, "%d %s", e.attempt, res)
		}
	}
}

type tstCallback struct {
	typ     string
	uid     string
	rv      string
	port    uint32
	oldRV   string
	oldPort uint32
}

type tstRecorder struct {
	mu        sync.Mutex
	callbacks []tstCallback
}

func (r *tstRecorder) add(c tstCallback) {
	r.mu.Lock()
	r.callbacks = append(r.callbacks, c)
	r.mu.Unlock()
}

func (r *tstRecorder) get() []tstCallback {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]tstCallback{}, r.callbacks...)
}

func (r *tstRecorder) getByUID(uid string) []tstCallback {
	var ret []tstCallback
	for _, c := range r.get() {
		if c.uid == uid {
			ret = append(ret, c)
		}
	}
	return ret
}

func (r *tstRecorder) onCreate(ctx context.Context, item umetav1.ResourceObjectI) error {
	svc := item.(*corev1.Service)
	r.add(tstCallback{
		typ:  "create",
		uid:  svc.Metadata.Uid,
		rv:   svc.Metadata.ResourceVersion,
		port: svc.Spec.Port,
	})
	return nil
}

func (r *tstRecorder) onUpdate(ctx context.Context, newItem, oldItem umetav1.ResourceObjectI) error {
	svc := newItem.(*corev1.Service)
	oldSvc := oldItem.(*corev1.Service)
	r.add(tstCallback{
		typ:     "update",
		uid:     svc.Metadata.Uid,
		rv:      svc.Metadata.ResourceVersion,
		port:    svc.Spec.Port,
		oldRV:   oldSvc.Metadata.ResourceVersion,
		oldPort: oldSvc.Spec.Port,
	})
	return nil
}

func (r *tstRecorder) onDelete(ctx context.Context, item umetav1.ResourceObjectI) error {
	svc := item.(*corev1.Service)
	r.add(tstCallback{
		typ:  "delete",
		uid:  svc.Metadata.Uid,
		rv:   svc.Metadata.ResourceVersion,
		port: svc.Spec.Port,
	})
	return nil
}

func newTstRecordingWatcher(r *tstRecorder) *Watcher {
	w := newTstWatcher()
	w.onCreate = r.onCreate
	w.onUpdate = r.onUpdate
	w.onDelete = r.onDelete
	return w
}

func newTstService(uid, rv, lastRV string, port uint32) *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Uid:                 uid,
			Name:                "svc.default",
			ResourceVersion:     rv,
			LastResourceVersion: lastRV,
		},
		Spec: &corev1.Service_Spec{
			Port: port,
		},
	}
}

func newTstCreateEvent(svc *corev1.Service) *rmetav1.WatchEvent {
	return &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			ApiVersion: "core/v1",
			Kind:       ucorev1.KindService,
			Type: &rmetav1.WatchEvent_Event_Create_{
				Create: &rmetav1.WatchEvent_Event_Create{
					Item: pbutils.MessageToAnyMust(svc),
				},
			},
		},
	}
}

func newTstUpdateEvent(newSvc, oldSvc *corev1.Service) *rmetav1.WatchEvent {
	return &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			ApiVersion: "core/v1",
			Kind:       ucorev1.KindService,
			Type: &rmetav1.WatchEvent_Event_Update_{
				Update: &rmetav1.WatchEvent_Event_Update{
					NewItem: pbutils.MessageToAnyMust(newSvc),
					OldItem: pbutils.MessageToAnyMust(oldSvc),
				},
			},
		},
	}
}

func newTstDeleteEvent(svc *corev1.Service) *rmetav1.WatchEvent {
	return &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			ApiVersion: "core/v1",
			Kind:       ucorev1.KindService,
			Type: &rmetav1.WatchEvent_Event_Delete_{
				Delete: &rmetav1.WatchEvent_Event_Delete{
					Item: pbutils.MessageToAnyMust(svc),
				},
			},
		},
	}
}

func waitForTstQueue(t *testing.T, w *Watcher) {
	assert.Eventually(t, func() bool {
		return isTstQueueEmpty(&w.queue)
	}, 30*time.Second, 10*time.Millisecond)
}

func TestWatcherProcessVersions(t *testing.T) {

	ctx := context.Background()

	r := &tstRecorder{}
	w := newTstRecordingWatcher(r)

	uid := vutils.UUIDv4()

	rv1 := vutils.UUIDv7()
	rv2 := vutils.UUIDv7()
	rv3 := vutils.UUIDv7()
	rv4 := vutils.UUIDv7()

	v1 := newTstService(uid, rv1, "", 1)
	v2 := newTstService(uid, rv2, rv1, 2)
	v3 := newTstService(uid, rv3, rv2, 3)
	deleted := newTstService(uid, rv4, rv3, 3)

	events := []*rmetav1.WatchEvent{
		newTstCreateEvent(v1),
		newTstCreateEvent(v1),
		newTstUpdateEvent(v2, v1),
		newTstUpdateEvent(v2, v1),
		newTstUpdateEvent(v1, v1),
		newTstCreateEvent(v1),
		newTstCreateEvent(v3),
		newTstCreateEvent(v2),
		newTstUpdateEvent(v2, v1),
		newTstDeleteEvent(deleted),
		newTstDeleteEvent(deleted),
		newTstUpdateEvent(newTstService(uid, vutils.UUIDv7(), rv3, 5), v3),
		newTstCreateEvent(v3),
	}

	for _, ev := range events {
		assert.Nil(t, w.doProcess(ctx, ev))
	}

	waitForTstQueue(t, w)

	assert.Equal(t, []tstCallback{
		{typ: "create", uid: uid, rv: rv1, port: 1},
		{typ: "update", uid: uid, rv: rv2, port: 2, oldRV: rv1, oldPort: 1},
		{typ: "update", uid: uid, rv: rv3, port: 3, oldRV: rv2, oldPort: 2},
		{typ: "delete", uid: uid, rv: rv4, port: 3},
	}, r.get())
}

func TestWatcherProcessUpdateOldItem(t *testing.T) {

	ctx := context.Background()

	{
		r := &tstRecorder{}
		w := newTstRecordingWatcher(r)

		uid := vutils.UUIDv4()
		rv1 := vutils.UUIDv7()
		rv2 := vutils.UUIDv7()

		assert.Nil(t, w.doProcess(ctx, newTstUpdateEvent(
			newTstService(uid, rv2, rv1, 2), newTstService(uid, rv1, "", 1))))

		waitForTstQueue(t, w)

		assert.Equal(t, []tstCallback{
			{typ: "update", uid: uid, rv: rv2, port: 2, oldRV: rv1, oldPort: 1},
		}, r.get())
	}

	{
		r := &tstRecorder{}
		w := newTstRecordingWatcher(r)

		uid := vutils.UUIDv4()
		rv1 := vutils.UUIDv7()
		rv2 := vutils.UUIDv7()
		rv3 := vutils.UUIDv7()

		assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv1, "", 1))))
		assert.Nil(t, w.doProcess(ctx, newTstUpdateEvent(
			newTstService(uid, rv3, rv2, 3), newTstService(uid, rv2, rv1, 2))))

		waitForTstQueue(t, w)

		assert.Equal(t, []tstCallback{
			{typ: "create", uid: uid, rv: rv1, port: 1},
			{typ: "update", uid: uid, rv: rv3, port: 3, oldRV: rv1, oldPort: 1},
		}, r.get())
	}

	{
		r := &tstRecorder{}
		w := newTstRecordingWatcher(r)

		uid := vutils.UUIDv4()
		rv1 := vutils.UUIDv7()
		rv2 := vutils.UUIDv7()

		oldItm := newTstService(uid, rv1, "", 1)
		oldItm.Metadata.Name = "from-event"

		assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv1, "", 1))))
		assert.Nil(t, w.doProcess(ctx, newTstUpdateEvent(newTstService(uid, rv2, rv1, 2), oldItm)))

		waitForTstQueue(t, w)

		var oldName string
		w.onUpdate = func(ctx context.Context, newItem, oldItem umetav1.ResourceObjectI) error {
			oldName = oldItem.GetMetadata().Name
			return nil
		}

		rv3 := vutils.UUIDv7()
		oldItm = newTstService(uid, rv2, rv1, 2)
		oldItm.Metadata.Name = "from-event"
		assert.Nil(t, w.doProcess(ctx, newTstUpdateEvent(newTstService(uid, rv3, rv2, 3), oldItm)))

		waitForTstQueue(t, w)
		assert.Equal(t, "from-event", oldName)
	}
}

func TestWatcherProcessBadOldItem(t *testing.T) {

	ctx := context.Background()

	r := &tstRecorder{}
	w := newTstRecordingWatcher(r)

	uid := vutils.UUIDv4()
	rv1 := vutils.UUIDv7()
	rv2 := vutils.UUIDv7()

	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv1, "", 1))))

	assert.NotNil(t, w.doProcess(ctx, &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			Type: &rmetav1.WatchEvent_Event_Update_{
				Update: &rmetav1.WatchEvent_Event_Update{
					NewItem: pbutils.MessageToAnyMust(newTstService(uid, rv2, rv1, 2)),
					OldItem: pbutils.MessageToAnyMust(&corev1.User{
						Metadata: &metav1.Metadata{Uid: uid},
					}),
				},
			},
		},
	}))

	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv2, rv1, 2))))

	waitForTstQueue(t, w)

	assert.Equal(t, []tstCallback{
		{typ: "create", uid: uid, rv: rv1, port: 1},
		{typ: "update", uid: uid, rv: rv2, port: 2, oldRV: rv1, oldPort: 1},
	}, r.get())
}

func TestWatcherProcessDeleteUnknown(t *testing.T) {

	ctx := context.Background()

	r := &tstRecorder{}
	w := newTstRecordingWatcher(r)

	uid := vutils.UUIDv4()
	rv := vutils.UUIDv7()

	assert.Nil(t, w.doProcess(ctx, newTstDeleteEvent(newTstService(uid, rv, "", 1))))

	waitForTstQueue(t, w)

	assert.Equal(t, []tstCallback{
		{typ: "delete", uid: uid, rv: rv, port: 1},
	}, r.get())
}

func TestWatcherProcessUpdateOnly(t *testing.T) {

	ctx := context.Background()

	r := &tstRecorder{}
	w := newTstWatcher()
	w.onUpdate = r.onUpdate

	uid := vutils.UUIDv4()
	rv1 := vutils.UUIDv7()
	rv2 := vutils.UUIDv7()

	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv1, "", 1))))
	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv1, "", 1))))
	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv2, rv1, 2))))
	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv2, rv1, 2))))
	assert.Nil(t, w.doProcess(ctx, newTstDeleteEvent(newTstService(uid, vutils.UUIDv7(), rv2, 2))))

	waitForTstQueue(t, w)

	assert.Equal(t, []tstCallback{
		{typ: "update", uid: uid, rv: rv2, port: 2, oldRV: rv1, oldPort: 1},
	}, r.get())
}

func TestWatcherProcessCreateOnly(t *testing.T) {

	ctx := context.Background()

	r := &tstRecorder{}
	w := newTstWatcher()
	w.onCreate = r.onCreate

	uid := vutils.UUIDv4()
	rv1 := vutils.UUIDv7()
	rv2 := vutils.UUIDv7()
	rv3 := vutils.UUIDv7()

	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv1, "", 1))))
	assert.Nil(t, w.doProcess(ctx, newTstUpdateEvent(
		newTstService(uid, rv2, rv1, 2), newTstService(uid, rv1, "", 1))))
	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv2, rv1, 2))))
	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv2, rv1, 2))))
	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv3, rv2, 3))))

	waitForTstQueue(t, w)

	assert.Equal(t, []tstCallback{
		{typ: "create", uid: uid, rv: rv1, port: 1},
		{typ: "create", uid: uid, rv: rv2, port: 2},
		{typ: "create", uid: uid, rv: rv3, port: 3},
	}, r.get())
}

func TestWatcherProcessOrdering(t *testing.T) {

	ctx := context.Background()

	r := &tstRecorder{}
	w := newTstRecordingWatcher(r)

	releaseCh := make(chan struct{})
	startedCh := make(chan struct{})

	w.onUpdate = func(ctx context.Context, newItem, oldItem umetav1.ResourceObjectI) error {
		if newItem.(*corev1.Service).Spec.Port == 2 {
			close(startedCh)
			<-releaseCh
		}
		return r.onUpdate(ctx, newItem, oldItem)
	}

	uidA := vutils.UUIDv4()
	uidB := vutils.UUIDv4()

	rv1 := vutils.UUIDv7()
	rv2 := vutils.UUIDv7()
	rv3 := vutils.UUIDv7()
	rvB := vutils.UUIDv7()

	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uidA, rv1, "", 1))))
	assert.Nil(t, w.doProcess(ctx, newTstUpdateEvent(
		newTstService(uidA, rv2, rv1, 2), newTstService(uidA, rv1, "", 1))))

	<-startedCh

	assert.Nil(t, w.doProcess(ctx, newTstUpdateEvent(
		newTstService(uidA, rv3, rv2, 3), newTstService(uidA, rv2, rv1, 2))))
	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uidB, rvB, "", 10))))

	assert.Eventually(t, func() bool {
		return len(r.getByUID(uidB)) == 1
	}, 10*time.Second, 10*time.Millisecond)

	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, []tstCallback{
		{typ: "create", uid: uidA, rv: rv1, port: 1},
	}, r.getByUID(uidA))

	close(releaseCh)

	waitForTstQueue(t, w)

	assert.Equal(t, []tstCallback{
		{typ: "create", uid: uidA, rv: rv1, port: 1},
		{typ: "update", uid: uidA, rv: rv2, port: 2, oldRV: rv1, oldPort: 1},
		{typ: "update", uid: uidA, rv: rv3, port: 3, oldRV: rv2, oldPort: 2},
	}, r.getByUID(uidA))
}

func TestWatcherProcessForgetOnFailure(t *testing.T) {

	ctx := context.Background()

	r := &tstRecorder{}
	w := newTstRecordingWatcher(r)

	var mu sync.Mutex
	attempts := 0

	w.onCreate = func(ctx context.Context, item umetav1.ResourceObjectI) error {
		mu.Lock()
		attempts++
		cur := attempts
		mu.Unlock()

		if cur <= runFnMaxAttempts {
			return errors.Errorf("fails")
		}

		return r.onCreate(ctx, item)
	}

	uid := vutils.UUIDv4()
	rv1 := vutils.UUIDv7()

	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv1, "", 1))))
	waitForTstQueue(t, w)

	assert.Equal(t, 0, len(r.get()))

	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv1, "", 1))))
	waitForTstQueue(t, w)

	assert.Equal(t, []tstCallback{
		{typ: "create", uid: uid, rv: rv1, port: 1},
	}, r.get())

	mu.Lock()
	assert.Equal(t, runFnMaxAttempts+1, attempts)
	mu.Unlock()

	assert.Nil(t, w.doProcess(ctx, newTstCreateEvent(newTstService(uid, rv1, "", 1))))
	waitForTstQueue(t, w)

	assert.Equal(t, 1, len(r.get()))
}

type tstStreamMsg struct {
	ev  *rmetav1.WatchEvent
	err error
}

type tstWatchStream struct {
	ctx   context.Context
	msgCh chan *tstStreamMsg
}

func (s *tstWatchStream) Header() (metadata.MD, error) {
	return nil, nil
}

func (s *tstWatchStream) Trailer() metadata.MD {
	return nil
}

func (s *tstWatchStream) CloseSend() error {
	return nil
}

func (s *tstWatchStream) Context() context.Context {
	return s.ctx
}

func (s *tstWatchStream) SendMsg(m any) error {
	return nil
}

func (s *tstWatchStream) RecvMsg(m any) error {
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case msg := <-s.msgCh:
		if msg.err != nil {
			return msg.err
		}
		proto.Merge(m.(*rmetav1.WatchEvent), msg.ev)
		return nil
	}
}

func (s *tstWatchStream) send(ev *rmetav1.WatchEvent) {
	s.msgCh <- &tstStreamMsg{ev: ev}
}

func (s *tstWatchStream) fail(err error) {
	s.msgCh <- &tstStreamMsg{err: err}
}

type tstWatchClient struct {
	mu      sync.Mutex
	errs    []error
	calls   int
	streams chan *tstWatchStream
}

func newTstWatchClient() *tstWatchClient {
	return &tstWatchClient{
		streams: make(chan *tstWatchStream, 32),
	}
}

func (c *tstWatchClient) WatchService(ctx context.Context, req *rmetav1.WatchOptions) (grpc.ClientStream, error) {
	c.mu.Lock()
	c.calls++
	if len(c.errs) > 0 {
		err := c.errs[0]
		c.errs = c.errs[1:]
		c.mu.Unlock()
		return nil, err
	}
	c.mu.Unlock()

	ret := &tstWatchStream{
		ctx:   ctx,
		msgCh: make(chan *tstStreamMsg, 128),
	}

	c.streams <- ret

	return ret, nil
}

func (c *tstWatchClient) getCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.calls
}

func (c *tstWatchClient) waitForStream(t *testing.T) *tstWatchStream {
	select {
	case ret := <-c.streams:
		return ret
	case <-time.After(30 * time.Second):
		t.Fatal("No watch stream was opened")
		return nil
	}
}

func newTstRunningWatcher(t *testing.T, ctx context.Context, client *tstWatchClient,
	onCreate func(ctx context.Context, item umetav1.ResourceObjectI) error,
	onUpdate func(ctx context.Context, newItem, oldItem umetav1.ResourceObjectI) error,
	onDelete func(ctx context.Context, item umetav1.ResourceObjectI) error) *Watcher {
	w, err := NewWatcher("core", "v1", ucorev1.KindService,
		onCreate, onUpdate, onDelete, client,
		func() (umetav1.ResourceObjectI, error) {
			return ucorev1.NewObject(ucorev1.KindService)
		})
	assert.Nil(t, err, "%+v", err)

	assert.Nil(t, w.Run(ctx))
	t.Cleanup(w.Close)

	return w
}

func TestWatcherRunReconcileOnReconnect(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := newTstWatchClient()
	r := &tstRecorder{}

	w := newTstRunningWatcher(t, ctx, client, r.onCreate, r.onUpdate, r.onDelete)

	uidA := vutils.UUIDv4()
	uidB := vutils.UUIDv4()
	uidC := vutils.UUIDv4()
	uidD := vutils.UUIDv4()

	rvA1 := vutils.UUIDv7()
	rvB1 := vutils.UUIDv7()
	rvD1 := vutils.UUIDv7()
	rvA2 := vutils.UUIDv7()
	rvB2 := vutils.UUIDv7()
	rvC1 := vutils.UUIDv7()

	strm := client.waitForStream(t)

	strm.send(newTstCreateEvent(newTstService(uidA, rvA1, "", 1)))
	strm.send(newTstCreateEvent(newTstService(uidB, rvB1, "", 1)))
	strm.send(newTstCreateEvent(newTstService(uidD, rvD1, "", 1)))
	strm.send(newTstUpdateEvent(newTstService(uidA, rvA2, rvA1, 2), newTstService(uidA, rvA1, "", 1)))

	assert.Eventually(t, func() bool {
		return len(r.get()) == 4
	}, 10*time.Second, 10*time.Millisecond)

	strm.fail(errors.Errorf("transient failure"))

	strm = client.waitForStream(t)

	strm.send(newTstCreateEvent(newTstService(uidA, rvA2, rvA1, 2)))
	strm.send(newTstCreateEvent(newTstService(uidB, rvB2, rvB1, 2)))
	strm.send(newTstCreateEvent(newTstService(uidC, rvC1, "", 1)))
	strm.send(newTstCreateEvent(newTstService(uidD, rvD1, "", 1)))

	assert.Eventually(t, func() bool {
		return len(r.get()) == 6
	}, 10*time.Second, 10*time.Millisecond)

	waitForTstQueue(t, w)
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, []tstCallback{
		{typ: "create", uid: uidA, rv: rvA1, port: 1},
		{typ: "update", uid: uidA, rv: rvA2, port: 2, oldRV: rvA1, oldPort: 1},
	}, r.getByUID(uidA))

	assert.Equal(t, []tstCallback{
		{typ: "create", uid: uidB, rv: rvB1, port: 1},
		{typ: "update", uid: uidB, rv: rvB2, port: 2, oldRV: rvB1, oldPort: 1},
	}, r.getByUID(uidB))

	assert.Equal(t, []tstCallback{
		{typ: "create", uid: uidC, rv: rvC1, port: 1},
	}, r.getByUID(uidC))

	assert.Equal(t, []tstCallback{
		{typ: "create", uid: uidD, rv: rvD1, port: 1},
	}, r.getByUID(uidD))

	assert.Equal(t, 2, client.getCalls())

	w.Close()

	select {
	case <-strm.ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("The watch stream is not closed")
	}

	time.Sleep(2 * time.Second)
	assert.Equal(t, 2, client.getCalls())
}

func TestWatcherRunOpenStreamRetry(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := newTstWatchClient()
	client.errs = []error{errors.Errorf("unavailable")}

	r := &tstRecorder{}

	newTstRunningWatcher(t, ctx, client, r.onCreate, r.onUpdate, r.onDelete)

	strm := client.waitForStream(t)

	uid := vutils.UUIDv4()
	rv := vutils.UUIDv7()
	strm.send(newTstCreateEvent(newTstService(uid, rv, "", 1)))

	assert.Eventually(t, func() bool {
		return len(r.get()) == 1
	}, 10*time.Second, 10*time.Millisecond)

	assert.Equal(t, 2, client.getCalls())
}

func TestWatcherRunCallbackSurvivesReconnect(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := newTstWatchClient()

	startedCh := make(chan struct{})
	releaseCh := make(chan struct{})
	ctxErrCh := make(chan error, 1)

	newTstRunningWatcher(t, ctx, client, func(ctx context.Context, item umetav1.ResourceObjectI) error {
		close(startedCh)
		<-releaseCh
		ctxErrCh <- ctx.Err()
		return nil
	}, nil, nil)

	strm := client.waitForStream(t)
	strm.send(newTstCreateEvent(newTstService(vutils.UUIDv4(), vutils.UUIDv7(), "", 1)))

	<-startedCh

	strm.fail(errors.Errorf("transient failure"))

	strm = client.waitForStream(t)

	close(releaseCh)

	select {
	case err := <-ctxErrCh:
		assert.Nil(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("The callback did not finish")
	}

	assert.Nil(t, strm.ctx.Err())
}

func TestWatcherOpenWatchStreamErrors(t *testing.T) {

	ctx := context.Background()

	{
		w := newTstWatcher()
		w.client = &tstBadClient{}

		_, err := w.openWatchStream(ctx)
		assert.NotNil(t, err)
	}

	{
		w := newTstWatcher()
		w.kind = "DoesNotExist"
		w.client = &tstBadClient{}

		_, err := w.openWatchStream(ctx)
		assert.NotNil(t, err)
	}
}
