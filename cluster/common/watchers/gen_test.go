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
		doneCh := make(chan struct{})

		err := w.runFn(ctx, func(ctx context.Context) error {
			close(doneCh)
			return nil
		})
		assert.Nil(t, err, "%+v", err)

		select {
		case <-doneCh:
		case <-time.After(5 * time.Second):
			assert.True(t, false)
		}
	}

	{
		attemptCh := make(chan int, 16)

		err := w.runFn(ctx, func(ctx context.Context) error {
			attemptCh <- 1
			return errors.Errorf("always fails")
		})
		assert.Nil(t, err, "%+v", err)

		assert.Eventually(t, func() bool {
			return len(attemptCh) == 5
		}, 10*time.Second, 50*time.Millisecond)
	}
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
