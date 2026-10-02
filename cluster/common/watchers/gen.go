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
	"reflect"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	runFnMaxAttempts = 5
	runFnTimeout     = 8 * time.Minute
	runFnBackoff     = 200 * time.Millisecond

	reconnectBackoff      = 1 * time.Second
	reconnectMaxBackoff   = 16 * time.Second
	healthyStreamDuration = 30 * time.Second
)

type Watcher struct {
	api     string
	version string
	kind    string

	onCreate func(ctx context.Context, item umetav1.ResourceObjectI) error
	onUpdate func(ctx context.Context, newItem, oldItem umetav1.ResourceObjectI) error
	onDelete func(ctx context.Context, item umetav1.ResourceObjectI) error

	client any

	cancelFn context.CancelFunc
	mu       sync.Mutex
	isClosed bool

	newObjFn func() (umetav1.ResourceObjectI, error)

	store itemStore
	queue keyedQueue
}

type Opts struct {
}

func NewWatcher(api, version, kind string,
	onCreate func(ctx context.Context, item umetav1.ResourceObjectI) error,
	onUpdate func(ctx context.Context, newItem, oldItem umetav1.ResourceObjectI) error,
	onDelete func(ctx context.Context, item umetav1.ResourceObjectI) error,
	client any,
	newObjFn func() (umetav1.ResourceObjectI, error),
) (*Watcher, error) {

	ret := &Watcher{
		api:      api,
		version:  version,
		kind:     kind,
		onCreate: onCreate,
		onUpdate: onUpdate,
		onDelete: onDelete,
		client:   client,
		newObjFn: newObjFn,
	}

	return ret, nil
}

func (w *Watcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.isClosed {
		return
	}

	zap.L().Debug("Closing resource watcher",
		zap.String("api", w.api),
		zap.String("version", w.version),
		zap.String("kind", w.kind))

	w.isClosed = true

	if w.cancelFn != nil {
		w.cancelFn()
	}
}

func (w *Watcher) Run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)

	w.mu.Lock()
	w.cancelFn = cancel
	w.mu.Unlock()

	go func() {
		defer cancel()

		failN := 0

		for ctx.Err() == nil {
			startedAt := time.Now()

			err := w.doRun(ctx)
			if err == nil {
				return
			}

			if time.Since(startedAt) > healthyStreamDuration {
				failN = 0
			}

			failN++

			zap.L().Warn("Could not run watcher. Trying again...",
				zap.String("api", w.api),
				zap.String("kind", w.kind),
				zap.String("version", w.version),
				zap.Int("attempt", failN),
				zap.Error(err))

			select {
			case <-ctx.Done():
				return
			case <-time.After(getReconnectBackoff(failN)):
			}
		}
	}()

	return nil
}

func getReconnectBackoff(attempt int) time.Duration {
	ret := reconnectBackoff
	for i := 1; i < attempt && ret < reconnectMaxBackoff; i++ {
		ret = ret * 2
	}

	if ret > reconnectMaxBackoff {
		ret = reconnectMaxBackoff
	}

	return ret + time.Duration(utilrand.GetRandomRangeMath(0, int(ret/2)))
}

func (w *Watcher) doRun(ctx context.Context) error {
	streamCtx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()

	zap.L().Debug("Starting running resource watcher",
		zap.String("api", w.api),
		zap.String("version", w.version),
		zap.String("kind", w.kind))

	grpcClientStream, err := w.openWatchStream(streamCtx)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	for {
		watchObj := &rmetav1.WatchEvent{}
		if err := grpcClientStream.RecvMsg(watchObj); err != nil {
			if ctx.Err() != nil {
				return nil
			}

			return errors.Errorf("Watch stream for %s/%s terminated: %+v", w.api, w.kind, err)
		}

		if err := w.doProcess(ctx, watchObj); err != nil {
			zap.L().Warn("Could not process watcher event",
				zap.String("api", w.api),
				zap.String("kind", w.kind),
				zap.String("version", w.version),
				zap.Error(err))
		}
	}
}

func (w *Watcher) openWatchStream(ctx context.Context) (grpc.ClientStream, error) {
	client := reflect.ValueOf(w.client)

	method := client.MethodByName(fmt.Sprintf("Watch%s", w.kind))
	if !method.IsValid() {
		return nil, errors.Errorf("Could not find Watch method for kind: %s", w.kind)
	}

	res := method.Call(
		[]reflect.Value{
			reflect.ValueOf(ctx),
			reflect.ValueOf(&rmetav1.WatchOptions{}),
		},
	)

	if len(res) != 2 {
		return nil, errors.Errorf("Invalid reflect ret len")
	}

	if res[1].Interface() != nil {
		return nil, res[1].Interface().(error)
	}

	if res[0].Interface() == nil {
		return nil, errors.Errorf("Could not run watcher. Client stream is nil")
	}

	grpcClientStream, ok := res[0].Interface().(grpc.ClientStream)
	if !ok {
		return nil, errors.Errorf("Could not run watcher. Could not cast to grpc.ClientStream")
	}

	return grpcClientStream, nil
}

func (w *Watcher) getObject(in *anypb.Any) (umetav1.ResourceObjectI, error) {
	obj, err := w.newObjFn()
	if err != nil {
		return nil, err
	}

	if err := pbutils.AnyToMessage(in, obj); err != nil {
		return nil, err
	}

	return obj, nil
}

func (w *Watcher) doProcess(ctx context.Context, watchObj *rmetav1.WatchEvent) error {
	if watchObj == nil || watchObj.Event == nil || watchObj.Event.Type == nil {
		return nil
	}

	switch watchObj.Event.Type.(type) {
	case *rmetav1.WatchEvent_Event_Create_:
		return w.processCreate(ctx, watchObj.Event.GetCreate().Item)
	case *rmetav1.WatchEvent_Event_Update_:
		return w.processUpdate(ctx,
			watchObj.Event.GetUpdate().NewItem, watchObj.Event.GetUpdate().OldItem)
	case *rmetav1.WatchEvent_Event_Delete_:
		return w.processDelete(ctx, watchObj.Event.GetDelete().Item)
	default:
		return errors.Errorf("Unknown event type")
	}
}

func (w *Watcher) processCreate(ctx context.Context, item *anypb.Any) error {
	obj, err := w.getObject(item)
	if err != nil {
		return err
	}

	md := obj.GetMetadata()

	prev, ok := w.store.set(md, item)
	if !ok {
		return nil
	}

	if prev == nil || w.onUpdate == nil {
		if w.onCreate == nil {
			return nil
		}

		w.dispatch(ctx, md, func(ctx context.Context) error {
			return w.onCreate(ctx, obj)
		})

		return nil
	}

	oldObj, err := w.getObject(prev.item)
	if err != nil {
		return err
	}

	w.dispatch(ctx, md, func(ctx context.Context) error {
		return w.onUpdate(ctx, obj, oldObj)
	})

	return nil
}

func (w *Watcher) processUpdate(ctx context.Context, newItem, oldItem *anypb.Any) error {
	if w.onUpdate == nil {
		return nil
	}

	newObj, err := w.getObject(newItem)
	if err != nil {
		return err
	}

	oldObj, err := w.getObject(oldItem)
	if err != nil {
		return err
	}

	md := newObj.GetMetadata()

	prev, ok := w.store.set(md, newItem)
	if !ok {
		return nil
	}

	if prev != nil && prev.resourceVersion != oldObj.GetMetadata().GetResourceVersion() {
		oldObj, err = w.getObject(prev.item)
		if err != nil {
			return err
		}
	}

	w.dispatch(ctx, md, func(ctx context.Context) error {
		return w.onUpdate(ctx, newObj, oldObj)
	})

	return nil
}

func (w *Watcher) processDelete(ctx context.Context, item *anypb.Any) error {
	obj, err := w.getObject(item)
	if err != nil {
		return err
	}

	md := obj.GetMetadata()

	if !w.store.delete(md) || w.onDelete == nil {
		return nil
	}

	w.dispatch(ctx, md, func(ctx context.Context) error {
		return w.onDelete(ctx, obj)
	})

	return nil
}

func (w *Watcher) dispatch(ctx context.Context, md *metav1.Metadata, fn func(ctx context.Context) error) {
	uid := md.GetUid()
	resourceVersion := md.GetResourceVersion()

	w.queue.enqueue(ctx, uid, func(ctx context.Context) {
		if err := w.runFn(ctx, fn); err != nil && ctx.Err() == nil {
			zap.L().Warn("Could not run watcher fn. Giving up",
				zap.String("api", w.api),
				zap.String("kind", w.kind),
				zap.String("version", w.version),
				zap.String("uid", uid),
				zap.Error(err))

			w.store.forget(uid, resourceVersion)
		}
	})
}

func (w *Watcher) runFn(ctx context.Context, fn func(ctx context.Context) error) error {
	if fn == nil {
		return nil
	}

	var err error

	for i := range runFnMaxAttempts {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(i) * runFnBackoff):
			}
		}

		err = w.doRunFn(ctx, fn)
		if err == nil {
			return nil
		}

		zap.L().Warn("Could not run watcher fn. Trying again...",
			zap.String("api", w.api),
			zap.String("kind", w.kind),
			zap.String("version", w.version),
			zap.Error(err),
			zap.Int("attempt", i+1))
	}

	return err
}

func (w *Watcher) doRunFn(ctx context.Context, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, runFnTimeout)
	defer cancel()

	return fn(ctx)
}
