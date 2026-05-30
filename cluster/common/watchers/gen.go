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

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
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

		for ctx.Err() == nil {
			err := w.doRun(ctx)
			if err == nil {
				return
			}

			zap.L().Warn("Could not run watcher. Trying again...",
				zap.String("api", w.api),
				zap.String("kind", w.kind),
				zap.String("version", w.version),
				zap.Error(err))

			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}
	}()

	return nil
}

func (w *Watcher) doRun(parentCtx context.Context) error {
	ctx, cancelFn := context.WithCancel(parentCtx)
	defer cancelFn()

	processCh := make(chan *rmetav1.WatchEvent, 1000)

	zap.L().Debug("Starting running resource watcher",
		zap.String("api", w.api),
		zap.String("version", w.version),
		zap.String("kind", w.kind))

	grpcClientStream, err := w.openWatchStream(ctx)
	if err != nil {
		return err
	}

	go w.startProcessLoop(ctx, cancelFn, processCh)
	go w.startRecvLoop(ctx, cancelFn, grpcClientStream, processCh)

	<-ctx.Done()

	if err := grpcClientStream.CloseSend(); err != nil {
		zap.L().Debug("Could not close watcher client stream",
			zap.String("api", w.api),
			zap.String("kind", w.kind),
			zap.String("version", w.version),
			zap.Error(err))
	}

	if parentCtx.Err() != nil {
		return nil
	}

	return errors.Errorf("Watch stream for %s/%s terminated...", w.api, w.kind)
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

func (w *Watcher) startRecvLoop(
	ctx context.Context,
	cancelFn context.CancelFunc,
	grpcClientStream grpc.ClientStream,
	processCh chan<- *rmetav1.WatchEvent,
) {
	failN := 0
	defer cancelFn()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			watchObj := &rmetav1.WatchEvent{}
			if err := grpcClientStream.RecvMsg(watchObj); err != nil {
				zap.L().Warn("Could not recv watch object",
					zap.String("api", w.api),
					zap.String("kind", w.kind),
					zap.String("version", w.version),
					zap.Error(err),
					zap.Int("attempt", failN+1))

				failN++

				select {
				case <-ctx.Done():
					return
				case <-time.After(100 * time.Millisecond):
				}

				if failN > 15 {
					zap.L().Warn("Could not recv watch object. Exiting watcher recv loop",
						zap.String("api", w.api),
						zap.String("kind", w.kind),
						zap.String("version", w.version),
						zap.Error(err))
					return
				}

				continue
			}

			failN = 0

			select {
			case processCh <- watchObj:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (w *Watcher) startProcessLoop(
	ctx context.Context,
	cancelFn context.CancelFunc,
	processCh <-chan *rmetav1.WatchEvent,
) {
	defer cancelFn()

	for {
		select {
		case <-ctx.Done():
			return
		case obj := <-processCh:
			if err := w.doProcess(ctx, obj); err != nil {
				zap.L().Warn("Could not process watcher event",
					zap.String("api", w.api),
					zap.String("kind", w.kind),
					zap.String("version", w.version),
					zap.Error(err))
			}
		}
	}
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
		if w.onCreate != nil {
			obj, err := w.getObject(watchObj.Event.GetCreate().Item)
			if err != nil {
				return err
			}

			return w.runFn(ctx, func(ctx context.Context) error {
				return w.onCreate(ctx, obj)
			})
		}

	case *rmetav1.WatchEvent_Event_Update_:
		if w.onUpdate != nil {
			newObj, err := w.getObject(watchObj.Event.GetUpdate().NewItem)
			if err != nil {
				return err
			}

			oldObj, err := w.getObject(watchObj.Event.GetUpdate().OldItem)
			if err != nil {
				return err
			}

			return w.runFn(ctx, func(ctx context.Context) error {
				return w.onUpdate(ctx, newObj, oldObj)
			})
		}

	case *rmetav1.WatchEvent_Event_Delete_:
		if w.onDelete != nil {
			obj, err := w.getObject(watchObj.Event.GetDelete().Item)
			if err != nil {
				return err
			}

			return w.runFn(ctx, func(ctx context.Context) error {
				return w.onDelete(ctx, obj)
			})
		}

	default:
		return errors.Errorf("Unknown event type")
	}

	return nil
}

func (w *Watcher) runFn(ctx context.Context, fn func(ctx context.Context) error) error {
	if fn == nil {
		return nil
	}

	go func(ctx context.Context) {
		for i := range 5 {
			nctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
			err := fn(nctx)
			if err == nil {
				cancel()
				return
			}

			cancel()

			zap.L().Warn("Could not run watcher fn. Trying again...",
				zap.String("api", w.api),
				zap.String("kind", w.kind),
				zap.String("version", w.version),
				zap.Error(err),
				zap.Int("attempt", i+1))
		}
	}(ctx)

	return nil
}
