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

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/client/mobilev1"
)

const logQueueSize = 256

type eventDispatcher struct {
	host      Host
	getStatus func() *daemonv1.GetStatusResponse

	statusCh chan struct{}
	logCh    chan *mobilev1.Log
	doneCh   chan struct{}
}

func newEventDispatcher(host Host, getStatus func() *daemonv1.GetStatusResponse) *eventDispatcher {
	return &eventDispatcher{
		host:      host,
		getStatus: getStatus,
		statusCh:  make(chan struct{}, 1),
		logCh:     make(chan *mobilev1.Log, logQueueSize),
		doneCh:    make(chan struct{}),
	}
}

func (d *eventDispatcher) run(ctx context.Context) {
	defer close(d.doneCh)

	for {
		select {
		case <-ctx.Done():
			return
		case <-d.statusCh:
			d.host.SendEvent(&mobilev1.Event{
				Type: &mobilev1.Event_Status{
					Status: d.getStatus(),
				},
			})
		case log := <-d.logCh:
			d.host.SendEvent(&mobilev1.Event{
				Type: &mobilev1.Event_Log{
					Log: log,
				},
			})
		}
	}
}

func (d *eventDispatcher) notifyStatus() {
	select {
	case d.statusCh <- struct{}{}:
	default:
	}
}

func (d *eventDispatcher) sendLog(log *mobilev1.Log) {
	select {
	case d.logCh <- log:
	default:
	}
}

func (d *eventDispatcher) wait() {
	<-d.doneCh
}
