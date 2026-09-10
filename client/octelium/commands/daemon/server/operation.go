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

package server

import (
	"context"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type operation struct {
	id     string
	domain string
	typ    daemonv1.Operation_Type
	state  daemonv1.Operation_State

	createdAt   *timestamppb.Timestamp
	updatedAt   *timestamppb.Timestamp
	completedAt *timestamppb.Timestamp

	action *daemonv1.Action
	err    *daemonv1.Error

	cancelFn context.CancelFunc
}

func newOperation(domain string, typ daemonv1.Operation_Type, cancelFn context.CancelFunc) *operation {
	now := pbutils.Now()

	return &operation{
		id:        uuid.NewString(),
		domain:    domain,
		typ:       typ,
		state:     daemonv1.Operation_PENDING,
		createdAt: now,
		updatedAt: now,
		cancelFn:  cancelFn,
	}
}

func (o *operation) isDone() bool {
	switch o.state {
	case daemonv1.Operation_SUCCEEDED, daemonv1.Operation_FAILED, daemonv1.Operation_CANCELED:
		return true
	default:
		return false
	}
}

func (o *operation) setState(state daemonv1.Operation_State) {
	if o.isDone() {
		return
	}

	o.state = state
	o.updatedAt = pbutils.Now()

	if o.isDone() {
		o.completedAt = o.updatedAt
		o.action = nil
	}
}

func (o *operation) setFailed(err *daemonv1.Error) {
	if o.isDone() {
		return
	}

	o.err = err
	if err.GetCode() == daemonv1.Error_OPERATION_CANCELED {
		o.setState(daemonv1.Operation_CANCELED)
		return
	}

	o.setState(daemonv1.Operation_FAILED)
}

func (o *operation) toPB() *daemonv1.Operation {
	return &daemonv1.Operation{
		Id:          o.id,
		Domain:      o.domain,
		Type:        o.typ,
		State:       o.state,
		CreatedAt:   o.createdAt,
		UpdatedAt:   o.updatedAt,
		CompletedAt: o.completedAt,
		Action:      o.action,
		Error:       o.err,
	}
}
