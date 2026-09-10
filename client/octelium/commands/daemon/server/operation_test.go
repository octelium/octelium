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
	"testing"

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/stretchr/testify/assert"
)

func TestOperation(t *testing.T) {
	{
		op := newOperation("example.com", daemonv1.Operation_CONNECT, nil)
		assert.NotEmpty(t, op.id)
		assert.Equal(t, daemonv1.Operation_PENDING, op.state)
		assert.False(t, op.isDone())
		assert.Nil(t, op.completedAt)

		op.setState(daemonv1.Operation_RUNNING)
		assert.False(t, op.isDone())

		op.setState(daemonv1.Operation_SUCCEEDED)
		assert.True(t, op.isDone())
		assert.NotNil(t, op.completedAt)

		op.setState(daemonv1.Operation_FAILED)
		assert.Equal(t, daemonv1.Operation_SUCCEEDED, op.state)

		pb := op.toPB()
		assert.Equal(t, op.id, pb.Id)
		assert.Equal(t, "example.com", pb.Domain)
		assert.Equal(t, daemonv1.Operation_CONNECT, pb.Type)
		assert.Equal(t, daemonv1.Operation_SUCCEEDED, pb.State)
	}

	{
		op := newOperation("example.com", daemonv1.Operation_AUTHENTICATE, nil)
		op.action = &daemonv1.Action{
			Type: &daemonv1.Action_OpenURL_{
				OpenURL: &daemonv1.Action_OpenURL{
					Url: "https://example.com/login",
				},
			},
		}
		op.setState(daemonv1.Operation_WAITING_FOR_USER)
		assert.False(t, op.isDone())
		assert.NotNil(t, op.toPB().Action)

		op.setFailed(&daemonv1.Error{
			Code: daemonv1.Error_AUTHENTICATION_FAILED,
		})
		assert.Equal(t, daemonv1.Operation_FAILED, op.state)
		assert.Equal(t, daemonv1.Error_AUTHENTICATION_FAILED, op.toPB().Error.Code)

		assert.Nil(t, op.toPB().Action)
	}

	{
		op := newOperation("example.com", daemonv1.Operation_LOGOUT, nil)
		op.setFailed(&daemonv1.Error{
			Code: daemonv1.Error_OPERATION_CANCELED,
		})
		assert.Equal(t, daemonv1.Operation_CANCELED, op.state)
	}

	{
		var isCanceled bool
		op := newOperation("example.com", daemonv1.Operation_CONNECT, func() {
			isCanceled = true
		})
		assert.True(t, op.isCancellable())
		assert.True(t, op.toPB().Cancellable)

		op.setState(daemonv1.Operation_RUNNING)
		assert.True(t, op.isCancellable())

		op.setCanceled("superseded")
		assert.Equal(t, daemonv1.Operation_CANCELED, op.state)
		assert.Equal(t, "superseded", op.toPB().Error.Message)
		assert.False(t, op.isCancellable())
		assert.False(t, op.toPB().Cancellable)
		assert.Nil(t, op.cancelFn)
		assert.False(t, isCanceled)
	}

	{
		op := newOperation("example.com", daemonv1.Operation_DISCONNECT, nil)
		op.setState(daemonv1.Operation_RUNNING)
		assert.False(t, op.isCancellable())
	}
}
