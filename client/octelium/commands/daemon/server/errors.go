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
	"errors"

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/pkg/grpcerr"
)

func getError(err error, code daemonv1.Error_Code) *daemonv1.Error {
	ret := &daemonv1.Error{
		Code:    code,
		Message: err.Error(),
	}

	switch {
	case errors.Is(err, context.Canceled):
		ret.Code = daemonv1.Error_OPERATION_CANCELED
	case errors.Is(err, context.DeadlineExceeded):
		ret.Retryable = true
	case grpcerr.IsUnauthenticated(err):
		ret.Code = daemonv1.Error_AUTHENTICATION_REQUIRED
	case grpcerr.IsPermissionDenied(err):
		ret.Code = daemonv1.Error_PERMISSION_DENIED
	case grpcerr.IsUnavailable(err):
		ret.Code = daemonv1.Error_CLUSTER_UNREACHABLE
		ret.Retryable = true
	}

	switch ret.Code {
	case daemonv1.Error_CLUSTER_UNREACHABLE,
		daemonv1.Error_CONNECTION_FAILED,
		daemonv1.Error_NETWORK_CONFIGURATION_FAILED,
		daemonv1.Error_DNS_CONFIGURATION_FAILED:
		ret.Retryable = true
	}

	return ret
}
