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

package grpcerr

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func IsNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

func AlreadyExists(err error) bool {
	return status.Code(err) == codes.AlreadyExists
}

func IsInternal(err error) bool {
	return status.Code(err) == codes.Internal
}

func IsInvalidArg(err error) bool {
	return status.Code(err) == codes.InvalidArgument
}

func IsUnauthorized(err error) bool {
	return status.Code(err) == codes.PermissionDenied
}

func IsPermissionDenied(err error) bool {
	return status.Code(err) == codes.PermissionDenied
}

func IsUnauthenticated(err error) bool {
	return status.Code(err) == codes.Unauthenticated
}

func IsUnknown(err error) bool {
	return status.Code(err) == codes.Unknown
}

func IsCanceled(err error) bool {
	return status.Code(err) == codes.Canceled
}

func IsDeadlineExceeded(err error) bool {
	return status.Code(err) == codes.DeadlineExceeded
}

func IsResourceChanged(err error) bool {
	return status.Code(err) == codes.OutOfRange
}

func IsUnavailable(err error) bool {
	return status.Code(err) == codes.Unavailable
}

func IsResourceExhausted(err error) bool {
	return status.Code(err) == codes.ResourceExhausted
}

func IsUnimplemented(err error) bool {
	return status.Code(err) == codes.Unimplemented
}
