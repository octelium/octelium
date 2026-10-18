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

package cliutils

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestExitError(t *testing.T) {
	grpcErr := status.Error(codes.NotFound, "Session UID not Found")
	plainErr := errors.New("Could not cleanly close the controller")

	assert.Equal(t, 1, GetExitCode(grpcErr))
	assert.Equal(t, 1, GetExitCode(plainErr))
	assert.Equal(t, 1, GetExitCode(&ExitError{Err: grpcErr}))

	exitErr := &ExitError{Code: 3, Err: grpcErr}
	assert.Equal(t, 3, GetExitCode(exitErr))
	assert.Equal(t, 3, GetExitCode(errors.Wrap(exitErr, "wrapped")))

	assert.Equal(t, grpcErr.Error(), exitErr.Error())
	assert.True(t, errors.Is(exitErr, grpcErr))
	assert.Equal(t, codes.NotFound, status.Code(exitErr))

	assert.Equal(t, GrpcErr(grpcErr).Error(), GrpcErr(exitErr).Error())
	assert.Equal(t, "gRPC error NotFound: Session UID not Found", GrpcErr(exitErr).Error())

	assert.Equal(t, plainErr.Error(), GrpcErr(&ExitError{Code: 3, Err: plainErr}).Error())
}
