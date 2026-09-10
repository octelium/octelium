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
	"testing"

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetError(t *testing.T) {
	{
		err := getError(errors.Errorf("Could not set the routes"),
			daemonv1.Error_NETWORK_CONFIGURATION_FAILED)
		assert.Equal(t, daemonv1.Error_NETWORK_CONFIGURATION_FAILED, err.Code)
		assert.Equal(t, "Could not set the routes", err.Message)
		assert.True(t, err.Retryable)
	}
	{
		err := getError(context.Canceled, daemonv1.Error_CONNECTION_FAILED)
		assert.Equal(t, daemonv1.Error_OPERATION_CANCELED, err.Code)
		assert.False(t, err.Retryable)
	}
	{
		err := getError(errors.Wrap(context.Canceled, "closing"),
			daemonv1.Error_AUTHENTICATION_FAILED)
		assert.Equal(t, daemonv1.Error_OPERATION_CANCELED, err.Code)
	}
	{
		err := getError(status.Error(codes.Unauthenticated, "no"),
			daemonv1.Error_CONNECTION_FAILED)
		assert.Equal(t, daemonv1.Error_AUTHENTICATION_REQUIRED, err.Code)
	}
	{
		err := getError(status.Error(codes.Unavailable, "no"),
			daemonv1.Error_CONNECTION_FAILED)
		assert.Equal(t, daemonv1.Error_CLUSTER_UNREACHABLE, err.Code)
		assert.True(t, err.Retryable)
	}
	{
		err := getError(status.Error(codes.PermissionDenied, "no"),
			daemonv1.Error_CONNECTION_FAILED)
		assert.Equal(t, daemonv1.Error_PERMISSION_DENIED, err.Code)
		assert.False(t, err.Retryable)
	}
	{
		err := getError(errors.Errorf("unknown"), daemonv1.Error_INTERNAL)
		assert.Equal(t, daemonv1.Error_INTERNAL, err.Code)
		assert.False(t, err.Retryable)
	}
	{
		err := getError(authenticator.ErrWebAuthenticationTimedOut,
			daemonv1.Error_AUTHENTICATION_FAILED)
		assert.Equal(t, daemonv1.Error_AUTHENTICATION_TIMED_OUT, err.Code)
		assert.False(t, err.Retryable)
	}
	{
		err := getError(errors.Wrap(authenticator.ErrWebAuthenticationTimedOut, "waiting"),
			daemonv1.Error_AUTHENTICATION_FAILED)
		assert.Equal(t, daemonv1.Error_AUTHENTICATION_TIMED_OUT, err.Code)
	}
}

func TestCanonicalizeDomain(t *testing.T) {
	for _, itm := range []struct {
		arg string
		ret string
	}{
		{arg: "example.com", ret: "example.com"},
		{arg: "EXAMPLE.COM", ret: "example.com"},
		{arg: "example.com.", ret: "example.com"},
		{arg: "  Example.Com.  ", ret: "example.com"},
		{arg: "sub.example.com", ret: "sub.example.com"},
		{arg: "bücher.example", ret: "xn--bcher-kva.example"},
	} {
		ret, err := canonicalizeDomain(itm.arg)
		assert.Nil(t, err, "arg=%s", itm.arg)
		assert.Equal(t, itm.ret, ret)
	}

	for _, arg := range []string{
		"",
		"   ",
		"example",
		"not a domain",
		"example.com/path",
		"1.2.3.4",
		"::1",
		"example..com",
		"-example.com",
	} {
		_, err := canonicalizeDomain(arg)
		assert.True(t, grpcerr.IsInvalidArg(err), "arg=%s", arg)
	}
}
