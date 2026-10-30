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

package grpcutils

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestStatusErrors(t *testing.T) {
	t.Setenv("OCTELIUM_DEV", "")
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	err := fmt.Errorf("private backend details")
	for _, tc := range []struct {
		err     error
		code    codes.Code
		message string
	}{
		{InvalidArg("invalid %s", "value"), codes.InvalidArgument, "invalid value"},
		{InvalidArgWithErr(err), codes.InvalidArgument, err.Error()},
		{NotFound("missing %s", "value"), codes.NotFound, "missing value"},
		{Internal("private %s", "details"), codes.Internal, "Internal error"},
		{InternalWithErr(err), codes.Internal, "Internal error"},
		{K8sInternal(err), codes.Internal, "Internal error"},
		{Unauthorized("denied %s", "value"), codes.PermissionDenied, "denied value"},
		{PermissionDenied("denied %s", "value"), codes.PermissionDenied, "denied value"},
		{Unauthenticated("private %s", "details"), codes.Unauthenticated, "Unauthenticated User"},
		{UnauthenticatedWithErr(err), codes.Unauthenticated, "Unauthenticated User"},
		{AlreadyExists("exists %s", "value"), codes.AlreadyExists, "exists value"},
	} {
		assert.Equal(t, tc.code, status.Code(tc.err))
		assert.Equal(t, tc.message, status.Convert(tc.err).Message())
	}
	for _, convert := range []func(error, string, ...any) error{NotFoundOrInternal, K8sNotFoundOrInternal} {
		assert.Equal(t, codes.NotFound, status.Code(convert(status.Error(codes.NotFound, "missing"), "missing %s", "value")))
		assert.Equal(t, "Internal error", status.Convert(convert(err, "private details")).Message())
	}
	notFound := status.Error(codes.NotFound, "missing")
	assert.Equal(t, notFound, K8sNotFoundOrInternalWithErr(notFound))
	assert.Equal(t, "Internal error", status.Convert(K8sNotFoundOrInternalWithErr(err)).Message())
	t.Setenv("OCTELIUM_DEV", "true")
	assert.ErrorContains(t, K8sInternal(err), err.Error())
}

func TestHeaderValues(t *testing.T) {
	for _, ctx := range []context.Context{context.Background(), metadata.NewIncomingContext(context.Background(), metadata.MD{})} {
		value, err := GetHeaderValue(ctx, "x-header")
		assert.NotNil(t, err)
		assert.Empty(t, value)
		assert.Empty(t, GetHeaderValueMust(ctx, "x-header"))
		assert.Nil(t, GetHeaderValueAll(ctx, "x-header"))
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-header", "first", "x-header", "second"))
	value, err := GetHeaderValue(ctx, "X-Header")
	assert.Nil(t, err)
	assert.Equal(t, "first", value)
	assert.Equal(t, "first", GetHeaderValueMust(ctx, "x-header"))
	assert.Equal(t, []string{"first", "second"}, GetHeaderValueAll(ctx, "x-header"))
}
