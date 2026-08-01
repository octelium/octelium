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

package middlewares

import (
	"context"
	"slices"
	"testing"

	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestGetSessionRef(t *testing.T) {

	ctx := context.Background()

	assert.Equal(t, "", getSessionRef(ctx))

	assert.Equal(t, "", getSessionRef(metadata.NewIncomingContext(ctx, metadata.MD{})))

	{
		mdCtx := metadata.NewIncomingContext(ctx, metadata.Pairs(
			"x-octelium-session-ref", "ref-value"))
		assert.Equal(t, "ref-value", getSessionRef(mdCtx))
	}

	{
		mdCtx := metadata.NewIncomingContext(ctx, metadata.MD{
			"x-octelium-session-ref": []string{"a", "b"},
		})
		assert.Equal(t, "", getSessionRef(mdCtx))
	}

	{
		mdCtx := metadata.NewIncomingContext(ctx, metadata.Pairs(
			"x-other-header", "val"))
		assert.Equal(t, "", getSessionRef(mdCtx))
	}
}

func TestGetReqPath(t *testing.T) {

	ctx := context.Background()

	assert.Equal(t, "", getReqPath(ctx))

	assert.Equal(t, "", getReqPath(metadata.NewIncomingContext(ctx, metadata.MD{})))

	{
		mdCtx := metadata.NewIncomingContext(ctx, metadata.Pairs(
			"x-octelium-req-path", "/svc/Method"))
		assert.Equal(t, "/svc/Method", getReqPath(mdCtx))
	}

	{
		mdCtx := metadata.NewIncomingContext(ctx, metadata.MD{
			"x-octelium-req-path": []string{"a", "b"},
		})
		assert.Equal(t, "", getReqPath(mdCtx))
	}
}

func TestGetRetryCodes(t *testing.T) {

	ret := getRetryCodes()

	assert.True(t, slices.Contains(ret, codes.Unavailable))
	assert.True(t, slices.Contains(ret, codes.ResourceExhausted))
	assert.True(t, slices.Contains(ret, codes.Aborted))

	assert.False(t, slices.Contains(ret, codes.Internal))
	assert.False(t, slices.Contains(ret, codes.Unknown))
	assert.False(t, slices.Contains(ret, codes.DataLoss))
	assert.False(t, slices.Contains(ret, codes.DeadlineExceeded))
	assert.False(t, slices.Contains(ret, codes.NotFound))
	assert.False(t, slices.Contains(ret, codes.InvalidArgument))
}

func TestHandleErr(t *testing.T) {

	errs := []error{
		nil,
		status.Error(codes.Unavailable, "unavailable"),
		status.Error(codes.Internal, "internal"),
		status.Error(codes.DeadlineExceeded, "deadline"),
		status.Error(codes.Unknown, "unknown"),
		status.Error(codes.Unimplemented, "unimplemented"),
		status.Error(codes.Aborted, "aborted"),
		status.Error(codes.NotFound, "notfound"),
		status.Error(codes.InvalidArgument, "invalid"),
	}

	for _, err := range errs {
		handleErr(err)
	}
}

func TestGetUnaryInterceptors(t *testing.T) {

	old := ldflags.TestMode
	t.Cleanup(func() {
		ldflags.TestMode = old
	})

	{
		ldflags.TestMode = "true"
		ret := GetUnaryInterceptors()
		assert.Equal(t, 2, len(ret))
		for _, itm := range ret {
			assert.NotNil(t, itm)
		}
	}

	{
		ldflags.TestMode = "false"
		ret := GetUnaryInterceptors()
		assert.Equal(t, 2, len(ret))
	}
}

func TestGetStreamInterceptors(t *testing.T) {

	ret := GetStreamInterceptors()
	assert.Equal(t, 2, len(ret))
	for _, itm := range ret {
		assert.NotNil(t, itm)
	}
}

func TestUnaryClientInterceptorPropagatesHeaders(t *testing.T) {

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-octelium-session-ref", "sess-ref",
		"x-octelium-req-path", "/svc/Method"))

	interceptor := unaryClientInterceptor()

	var gotMD metadata.MD

	err := interceptor(ctx, "/svc/Method", nil, nil, nil,
		func(ctx context.Context, method string, req, reply any,
			cc *grpc.ClientConn, opts ...grpc.CallOption) error {
			gotMD, _ = metadata.FromOutgoingContext(ctx)
			return nil
		})
	assert.Nil(t, err, "%+v", err)

	assert.Equal(t, []string{"sess-ref"}, gotMD.Get("x-octelium-session-ref"))
	assert.Equal(t, []string{"/svc/Method"}, gotMD.Get("x-octelium-req-path"))
}

func TestStreamClientInterceptorPropagatesHeaders(t *testing.T) {

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-octelium-session-ref", "sess-ref"))

	interceptor := streamClientInterceptor()

	var gotMD metadata.MD

	_, err := interceptor(ctx, nil, nil, "/svc/Method",
		func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
			method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			gotMD, _ = metadata.FromOutgoingContext(ctx)
			return nil, nil
		})
	assert.Nil(t, err, "%+v", err)

	assert.Equal(t, []string{"sess-ref"}, gotMD.Get("x-octelium-session-ref"))
	assert.Equal(t, 0, len(gotMD.Get("x-octelium-req-path")))
}
