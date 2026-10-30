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

package userctx

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octovigilc"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type downstreamClient struct {
	coctovigilv1.InternalServiceClient
	response *coctovigilv1.GetDownstreamFromSessionUIDResponse
	err      error
	uid      string
}

func (c *downstreamClient) GetDownstreamFromSessionUID(ctx context.Context, req *coctovigilv1.GetDownstreamFromSessionUIDRequest, opts ...grpc.CallOption) (*coctovigilv1.GetDownstreamFromSessionUIDResponse, error) {
	c.uid = req.SessionUID
	return c.response, c.err
}

type downstreamOctovigilClient struct {
	octovigilc.ClientInterface
	c *downstreamClient
}

func (c *downstreamOctovigilClient) InternalC() coctovigilv1.InternalServiceClient {
	return c.c
}

type downstreamStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *downstreamStream) Context() context.Context {
	return s.ctx
}

func TestSessionUID(t *testing.T) {
	for _, md := range []metadata.MD{nil, {}, {"x-octelium-session-uid": {}}, {"x-octelium-session-uid": {"first", "second"}}} {
		_, err := getSessionUID(metadata.NewIncomingContext(context.Background(), md))
		assert.NotNil(t, err)
	}
	_, err := getSessionUID(context.Background())
	assert.NotNil(t, err)
	uid, err := getSessionUID(metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-octelium-session-uid", "session")))
	assert.Nil(t, err)
	assert.Equal(t, "session", uid)
}

func TestUserCtx(t *testing.T) {
	previous := ldflags.TestMode
	t.Cleanup(func() { ldflags.TestMode = previous })
	ldflags.TestMode = "false"
	c := &downstreamClient{response: &coctovigilv1.GetDownstreamFromSessionUIDResponse{
		User: &corev1.User{}, Session: &corev1.Session{}, Device: &corev1.Device{}, Groups: []*corev1.Group{{}},
	}}
	m := &Middleware{c: &downstreamOctovigilClient{c: c}}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-octelium-session-uid", "session"))
	_, err := GetUserCtx(ctx)
	assert.Equal(t, codes.Internal, status.Code(err))
	_, err = m.getDownstream(context.Background())
	assert.NotNil(t, err)
	assert.Empty(t, c.uid)
	ctx = context.WithValue(ctx, ctxMiddleware, m)
	res, err := GetUserCtx(ctx)
	assert.Nil(t, err)
	assert.Equal(t, "session", c.uid)
	assert.Same(t, c.response.User, res.User)
	assert.Same(t, c.response.Session, res.Session)
	assert.Same(t, c.response.Device, res.Device)
	assert.Equal(t, c.response.Groups, res.Groups)
	c.err = status.Error(codes.Unavailable, "unavailable")
	res, err = GetUserCtx(ctx)
	assert.ErrorIs(t, err, c.err)
	assert.Nil(t, res)

	ldflags.TestMode = "true"
	_, err = GetUserCtx(context.Background())
	assert.Equal(t, codes.Internal, status.Code(err))
	want := &UserCtx{User: &corev1.User{}}
	res, err = GetUserCtx(context.WithValue(context.Background(), "octelium-user-ctx", want))
	assert.Nil(t, err)
	assert.Same(t, want, res)
}

func TestInterceptors(t *testing.T) {
	m := &Middleware{}
	wantErr := status.Error(codes.PermissionDenied, "denied")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-octelium-session-uid", "session"))
	req := &corev1.User{}
	resp, err := m.UnaryServerInterceptor()(ctx, req, &grpc.UnaryServerInfo{}, func(ctx context.Context, actual any) (any, error) {
		assert.Same(t, m, ctx.Value(ctxMiddleware))
		assert.Same(t, req, actual)
		uid, err := getSessionUID(ctx)
		assert.Nil(t, err)
		assert.Equal(t, "session", uid)
		return req, wantErr
	})
	assert.Same(t, req, resp)
	assert.ErrorIs(t, err, wantErr)
	assert.Nil(t, ctx.Value(ctxMiddleware))
	err = m.StreamServerInterceptor()(req, &downstreamStream{ctx: ctx}, &grpc.StreamServerInfo{}, func(srv any, stream grpc.ServerStream) error {
		assert.Same(t, req, srv)
		assert.Same(t, m, stream.Context().Value(ctxMiddleware))
		uid, err := getSessionUID(stream.Context())
		assert.Nil(t, err)
		assert.Equal(t, "session", uid)
		return wantErr
	})
	assert.ErrorIs(t, err, wantErr)
}

func TestNewMiddlewareCredentialError(t *testing.T) {
	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "true")
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/octelium-nonexistent-spiffe.sock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m, err := New(ctx, nil)
	assert.NotNil(t, err)
	assert.Nil(t, m)
}
