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

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/pkg/errors"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/octovigilc"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Middleware struct {
	c octovigilc.ClientInterface
}

func New(ctx context.Context) (*Middleware, error) {

	c, err := octovigilc.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	return &Middleware{
		c: c,
	}, nil

}

func (m *Middleware) getDownstream(ctx context.Context) (*UserCtx, error) {

	sessUID, err := getSessionUID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := m.c.InternalC().GetDownstreamFromSessionUID(ctx, &coctovigilv1.GetDownstreamFromSessionUIDRequest{
		SessionUID: sessUID,
	})
	if err != nil {
		return nil, err
	}

	return &UserCtx{
		User:    resp.User,
		Session: resp.Session,
		Groups:  resp.Groups,
		Device:  resp.Device,
	}, nil
}

func (m *Middleware) UnaryServerInterceptor() grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {

		i, err := m.getDownstream(ctx)
		if err != nil {
			zap.S().Debugf("Could not authenticate User: %+v", err)
			return nil, status.Errorf(codes.Unauthenticated, "Could not authenticate User")
		}

		newCtx := context.WithValue(ctx, "octelium-user-ctx", i)

		return handler(newCtx, req)
	}
}

func (m *Middleware) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

		ctx := stream.Context()

		i, err := m.getDownstream(ctx)
		if err != nil {
			zap.S().Debugf("Could not authenticate User: %+v", err)
			return status.Errorf(codes.Unauthenticated, "Could not authenticate User")
		}

		newCtx := context.WithValue(ctx, "octelium-user-ctx", i)

		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx

		return handler(srv, wrapped)
	}
}

func getSessionUID(ctx context.Context) (string, error) {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.Errorf("Could not find metadata from context")
	}

	if hdrVal := md.Get("x-octelium-session-uid"); hdrVal != nil {
		if len(hdrVal) == 1 {
			return hdrVal[0], nil
		}
	}

	return "", errors.Errorf("Could not find x-octelium-session-uid header")
}

type UserCtx struct {
	User    *corev1.User
	Session *corev1.Session
	Groups  []*corev1.Group
	Device  *corev1.Device
}

func GetUserCtx(ctx context.Context) (*UserCtx, error) {
	usrCtx, ok := ctx.Value("octelium-user-ctx").(*UserCtx)
	if !ok {
		return nil, serr.Internal("Could not get user information. Please try again.")
	}
	return usrCtx, nil
}
