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
	"math"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

func unaryClientInterceptor() grpc.UnaryClientInterceptor {

	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {

		if sessionRef := getSessionRef(ctx); sessionRef != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-session-ref", sessionRef)
		}

		if reqPath := getReqPath(ctx); reqPath != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-req-path", reqPath)
		}

		err := invoker(ctx, method, req, reply, cc, opts...)
		if err != nil {
			handleErr(err)
		}
		return err
	}
}

func handleErr(err error) {
	if grpcerr.IsInternal(err) || grpcerr.IsUnknown(err) || grpcerr.IsDeadlineExceeded(err) || grpcerr.IsUnavailable(err) {
		zap.L().Debug("octeliumC err", zap.Error(err))
	}
}

func streamClientInterceptor() grpc.StreamClientInterceptor {

	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {

		if sessionRef := getSessionRef(ctx); sessionRef != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-session-ref", sessionRef)
		}

		if reqPath := getReqPath(ctx); reqPath != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "x-octelium-req-path", reqPath)
		}

		clientStream, err := streamer(ctx, desc, cc, method, opts...)
		return clientStream, err
	}
}

func getSessionRef(ctx context.Context) string {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	if hdrVal := md.Get("x-octelium-session-ref"); hdrVal != nil {
		if len(hdrVal) == 1 {
			return hdrVal[0]
		}
	}

	return ""
}

func getReqPath(ctx context.Context) string {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	if hdrVal := md.Get("x-octelium-req-path"); hdrVal != nil {
		if len(hdrVal) == 1 {
			return hdrVal[0]
		}
	}

	return ""
}

func getRetryCodes() []codes.Code {
	return []codes.Code{
		codes.Unavailable,
		codes.ResourceExhausted,
		codes.Unknown,
		codes.Aborted,
		codes.DataLoss,
		codes.Internal,
		codes.DeadlineExceeded,
	}
}

func GetUnaryInterceptors() []grpc.UnaryClientInterceptor {

	unaryTries := uint(32)
	if ldflags.IsTest() {
		unaryTries = 1
	}

	return []grpc.UnaryClientInterceptor{
		grpc_retry.UnaryClientInterceptor(
			grpc_retry.WithMax(unaryTries),
			grpc_retry.WithBackoff(grpc_retry.BackoffLinear(1000*time.Millisecond)),
			grpc_retry.WithCodes(getRetryCodes()...)),
		unaryClientInterceptor(),
	}
}

func GetStreamInterceptors() []grpc.StreamClientInterceptor {
	return []grpc.StreamClientInterceptor{
		grpc_retry.StreamClientInterceptor(
			grpc_retry.WithMax(math.MaxUint32),
			grpc_retry.WithBackoff(grpc_retry.BackoffLinear(1000*time.Millisecond)),
			grpc_retry.WithCodes(getRetryCodes()...)),
		streamClientInterceptor(),
	}
}
