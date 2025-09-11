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

	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func NotFoundOrInternal(err error, format string, a ...any) error {
	if grpcerr.IsNotFound(err) {
		return status.Errorf(codes.NotFound, format, a...)
	}

	zap.L().Warn("Internal error", zap.Error(err))
	return K8sInternal(err)
}

func K8sInternal(err error) error {
	zap.L().Warn("Internal error", zap.Error(err))
	if ldflags.IsDev() {
		return status.Errorf(codes.Internal, "internal error.: %+v", err)
	}
	return status.Errorf(codes.Internal, "Internal error")
}

func InvalidArg(format string, a ...any) error {
	return status.Errorf(codes.InvalidArgument, format, a...)
}

func InvalidArgWithErr(err error) error {
	zap.L().Debug("Invalid error", zap.Error(err))
	return status.Errorf(codes.InvalidArgument, "%s", err.Error())
}

func NotFound(format string, a ...any) error {
	return status.Errorf(codes.NotFound, format, a...)
}

func Internal(format string, a ...any) error {
	zap.L().Warn("Internal error", zap.Error(errors.Errorf(format, a...)))
	return status.Errorf(codes.Internal, "Internal error")
}

func InternalWithErr(err error) error {
	zap.L().Warn("Internal error", zap.Error(err))
	return status.Errorf(codes.Internal, "Internal error")
}

func K8sNotFoundOrInternal(err error, format string, a ...any) error {
	if grpcerr.IsNotFound(err) {
		return status.Errorf(codes.NotFound, format, a...)
	}
	zap.L().Warn("Internal error", zap.Error(err))
	return K8sInternal(err)
}

func K8sNotFoundOrInternalWithErr(err error) error {
	if grpcerr.IsNotFound(err) {
		return err
	}

	zap.L().Warn("Internal error", zap.Error(err))
	return K8sInternal(err)
}

func Unauthorized(format string, a ...any) error {
	zap.L().Debug("Unauthorized error", zap.Error(errors.Errorf(format, a...)))
	return status.Errorf(codes.PermissionDenied, format, a...)
}

func PermissionDenied(format string, a ...any) error {
	zap.L().Debug("permissionDenied error", zap.Error(errors.Errorf(format, a...)))
	return status.Errorf(codes.PermissionDenied, format, a...)
}

func Unauthenticated(format string, a ...any) error {
	zap.L().Debug("Unauthenticated error", zap.Error(errors.Errorf(format, a...)))
	return status.Errorf(codes.Unauthenticated, "Unauthenticated User")
}

func UnauthenticatedWithErr(err error) error {
	zap.L().Debug("Unauthenticated error", zap.Error(err))
	return status.Errorf(codes.Unauthenticated, "Unauthenticated User")
}

func AlreadyExists(format string, a ...any) error {
	zap.L().Debug("InternalAlreadyExists error", zap.Error(errors.Errorf(format, a...)))
	return status.Errorf(codes.AlreadyExists, format, a...)
}

func GetHeaderValue(ctx context.Context, key string) (string, error) {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.Errorf("Could not find metadata from context")
	}

	if hdrVal := md.Get(key); len(hdrVal) > 0 {
		return hdrVal[0], nil
	}

	return "", errors.Errorf("Could not find header: %s", key)
}

func GetHeaderValueMust(ctx context.Context, key string) string {
	ret, _ := GetHeaderValue(ctx, key)
	return ret
}

func GetHeaderValueAll(ctx context.Context, key string) []string {

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}

	return md.Get(key)
}
