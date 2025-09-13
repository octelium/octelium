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

package rerr

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func NotFound(format string, a ...any) error {
	return status.Errorf(codes.NotFound, format, a...)
}

func Internal(format string, a ...any) error {
	zap.L().Warn("internal error", zap.Error(errors.Errorf(format, a...)))
	return status.Errorf(codes.Internal, format, a...)
}

func InternalWithErr(err error) error {
	zap.L().Warn("internal error", zap.Error(err))
	return status.Errorf(codes.Internal, "%s", err.Error())
}

func InvalidWithErr(err error) error {
	zap.L().Debug("Invalid arg", zap.Error(err))
	return status.Errorf(codes.InvalidArgument, "%s", err.Error())
}

func AlreadyExistsWithErr(err error) error {
	zap.L().Debug("Already exists", zap.Error(err))
	return status.Errorf(codes.AlreadyExists, "%s", err.Error())
}

func ResourceChanged(err error) error {
	zap.L().Debug("Resource changed", zap.Error(err))
	return status.Error(codes.OutOfRange, err.Error())
}
