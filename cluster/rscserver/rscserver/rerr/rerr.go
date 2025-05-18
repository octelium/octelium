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
	zap.S().Errorf("internal error.: %v", errors.Errorf(format, a...))
	return status.Errorf(codes.Internal, format, a...)
}

func InternalWithErr(err error) error {
	zap.S().Errorf("internal error.: %+v", err)
	return status.Errorf(codes.Internal, err.Error())
}

func InvalidWithErr(err error) error {
	zap.S().Errorf("Invalid error.: %+v", err)
	return status.Errorf(codes.InvalidArgument, err.Error())
}

func AlreadyExistsWithErr(err error) error {
	zap.S().Errorf("already exists error.: %+v", err)
	return status.Errorf(codes.AlreadyExists, err.Error())
}

func ResourceChanged(err error) error {
	zap.S().Warn("Resource changed: %+v", err)
	return status.Errorf(codes.FailedPrecondition, err.Error())
}
