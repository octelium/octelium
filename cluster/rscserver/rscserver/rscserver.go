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

package rscserver

import (
	"context"

	"github.com/octelium/octelium/cluster/common/commoninit"
	"go.uber.org/zap"
)

func Run(ctx context.Context) error {

	zap.L().Debug("Starting Resource server")

	if err := commoninit.Run(ctx, nil); err != nil {
		return err
	}

	srv, err := NewServer(ctx, nil)
	if err != nil {
		return err
	}

	zap.L().Debug("starting gRPC server...")

	if err := srv.Run(ctx); err != nil {
		return err
	}
	zap.L().Info("Resource Server is now running...")

	<-ctx.Done()

	return nil
}
