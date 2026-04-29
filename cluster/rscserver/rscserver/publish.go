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
	"fmt"

	"github.com/octelium/octelium/pkg/common/pbutils"
	"google.golang.org/protobuf/proto"
)

func getRedisRscChannel(api, version, kind string) string {
	return fmt.Sprintf("octelium.rsc.%s.%s.%s", api, version, kind)
}

func (s *Server) publishMessage(ctx context.Context, api, version, kind string, msg proto.Message) error {

	data, err := pbutils.Marshal(msg)
	if err != nil {
		return err
	}

	if _, err := s.redisC.Publish(ctx, getRedisRscChannel(api, version, kind), string(data)).Result(); err != nil {
		return err
	}

	return nil
}
