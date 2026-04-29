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

	"github.com/go-redis/redis/v8"
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

	_, err = s.redisC.XAdd(ctx, &redis.XAddArgs{
		Stream: getRedisRscChannel(api, version, kind),
		MaxLen: 2000,
		Approx: true,
		Values: map[string]any{
			"payload": string(data),
		},
	}).Result()

	if err != nil {
		return err
	}

	return nil
}
