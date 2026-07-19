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
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
)

const (
	rscStreamMaxLen = 10000

	rscStreamPrefix    = "octelium:rsc:stream:"
	rscStreamFieldData = "d"
)

func getRscStreamKey(api, version, kind string) string {
	return fmt.Sprintf("%s%s:%s:%s", rscStreamPrefix, api, version, kind)
}

func parseRscStreamKey(streamKey string) (string, string, string, error) {
	rest, found := strings.CutPrefix(streamKey, rscStreamPrefix)
	if !found {
		return "", "", "", errors.Errorf("Invalid stream key: %s", streamKey)
	}

	args := strings.Split(rest, ":")
	if len(args) != 3 {
		return "", "", "", errors.Errorf("Invalid stream key: %s", streamKey)
	}

	for _, arg := range args {
		if arg == "" {
			return "", "", "", errors.Errorf("Invalid stream key: %s", streamKey)
		}
	}

	return args[0], args[1], args[2], nil
}

func (s *Server) publishMessage(ctx context.Context, api, version, kind string, msg proto.Message) error {

	data, err := pbutils.Marshal(msg)
	if err != nil {
		return err
	}

	if err := s.redisC.XAdd(ctx, &redis.XAddArgs{
		Stream:       getRscStreamKey(api, version, kind),
		MaxLenApprox: rscStreamMaxLen,
		Values: map[string]any{
			rscStreamFieldData: string(data),
		},
	}).Err(); err != nil {
		return err
	}

	return nil
}
