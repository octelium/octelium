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

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
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

func (s *Server) publishWatchEvent(ctx context.Context, api, version, kind string, msg proto.Message) error {
	if err := s.publishMessage(ctx, api, version, kind, msg); err != nil {
		if s.eventHub != nil {
			zap.L().Warn("Could not publish the Watch event. Closing all the stream subscribers to force resync",
				zap.String("api", api), zap.String("version", version), zap.String("kind", kind), zap.Error(err))
			s.eventHub.closeStream(getRscStreamKey(api, version, kind))
		}
		return err
	}

	return nil
}

func (s *Server) publishMessage(ctx context.Context, api, version, kind string, msg proto.Message) error {

	data, err := pbutils.Marshal(msg)
	if err != nil {
		return err
	}

	if err := s.redisC.XAdd(ctx, &redis.XAddArgs{
		Stream: getRscStreamKey(api, version, kind),
		MaxLen: rscStreamMaxLen,
		Approx: true,
		Values: map[string]any{
			rscStreamFieldData: string(data),
		},
	}).Err(); err != nil {
		return err
	}

	return nil
}

func (s *Server) getWatchEventItem(obj umetav1.ResourceObjectI, kind string) *anypb.Any {
	if s.isTypeSecret(kind) {
		obj = withoutSecretData(obj)
	}

	return pbutils.MessageToAnyMust(obj)
}

func withoutSecretData(obj umetav1.ResourceObjectI) umetav1.ResourceObjectI {
	fd := obj.ProtoReflect().Descriptor().Fields().ByName("data")
	if fd == nil || !obj.ProtoReflect().Has(fd) {
		return obj
	}

	ret := pbutils.Clone(obj).(umetav1.ResourceObjectI)
	ret.ProtoReflect().Clear(fd)

	return ret
}

func (s *Server) getSecretWatchEvent(ctx context.Context,
	ev *rmetav1.WatchEvent, api, version, kind string) (*rmetav1.WatchEvent, error) {

	var item *anypb.Any

	switch {
	case ev.Event.GetCreate() != nil:
		item = ev.Event.GetCreate().Item
	case ev.Event.GetUpdate() != nil:
		item = ev.Event.GetUpdate().NewItem
	default:
		return ev, nil
	}

	obj, err := s.opts.NewResourceObject(api, version, kind)
	if err != nil {
		return nil, err
	}

	if err := pbutils.AnyToMessage(item, obj); err != nil {
		return nil, err
	}

	cur, err := s.doGet(ctx, &rmetav1.GetOptions{
		Uid: obj.GetMetadata().GetUid(),
	}, api, version, kind)
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	ret := pbutils.Clone(ev).(*rmetav1.WatchEvent)

	if ret.Event.GetUpdate() != nil {
		ret.Event.GetUpdate().NewItem = pbutils.MessageToAnyMust(cur)
	} else {
		ret.Event.GetCreate().Item = pbutils.MessageToAnyMust(cur)
	}

	return ret, nil
}
