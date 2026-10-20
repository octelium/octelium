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
	"sync/atomic"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rpubsubv1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pubSubMaxTopicLen    = 256
	pubSubMaxGroupLen    = 128
	pubSubMaxIDLen       = 41
	pubSubMaxMessages    = 100
	pubSubMaxAckIDs      = 1000
	pubSubMaxMessageSize = 16 * 1024

	pubSubDefaultMaxLength = 1000
	pubSubMaxMaxLength     = 10000

	pubSubDefaultMaxAge = 1 * time.Hour
	pubSubMinMaxAge     = 1 * time.Second
	pubSubMaxMaxAge     = 24 * time.Hour

	pubSubDefaultAckTimeout = 1 * time.Minute
	pubSubMinAckTimeout     = 1 * time.Second
	pubSubMaxAckTimeout     = 1 * time.Hour

	pubSubMaxSubscriptions = 128
	pubSubReadCount        = 100
	pubSubReadBlock        = 5 * time.Second
	pubSubMaxClaimRounds   = 10

	pubSubMaintainInterval    = 30 * time.Second
	pubSubSubscriptionTTL     = 10 * time.Minute
	pubSubConsumerIdleTimeout = 1 * time.Hour
	pubSubCleanupTimeout      = 5 * time.Second

	pubSubFieldData = "d"
)

var scriptPubSubTouch = redis.NewScript(`
if ARGV[2] == "1" and redis.call("exists", KEYS[1]) == 0 then
	redis.call("xadd", KEYS[1], "MAXLEN", "0", "*", ARGV[3], "")
end
local ttl = redis.call("pttl", KEYS[1])
if ttl == -2 then
	return 0
end
if ttl < tonumber(ARGV[1]) then
	redis.call("pexpire", KEYS[1], ARGV[1])
end
return 1
`)

var errPubSubTooManySubscriptions = status.Error(codes.ResourceExhausted,
	"Too many PubSub subscriptions")

type srvPubSub struct {
	redisC *redis.Client
	blockC *redis.Client

	subscriptions atomic.Int64

	rpubsubv1.UnimplementedMainServiceServer
}

func newSrvPubSub(redisC *redis.Client) *srvPubSub {
	opts := redisutils.NewOptions()
	opts.PoolSize = pubSubMaxSubscriptions + 8

	return &srvPubSub{
		redisC: redisC,
		blockC: redis.NewClient(opts),
	}
}

func (s *srvPubSub) close() {
	if s.blockC != nil {
		s.blockC.Close()
	}
}

func (s *srvPubSub) getTopicKey(topic []byte) string {
	return fmt.Sprintf("octelium:pubsub:%s", vutils.Sha256SumHex(topic))
}

func (s *srvPubSub) validateTopic(topic []byte) error {
	if len(topic) == 0 {
		return grpcutils.InvalidArg("Empty topic is not allowed")
	}
	if len(topic) > pubSubMaxTopicLen {
		return grpcutils.InvalidArg("The topic is too long")
	}
	return nil
}

func (s *srvPubSub) validateGroup(group []byte) error {
	if len(group) == 0 {
		return grpcutils.InvalidArg("Empty group is not allowed")
	}
	if len(group) > pubSubMaxGroupLen {
		return grpcutils.InvalidArg("The group is too long")
	}
	return nil
}

func (s *srvPubSub) validateID(id []byte) error {
	if len(id) == 0 || len(id) > pubSubMaxIDLen {
		return grpcutils.InvalidArg("Invalid ID")
	}
	if _, _, err := parseStreamID(string(id)); err != nil {
		return grpcutils.InvalidArg("Invalid ID")
	}
	return nil
}

func (s *srvPubSub) getMaxLength(maxLength uint32) (int64, error) {
	switch {
	case maxLength == 0:
		return pubSubDefaultMaxLength, nil
	case maxLength > pubSubMaxMaxLength:
		return 0, grpcutils.InvalidArg("The maxLength cannot exceed %d", pubSubMaxMaxLength)
	default:
		return int64(maxLength), nil
	}
}

func (s *srvPubSub) getDuration(arg *metav1.Duration, def, minVal, maxVal time.Duration, name string) (time.Duration, error) {
	if arg == nil {
		return def, nil
	}

	ret := umetav1.ToDuration(arg).ToGo()
	switch {
	case ret == 0:
		return def, nil
	case ret < minVal:
		return 0, grpcutils.InvalidArg("The %s cannot be less than %s", name, minVal)
	case ret > maxVal:
		return 0, grpcutils.InvalidArg("The %s cannot exceed %s", name, maxVal)
	default:
		return ret, nil
	}
}

func (s *srvPubSub) toGRPCErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return status.FromContextError(ctxErr).Err()
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}

	zap.L().Warn("pubsub redis err", zap.Error(err))

	return status.Error(codes.Unavailable, "Could not reach the PubSub backend")
}

func (s *srvPubSub) touchTopic(ctx context.Context, key string, ttl time.Duration, create bool) error {
	createArg := "0"
	if create {
		createArg = "1"
	}

	return scriptPubSubTouch.Run(ctx, s.redisC, []string{key},
		ttl.Milliseconds(), createArg, pubSubFieldData).Err()
}

func (s *srvPubSub) Publish(ctx context.Context, req *rpubsubv1.PublishRequest) (*rpubsubv1.PublishResponse, error) {
	if err := s.validateTopic(req.Topic); err != nil {
		return nil, err
	}

	if len(req.Messages) == 0 {
		return nil, grpcutils.InvalidArg("No messages")
	}
	if len(req.Messages) > pubSubMaxMessages {
		return nil, grpcutils.InvalidArg("Too many messages")
	}

	maxLength, err := s.getMaxLength(req.MaxLength)
	if err != nil {
		return nil, err
	}

	maxAge, err := s.getDuration(req.MaxAge,
		pubSubDefaultMaxAge, pubSubMinMaxAge, pubSubMaxMaxAge, "maxAge")
	if err != nil {
		return nil, err
	}

	now := time.Now()
	createdAt := pbutils.Timestamp(now)

	var payloads []string
	for _, msg := range req.Messages {
		if msg == nil || msg.Type == nil {
			return nil, grpcutils.InvalidArg("Empty message")
		}

		data, err := pbutils.Marshal(&rpubsubv1.Message{
			CreatedAt: createdAt,
			Type:      msg.Type,
		})
		if err != nil {
			return nil, grpcutils.InvalidArg("Invalid message")
		}

		if len(data) > pubSubMaxMessageSize {
			return nil, grpcutils.InvalidArg("The message is too large")
		}

		payloads = append(payloads, string(data))
	}

	key := s.getTopicKey(req.Topic)

	pipe := s.redisC.Pipeline()
	var cmds []*redis.StringCmd
	for _, payload := range payloads {
		cmds = append(cmds, pipe.XAdd(ctx, &redis.XAddArgs{
			Stream:     key,
			NoMkStream: req.IfExists,
			MaxLen:     maxLength,
			Approx:     true,
			Values: map[string]any{
				pubSubFieldData: payload,
			},
		}))
	}

	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, s.toGRPCErr(ctx, err)
	}

	ret := &rpubsubv1.PublishResponse{}
	for _, cmd := range cmds {
		id, err := cmd.Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			return nil, s.toGRPCErr(ctx, err)
		}

		ret.Ids = append(ret.Ids, []byte(id))
	}

	if len(ret.Ids) == 0 {
		return ret, nil
	}

	minID := fmt.Sprintf("%d-0", now.Add(-maxAge).UnixMilli())
	if err := s.redisC.XTrimMinIDApprox(ctx, key, minID, 0).Err(); err != nil {
		return nil, s.toGRPCErr(ctx, err)
	}

	if err := s.touchTopic(ctx, key, maxAge, false); err != nil {
		return nil, s.toGRPCErr(ctx, err)
	}

	return ret, nil
}

func (s *srvPubSub) Acknowledge(ctx context.Context, req *rpubsubv1.AcknowledgeRequest) (*rpubsubv1.AcknowledgeResponse, error) {
	if err := s.validateTopic(req.Topic); err != nil {
		return nil, err
	}

	if err := s.validateGroup(req.Group); err != nil {
		return nil, err
	}

	if len(req.Ids) == 0 {
		return &rpubsubv1.AcknowledgeResponse{}, nil
	}
	if len(req.Ids) > pubSubMaxAckIDs {
		return nil, grpcutils.InvalidArg("Too many IDs")
	}

	var ids []string
	for _, id := range req.Ids {
		if err := s.validateID(id); err != nil {
			return nil, err
		}
		ids = append(ids, string(id))
	}

	count, err := s.redisC.XAck(ctx, s.getTopicKey(req.Topic), string(req.Group), ids...).Result()
	if err != nil {
		if isPubSubNoGroupErr(err) {
			return &rpubsubv1.AcknowledgeResponse{}, nil
		}
		return nil, s.toGRPCErr(ctx, err)
	}

	return &rpubsubv1.AcknowledgeResponse{
		Count: uint32(count),
	}, nil
}

func (s *srvPubSub) Subscribe(req *rpubsubv1.SubscribeRequest, stream rpubsubv1.MainService_SubscribeServer) error {
	if err := s.validateTopic(req.Topic); err != nil {
		return err
	}

	if len(req.Group) > 0 {
		if err := s.validateGroup(req.Group); err != nil {
			return err
		}
		if len(req.AfterID) > 0 {
			return grpcutils.InvalidArg("The afterID cannot be used with a group")
		}
	}

	if len(req.AfterID) > 0 {
		if err := s.validateID(req.AfterID); err != nil {
			return err
		}
	}

	ackTimeout, err := s.getDuration(req.AckTimeout,
		pubSubDefaultAckTimeout, pubSubMinAckTimeout, pubSubMaxAckTimeout, "ackTimeout")
	if err != nil {
		return err
	}

	if s.subscriptions.Add(1) > pubSubMaxSubscriptions {
		s.subscriptions.Add(-1)
		return errPubSubTooManySubscriptions
	}
	defer s.subscriptions.Add(-1)

	if len(req.Group) > 0 {
		return s.doSubscribeGroup(stream.Context(), req, ackTimeout, stream)
	}

	return s.doSubscribe(stream.Context(), req, stream)
}

func (s *srvPubSub) getStartID(ctx context.Context, key string, req *rpubsubv1.SubscribeRequest) (string, error) {
	switch {
	case len(req.AfterID) > 0:
		return string(req.AfterID), nil
	case req.Position == rpubsubv1.SubscribeRequest_EARLIEST:
		return streamIDZero, nil
	}

	res, err := s.redisC.XRevRangeN(ctx, key, "+", "-", 1).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return streamIDZero, nil
		}
		return "", err
	}

	if len(res) == 0 {
		return streamIDZero, nil
	}

	return res[0].ID, nil
}

func (s *srvPubSub) doSubscribe(ctx context.Context,
	req *rpubsubv1.SubscribeRequest, stream rpubsubv1.MainService_SubscribeServer) error {
	key := s.getTopicKey(req.Topic)

	if err := s.touchTopic(ctx, key, pubSubSubscriptionTTL, true); err != nil {
		return s.toGRPCErr(ctx, err)
	}

	cursor, err := s.getStartID(ctx, key, req)
	if err != nil {
		return s.toGRPCErr(ctx, err)
	}

	if err := stream.Send(&rpubsubv1.SubscribeResponse{}); err != nil {
		return err
	}

	lastMaintainedAt := time.Now()

	for {
		if ctx.Err() != nil {
			return nil
		}

		if time.Since(lastMaintainedAt) >= pubSubMaintainInterval {
			if err := s.touchTopic(ctx, key, pubSubSubscriptionTTL, true); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return s.toGRPCErr(ctx, err)
			}
			lastMaintainedAt = time.Now()
		}

		res, err := s.blockC.XRead(ctx, &redis.XReadArgs{
			Streams: []string{key, cursor},
			Count:   pubSubReadCount,
			Block:   pubSubReadBlock,
		}).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return s.toGRPCErr(ctx, err)
		}

		var msgs []*rpubsubv1.Message
		for _, res := range res {
			for _, itm := range res.Messages {
				cursor = itm.ID

				msg, err := s.decodeMessage(itm)
				if err != nil {
					zap.L().Debug("Skipping an invalid PubSub message",
						zap.String("id", itm.ID), zap.Error(err))
					continue
				}

				msgs = append(msgs, msg)
			}
		}

		if len(msgs) == 0 {
			continue
		}

		if err := stream.Send(&rpubsubv1.SubscribeResponse{
			Messages: msgs,
		}); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func (s *srvPubSub) ensureGroup(ctx context.Context, key string, group string, position rpubsubv1.SubscribeRequest_Position) error {
	start := "$"
	if position == rpubsubv1.SubscribeRequest_EARLIEST {
		start = streamIDZero
	}

	if err := s.redisC.XGroupCreateMkStream(ctx, key, group, start).Err(); err != nil &&
		!strings.HasPrefix(err.Error(), "BUSYGROUP") {
		return err
	}

	return s.touchTopic(ctx, key, pubSubSubscriptionTTL, false)
}

func (s *srvPubSub) doSubscribeGroup(ctx context.Context,
	req *rpubsubv1.SubscribeRequest, ackTimeout time.Duration,
	stream rpubsubv1.MainService_SubscribeServer) error {
	key := s.getTopicKey(req.Topic)
	group := string(req.Group)
	consumer := utilrand.GetRandomStringCanonical(16)

	if err := s.ensureGroup(ctx, key, group, req.Position); err != nil {
		return s.toGRPCErr(ctx, err)
	}

	defer s.cleanupConsumer(key, group, consumer)

	if err := stream.Send(&rpubsubv1.SubscribeResponse{}); err != nil {
		return err
	}

	var lastMaintainedAt time.Time

	for {
		if ctx.Err() != nil {
			return nil
		}

		if time.Since(lastMaintainedAt) >= pubSubMaintainInterval {
			if err := s.maintainGroup(ctx, key, group, consumer, ackTimeout, stream); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if isPubSubNoGroupErr(err) {
					if err := s.ensureGroup(ctx, key, group, rpubsubv1.SubscribeRequest_EARLIEST); err != nil {
						return s.toGRPCErr(ctx, err)
					}
					continue
				}
				if _, ok := status.FromError(err); ok {
					return err
				}
				return s.toGRPCErr(ctx, err)
			}
			lastMaintainedAt = time.Now()
		}

		res, err := s.blockC.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    group,
			Consumer: consumer,
			Streams:  []string{key, ">"},
			Count:    pubSubReadCount,
			Block:    pubSubReadBlock,
		}).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			if isPubSubNoGroupErr(err) {
				if err := s.ensureGroup(ctx, key, group, rpubsubv1.SubscribeRequest_EARLIEST); err != nil {
					return s.toGRPCErr(ctx, err)
				}
				continue
			}
			return s.toGRPCErr(ctx, err)
		}

		var itms []redis.XMessage
		for _, res := range res {
			itms = append(itms, res.Messages...)
		}

		if err := s.sendGroupMessages(ctx, key, group, itms, stream); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
}

func (s *srvPubSub) maintainGroup(ctx context.Context, key, group, consumer string,
	ackTimeout time.Duration, stream rpubsubv1.MainService_SubscribeServer) error {
	if err := s.touchTopic(ctx, key, pubSubSubscriptionTTL, false); err != nil {
		return err
	}

	start := streamIDZero
	for range pubSubMaxClaimRounds {
		itms, next, err := s.redisC.XAutoClaim(ctx, &redis.XAutoClaimArgs{
			Stream:   key,
			Group:    group,
			Consumer: consumer,
			MinIdle:  ackTimeout,
			Start:    start,
			Count:    pubSubReadCount,
		}).Result()
		if err != nil {
			return err
		}

		if err := s.sendGroupMessages(ctx, key, group, itms, stream); err != nil {
			return err
		}

		if next == "" || next == streamIDZero {
			break
		}
		start = next
	}

	consumers, err := s.redisC.XInfoConsumers(ctx, key, group).Result()
	if err != nil {
		return err
	}

	for _, itm := range consumers {
		if itm.Name == consumer || itm.Pending > 0 || itm.Idle < pubSubConsumerIdleTimeout {
			continue
		}

		if err := s.redisC.XGroupDelConsumer(ctx, key, group, itm.Name).Err(); err != nil {
			return err
		}
	}

	return nil
}

func (s *srvPubSub) sendGroupMessages(ctx context.Context, key, group string,
	itms []redis.XMessage, stream rpubsubv1.MainService_SubscribeServer) error {
	if len(itms) == 0 {
		return nil
	}

	var msgs []*rpubsubv1.Message
	var invalidIDs []string

	for _, itm := range itms {
		msg, err := s.decodeMessage(itm)
		if err != nil {
			zap.L().Debug("Dropping an invalid PubSub message",
				zap.String("id", itm.ID), zap.Error(err))
			invalidIDs = append(invalidIDs, itm.ID)
			continue
		}

		msgs = append(msgs, msg)
	}

	if len(invalidIDs) > 0 {
		if err := s.redisC.XAck(ctx, key, group, invalidIDs...).Err(); err != nil {
			return s.toGRPCErr(ctx, err)
		}
	}

	if len(msgs) == 0 {
		return nil
	}

	return stream.Send(&rpubsubv1.SubscribeResponse{
		Messages: msgs,
	})
}

func (s *srvPubSub) cleanupConsumer(key, group, consumer string) {
	ctx, cancel := context.WithTimeout(context.Background(), pubSubCleanupTimeout)
	defer cancel()

	pending, err := s.redisC.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream:   key,
		Group:    group,
		Start:    "-",
		End:      "+",
		Count:    1,
		Consumer: consumer,
	}).Result()
	if err != nil {
		zap.L().Debug("Could not get the pending messages of the PubSub consumer", zap.Error(err))
		return
	}

	if len(pending) > 0 {
		return
	}

	if err := s.redisC.XGroupDelConsumer(ctx, key, group, consumer).Err(); err != nil {
		zap.L().Debug("Could not delete the PubSub consumer", zap.Error(err))
	}
}

func (s *srvPubSub) decodeMessage(itm redis.XMessage) (*rpubsubv1.Message, error) {
	dataI, ok := itm.Values[pubSubFieldData]
	if !ok {
		return nil, errors.Errorf("The message has no data field")
	}

	data, ok := dataI.(string)
	if !ok {
		return nil, errors.Errorf("The message data field is not a string")
	}

	ret := &rpubsubv1.Message{}
	if err := pbutils.Unmarshal([]byte(data), ret); err != nil {
		return nil, err
	}

	if ret.Type == nil {
		return nil, errors.Errorf("The message is empty")
	}

	ret.Id = []byte(itm.ID)

	return ret, nil
}

func isPubSubNoGroupErr(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "NOGROUP")
}
