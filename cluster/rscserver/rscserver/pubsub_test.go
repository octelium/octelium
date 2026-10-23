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
	"io"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/rsc/rpubsubv1"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type fakePubSubStream struct {
	grpc.ServerStream
	ctx context.Context
	ch  chan *rpubsubv1.SubscribeResponse
}

func (s *fakePubSubStream) Context() context.Context {
	return s.ctx
}

func (s *fakePubSubStream) Send(resp *rpubsubv1.SubscribeResponse) error {
	select {
	case s.ch <- resp:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

type testPubSubSubscription struct {
	stream *fakePubSubStream
	cancel context.CancelFunc
	errCh  chan error
}

func startTestPubSubSubscription(t *testing.T, srv *srvPubSub, req *rpubsubv1.SubscribeRequest) *testPubSubSubscription {
	ctx, cancel := context.WithCancel(context.Background())

	ret := &testPubSubSubscription{
		stream: &fakePubSubStream{
			ctx: ctx,
			ch:  make(chan *rpubsubv1.SubscribeResponse, 100),
		},
		cancel: cancel,
		errCh:  make(chan error, 1),
	}

	go func() {
		ret.errCh <- srv.Subscribe(req, ret.stream)
	}()

	select {
	case resp := <-ret.stream.ch:
		assert.Equal(t, 0, len(resp.Messages))
	case err := <-ret.errCh:
		t.Fatalf("The subscription exited: %+v", err)
	case <-time.After(10 * time.Second):
		t.Fatalf("Timed out while waiting for the subscription to start")
	}

	return ret
}

func (s *testPubSubSubscription) stop() error {
	s.cancel()

	select {
	case err := <-s.errCh:
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("Timed out while waiting for the subscription to exit")
	}
}

func (s *testPubSubSubscription) receive(n int, d time.Duration) []*rpubsubv1.Message {
	var ret []*rpubsubv1.Message

	timer := time.NewTimer(d)
	defer timer.Stop()

	for len(ret) < n {
		select {
		case resp := <-s.stream.ch:
			ret = append(ret, resp.Messages...)
		case <-timer.C:
			return ret
		}
	}

	return ret
}

func newTestPubSubTopic() []byte {
	return []byte(fmt.Sprintf("test.%s", utilrand.GetRandomStringCanonical(12)))
}

func newTestPubSubDataMessage(data string) *rpubsubv1.Message {
	return &rpubsubv1.Message{
		Type: &rpubsubv1.Message_Data{
			Data: []byte(data),
		},
	}
}

func getTestPubSubData(msgs []*rpubsubv1.Message) []string {
	var ret []string
	for _, msg := range msgs {
		ret = append(ret, string(msg.GetData()))
	}
	return ret
}

func getTestPubSubIDs(msgs []*rpubsubv1.Message) [][]byte {
	var ret [][]byte
	for _, msg := range msgs {
		ret = append(ret, msg.Id)
	}
	return ret
}

func TestPubSubValidation(t *testing.T) {
	ctx := context.Background()
	srv := newSrvPubSub(redisutils.NewClient())
	defer srv.close()

	topic := newTestPubSubTopic()

	{
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("a")},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    []byte(utilrand.GetRandomString(pubSubMaxTopicLen + 1)),
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("a")},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic: topic,
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		var msgs []*rpubsubv1.Message
		for range pubSubMaxMessages + 1 {
			msgs = append(msgs, newTestPubSubDataMessage("a"))
		}
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: msgs,
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{{}},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic: topic,
			Messages: []*rpubsubv1.Message{
				newTestPubSubDataMessage(utilrand.GetRandomString(pubSubMaxMessageSize + 1)),
			},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:     topic,
			Messages:  []*rpubsubv1.Message{newTestPubSubDataMessage("a")},
			MaxLength: pubSubMaxMaxLength + 1,
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("a")},
			MaxAge:   durMinutes(25 * 60),
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("a")},
			MaxAge:   durMilliseconds(100),
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		err := srv.Subscribe(&rpubsubv1.SubscribeRequest{}, &fakePubSubStream{
			ctx: ctx,
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		err := srv.Subscribe(&rpubsubv1.SubscribeRequest{
			Topic:   topic,
			Group:   []byte("grp"),
			AfterID: []byte("1-0"),
		}, &fakePubSubStream{
			ctx: ctx,
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		err := srv.Subscribe(&rpubsubv1.SubscribeRequest{
			Topic:   topic,
			AfterID: []byte("invalid"),
		}, &fakePubSubStream{
			ctx: ctx,
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		err := srv.Subscribe(&rpubsubv1.SubscribeRequest{
			Topic:      topic,
			Group:      []byte("grp"),
			AckTimeout: durMinutes(61),
		}, &fakePubSubStream{
			ctx: ctx,
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		err := srv.Subscribe(&rpubsubv1.SubscribeRequest{
			Topic: topic,
			Group: []byte(utilrand.GetRandomString(pubSubMaxGroupLen + 1)),
		}, &fakePubSubStream{
			ctx: ctx,
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{
			Topic: topic,
			Ids:   [][]byte{[]byte("1-0")},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{
			Topic: topic,
			Group: []byte("grp"),
			Ids:   [][]byte{[]byte("invalid")},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		res, err := srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{
			Topic: topic,
			Group: []byte("grp"),
			Ids:   [][]byte{[]byte("1-0")},
		})
		assert.Nil(t, err)
		assert.Equal(t, uint32(0), res.Count)
	}
	{
		srv.subscriptions.Store(pubSubMaxSubscriptions)
		err := srv.Subscribe(&rpubsubv1.SubscribeRequest{
			Topic: topic,
		}, &fakePubSubStream{
			ctx: ctx,
		})
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.Equal(t, int64(pubSubMaxSubscriptions), srv.subscriptions.Load())
		srv.subscriptions.Store(0)
	}
}

func TestPubSubPublish(t *testing.T) {
	ctx := context.Background()
	srv := newSrvPubSub(redisutils.NewClient())
	defer srv.close()

	{
		topic := newTestPubSubTopic()
		key := srv.getTopicKey(topic)

		res, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("a")},
			IfExists: true,
		})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(res.Ids))

		exists, err := srv.redisC.Exists(ctx, key).Result()
		assert.Nil(t, err)
		assert.Equal(t, int64(0), exists)

		res, err = srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic: topic,
			Messages: []*rpubsubv1.Message{
				newTestPubSubDataMessage("a"),
				newTestPubSubDataMessage("b"),
			},
			MaxAge: durMinutes(5),
		})
		assert.Nil(t, err)
		assert.Equal(t, 2, len(res.Ids))
		assert.True(t, compareStreamIDs(string(res.Ids[1]), string(res.Ids[0])) > 0)

		ttl, err := srv.redisC.PTTL(ctx, key).Result()
		assert.Nil(t, err)
		assert.True(t, ttl > 4*time.Minute && ttl <= 5*time.Minute, ttl)

		res, err = srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("c")},
			IfExists: true,
			MaxAge:   durMinutes(1),
		})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(res.Ids))

		ttl, err = srv.redisC.PTTL(ctx, key).Result()
		assert.Nil(t, err)
		assert.True(t, ttl > 4*time.Minute, ttl)

		length, err := srv.redisC.XLen(ctx, key).Result()
		assert.Nil(t, err)
		assert.Equal(t, int64(3), length)
	}

	{
		topic := newTestPubSubTopic()
		key := srv.getTopicKey(topic)

		for i := range 20 {
			_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
				Topic:     topic,
				Messages:  []*rpubsubv1.Message{newTestPubSubDataMessage(fmt.Sprintf("%d", i))},
				MaxLength: 5,
			})
			assert.Nil(t, err)
		}

		length, err := srv.redisC.XLen(ctx, key).Result()
		assert.Nil(t, err)
		assert.Equal(t, int64(5), length)

		sub := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
			Topic:    topic,
			Position: rpubsubv1.SubscribeRequest_EARLIEST,
		})

		msgs := sub.receive(5, 5*time.Second)
		assert.Equal(t, []string{"15", "16", "17", "18", "19"}, getTestPubSubData(msgs))
		assert.Nil(t, sub.stop())
	}

	{
		topic := newTestPubSubTopic()
		key := srv.getTopicKey(topic)

		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("old")},
			MaxAge:   durSeconds(1),
		})
		assert.Nil(t, err)

		time.Sleep(1500 * time.Millisecond)

		_, err = srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("new")},
			MaxAge:   durSeconds(1),
		})
		assert.Nil(t, err)

		res, err := srv.redisC.XRange(ctx, key, "-", "+").Result()
		assert.Nil(t, err)
		assert.Equal(t, 1, len(res))
	}
}

func TestPubSubSubscribe(t *testing.T) {
	ctx := context.Background()
	srv := newSrvPubSub(redisutils.NewClient())
	defer srv.close()

	topic := newTestPubSubTopic()

	{
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("before")},
		})
		assert.Nil(t, err)
	}

	latest := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
		Topic: topic,
	})

	content, err := structpb.NewStruct(map[string]any{
		"key": "value",
	})
	assert.Nil(t, err)

	res, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
		Topic: topic,
		Messages: []*rpubsubv1.Message{
			newTestPubSubDataMessage("a"),
			{
				Type: &rpubsubv1.Message_Content{
					Content: content,
				},
			},
			newTestPubSubDataMessage("b"),
		},
		IfExists: true,
	})
	assert.Nil(t, err)
	assert.Equal(t, 3, len(res.Ids))

	msgs := latest.receive(3, 10*time.Second)
	assert.Equal(t, 3, len(msgs))
	assert.Equal(t, res.Ids, getTestPubSubIDs(msgs))
	assert.Equal(t, "a", string(msgs[0].GetData()))
	assert.Equal(t, "value", msgs[1].GetContent().AsMap()["key"])
	assert.Equal(t, "b", string(msgs[2].GetData()))
	for _, msg := range msgs {
		assert.True(t, msg.CreatedAt.IsValid())
		assert.True(t, time.Since(msg.CreatedAt.AsTime()) < time.Minute)
	}

	assert.Nil(t, latest.stop())

	earliest := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
		Topic:    topic,
		Position: rpubsubv1.SubscribeRequest_EARLIEST,
	})
	msgs = earliest.receive(4, 10*time.Second)
	assert.Equal(t, 4, len(msgs))
	assert.Equal(t, "before", string(msgs[0].GetData()))
	assert.Nil(t, earliest.stop())

	after := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
		Topic:   topic,
		AfterID: res.Ids[1],
	})
	msgs = after.receive(1, 10*time.Second)
	assert.Equal(t, []string{"b"}, getTestPubSubData(msgs))
	assert.Nil(t, after.stop())

	{
		topic := newTestPubSubTopic()
		sub := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
			Topic: topic,
		})

		res, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("a")},
			IfExists: true,
		})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(res.Ids))

		msgs := sub.receive(1, 10*time.Second)
		assert.Equal(t, []string{"a"}, getTestPubSubData(msgs))
		assert.Nil(t, sub.stop())
	}
}

func TestPubSubSubscribeGroup(t *testing.T) {
	ctx := context.Background()
	srv := newSrvPubSub(redisutils.NewClient())
	defer srv.close()

	topic := newTestPubSubTopic()
	group := []byte("grp")

	{
		res, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("before")},
			IfExists: true,
		})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(res.Ids))
	}

	sub1 := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
		Topic:      topic,
		Group:      group,
		AckTimeout: durSeconds(1),
	})
	sub2 := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
		Topic:      topic,
		Group:      group,
		AckTimeout: durSeconds(1),
	})

	var published []string
	for i := range 10 {
		published = append(published, fmt.Sprintf("%d", i))
		res, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage(published[i])},
			IfExists: true,
		})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(res.Ids))
	}

	var msgs1, msgs2 []*rpubsubv1.Message
	deadline := time.Now().Add(10 * time.Second)
	for len(msgs1)+len(msgs2) < len(published) && time.Now().Before(deadline) {
		msgs1 = append(msgs1, sub1.receive(1, 100*time.Millisecond)...)
		msgs2 = append(msgs2, sub2.receive(1, 100*time.Millisecond)...)
	}

	assert.Equal(t, len(published), len(msgs1)+len(msgs2))
	assert.ElementsMatch(t, published, append(getTestPubSubData(msgs1), getTestPubSubData(msgs2)...))

	{
		res, err := srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{
			Topic: topic,
			Group: group,
			Ids:   getTestPubSubIDs(msgs1),
		})
		assert.Nil(t, err)
		assert.Equal(t, uint32(len(msgs1)), res.Count)
	}

	assert.Nil(t, sub1.stop())
	assert.Nil(t, sub2.stop())

	time.Sleep(1500 * time.Millisecond)

	sub3 := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
		Topic:      topic,
		Group:      group,
		AckTimeout: durSeconds(1),
	})

	redelivered := sub3.receive(len(msgs2), 10*time.Second)
	assert.ElementsMatch(t, getTestPubSubData(msgs2), getTestPubSubData(redelivered))

	{
		res, err := srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{
			Topic: topic,
			Group: group,
			Ids:   getTestPubSubIDs(redelivered),
		})
		assert.Nil(t, err)
		assert.Equal(t, uint32(len(redelivered)), res.Count)
	}

	assert.Nil(t, sub3.stop())

	{
		res, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("offline")},
			IfExists: true,
		})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(res.Ids))
	}

	sub4 := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
		Topic:      topic,
		Group:      group,
		AckTimeout: durSeconds(1),
	})
	msgs := sub4.receive(1, 10*time.Second)
	assert.Equal(t, []string{"offline"}, getTestPubSubData(msgs))
	assert.Equal(t, 0, len(sub4.receive(1, 500*time.Millisecond)))

	{
		res, err := srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{
			Topic: topic,
			Group: group,
			Ids:   getTestPubSubIDs(msgs),
		})
		assert.Nil(t, err)
		assert.Equal(t, uint32(1), res.Count)
	}

	assert.Nil(t, sub4.stop())

	consumers, err := srv.redisC.XInfoConsumers(ctx, srv.getTopicKey(topic), string(group)).Result()
	assert.Nil(t, err)
	assert.Equal(t, 1, len(consumers))
	assert.Equal(t, int64(0), consumers[0].Pending)

	{
		topic := newTestPubSubTopic()

		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("retained")},
		})
		assert.Nil(t, err)

		sub := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
			Topic:    topic,
			Group:    group,
			Position: rpubsubv1.SubscribeRequest_EARLIEST,
		})
		msgs := sub.receive(1, 10*time.Second)
		assert.Equal(t, []string{"retained"}, getTestPubSubData(msgs))
		assert.Nil(t, sub.stop())
	}

	{
		topic := newTestPubSubTopic()
		key := srv.getTopicKey(topic)

		sub := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{
			Topic: topic,
			Group: group,
		})

		_, err := srv.redisC.XAdd(ctx, &redis.XAddArgs{
			Stream: key,
			Values: map[string]any{
				"x": "y",
			},
		}).Result()
		assert.Nil(t, err)

		res, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{
			Topic:    topic,
			Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("valid")},
			IfExists: true,
		})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(res.Ids))

		msgs := sub.receive(1, 10*time.Second)
		assert.Equal(t, []string{"valid"}, getTestPubSubData(msgs))

		pending, err := srv.redisC.XPending(ctx, key, string(group)).Result()
		assert.Nil(t, err)
		assert.Equal(t, int64(1), pending.Count)

		assert.Nil(t, sub.stop())
	}
}

func TestPubSubDecodeMessage(t *testing.T) {
	srv := &srvPubSub{}
	for _, values := range []map[string]any{
		{}, {pubSubFieldData: 1}, {pubSubFieldData: string([]byte{255})}, {pubSubFieldData: ""},
	} {
		res, err := srv.decodeMessage(redis.XMessage{ID: "1-0", Values: values})
		assert.Nil(t, res)
		assert.NotNil(t, err)
	}
	msg := newTestPubSubDataMessage(string([]byte{0, 255, 1}))
	msg.Id = []byte("forged")
	data, err := pbutils.Marshal(msg)
	require.Nil(t, err)
	res, err := srv.decodeMessage(redis.XMessage{ID: "2-1", Values: map[string]any{pubSubFieldData: string(data)}})
	require.Nil(t, err)
	assert.Equal(t, []byte("2-1"), res.Id)
	assert.Equal(t, msg.GetData(), res.GetData())
}

func TestPubSubPublishValidationAtomicity(t *testing.T) {
	srv := newSrvPubSub(redisutils.NewClient())
	t.Cleanup(func() { srv.close(); srv.redisC.Close() })
	ctx := t.Context()
	topic := newTestPubSubTopic()
	key := srv.getTopicKey(topic)
	t.Cleanup(func() { srv.redisC.Del(context.Background(), key) })
	for _, invalid := range []*rpubsubv1.Message{nil, {}, newTestPubSubDataMessage(string(make([]byte, pubSubMaxMessageSize+1)))} {
		_, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{Topic: topic, Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("valid"), invalid}})
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		count, err := srv.redisC.Exists(ctx, key).Result()
		require.Nil(t, err)
		assert.Zero(t, count)
	}
	msg := newTestPubSubDataMessage("valid")
	msg.Id = []byte("forged")
	before := proto.Clone(msg)
	res, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{Topic: topic, Messages: []*rpubsubv1.Message{msg}})
	require.Nil(t, err)
	require.Len(t, res.Ids, 1)
	assert.True(t, proto.Equal(before, msg))
	entries, err := srv.redisC.XRange(ctx, key, "-", "+").Result()
	require.Nil(t, err)
	require.Len(t, entries, 1)
	decoded, err := srv.decodeMessage(entries[0])
	require.Nil(t, err)
	assert.Equal(t, res.Ids[0], decoded.Id)
	assert.NotEqual(t, msg.Id, decoded.Id)
	assert.True(t, decoded.CreatedAt.IsValid())
}

func TestPubSubFanoutConcurrent(t *testing.T) {
	srv := newSrvPubSub(redisutils.NewClient())
	t.Cleanup(func() { srv.close(); srv.redisC.Close() })
	topic := newTestPubSubTopic()
	t.Cleanup(func() { srv.redisC.Del(context.Background(), srv.getTopicKey(topic)) })
	var subs []*testPubSubSubscription
	for range 3 {
		sub := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{Topic: topic})
		subs = append(subs, sub)
		t.Cleanup(func() { assert.Nil(t, sub.stop()) })
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 25 {
				_, err := srv.Publish(t.Context(), &rpubsubv1.PublishRequest{Topic: topic,
					Messages: []*rpubsubv1.Message{newTestPubSubDataMessage(fmt.Sprintf("%d-%d", worker, i))}})
				assert.Nil(t, err)
			}
		})
	}
	wg.Wait()
	var expected []*rpubsubv1.Message
	entries, err := srv.redisC.XRange(t.Context(), srv.getTopicKey(topic), "-", "+").Result()
	require.Nil(t, err)
	require.Len(t, entries, 200)
	for _, entry := range entries {
		msg, err := srv.decodeMessage(entry)
		require.Nil(t, err)
		expected = append(expected, msg)
	}
	for _, sub := range subs {
		actual := sub.receive(len(expected), 10*time.Second)
		assert.Equal(t, getTestPubSubIDs(expected), getTestPubSubIDs(actual))
		assert.Equal(t, getTestPubSubData(expected), getTestPubSubData(actual))
	}
}

func TestPubSubGroupIsolationAndRecovery(t *testing.T) {
	srv := newSrvPubSub(redisutils.NewClient())
	t.Cleanup(func() { srv.close(); srv.redisC.Close() })
	ctx := t.Context()
	topic := newTestPubSubTopic()
	key := srv.getTopicKey(topic)
	t.Cleanup(func() { srv.redisC.Del(context.Background(), key) })
	sub := startTestPubSubSubscription(t, srv, &rpubsubv1.SubscribeRequest{Topic: topic, Group: []byte("first")})
	t.Cleanup(func() { assert.Nil(t, sub.stop()) })
	res, err := srv.Publish(ctx, &rpubsubv1.PublishRequest{Topic: topic, Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("first")}})
	require.Nil(t, err)
	require.Len(t, sub.receive(1, 5*time.Second), 1)
	ack, err := srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{Topic: topic, Group: []byte("other"), Ids: res.Ids})
	require.Nil(t, err)
	assert.Zero(t, ack.Count)
	pending, err := srv.redisC.XPending(ctx, key, "first").Result()
	require.Nil(t, err)
	assert.Equal(t, int64(1), pending.Count)

	require.Nil(t, srv.redisC.XGroupDestroy(ctx, key, "first").Err())
	_, err = srv.Publish(ctx, &rpubsubv1.PublishRequest{Topic: topic, Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("second")}})
	require.Nil(t, err)
	msgs := sub.receive(2, 10*time.Second)
	assert.Equal(t, []string{"first", "second"}, getTestPubSubData(msgs))
	ack, err = srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{Topic: topic, Group: []byte("first"), Ids: getTestPubSubIDs(msgs)})
	require.Nil(t, err)
	assert.Equal(t, uint32(2), ack.Count)
	ack, err = srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{Topic: topic, Group: []byte("first"), Ids: getTestPubSubIDs(msgs)})
	require.Nil(t, err)
	assert.Zero(t, ack.Count)
}

type testPubSubErrorStream struct {
	*fakePubSubStream
}

func (s *testPubSubErrorStream) Send(*rpubsubv1.SubscribeResponse) error {
	return io.ErrUnexpectedEOF
}

func TestPubSubErrors(t *testing.T) {
	srv := newSrvPubSub(redisutils.NewClient())
	t.Cleanup(func() { srv.close(); srv.redisC.Close() })
	ctx := t.Context()
	for _, group := range [][]byte{nil, []byte("group")} {
		topic := newTestPubSubTopic()
		t.Cleanup(func() { srv.redisC.Del(context.Background(), srv.getTopicKey(topic)) })
		stream := &testPubSubErrorStream{fakePubSubStream: &fakePubSubStream{ctx: ctx}}
		assert.ErrorIs(t, srv.Subscribe(&rpubsubv1.SubscribeRequest{Topic: topic, Group: group}, stream), io.ErrUnexpectedEOF)
		assert.Zero(t, srv.subscriptions.Load())
	}
	for _, id := range [][]byte{nil, []byte("1-"), []byte("1-2-3"), make([]byte, pubSubMaxIDLen+1)} {
		assert.Equal(t, codes.InvalidArgument, status.Code(srv.validateID(id)))
	}
	_, err := srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{Topic: []byte("topic"), Group: []byte("group"), Ids: make([][]byte, pubSubMaxAckIDs+1)})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Nil(t, srv.redisC.Close())
	_, err = srv.Publish(ctx, &rpubsubv1.PublishRequest{Topic: []byte("topic"), Messages: []*rpubsubv1.Message{newTestPubSubDataMessage("data")}})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = srv.Acknowledge(ctx, &rpubsubv1.AcknowledgeRequest{Topic: []byte("topic"), Group: []byte("group"), Ids: [][]byte{[]byte("1-0")}})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	for _, group := range [][]byte{nil, []byte("group")} {
		err := srv.Subscribe(&rpubsubv1.SubscribeRequest{Topic: []byte("topic"), Group: group}, &fakePubSubStream{ctx: ctx})
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assert.Zero(t, srv.subscriptions.Load())
	}
	assert.Equal(t, codes.Canceled, status.Code(srv.toGRPCErr(ctx, context.Canceled)))
	assert.Equal(t, codes.DeadlineExceeded, status.Code(srv.toGRPCErr(ctx, context.DeadlineExceeded)))
	assert.False(t, isPubSubNoGroupErr(nil))
	assert.True(t, isPubSubNoGroupErr(fmt.Errorf("NOGROUP missing")))
}
