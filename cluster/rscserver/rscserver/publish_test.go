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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func newUnreachableRedisClient() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:        "localhost:1",
		MaxRetries:  -1,
		DialTimeout: 500 * time.Millisecond,
	})
}

func newTestUser(name string) *corev1.User {
	return &corev1.User{
		Metadata: &metav1.Metadata{
			Name:            name,
			Uid:             vutils.UUIDv4(),
			ResourceVersion: vutils.UUIDv7(),
		},
		Spec:   &corev1.User_Spec{},
		Status: &corev1.User_Status{},
	}
}

func TestPublishWatchEventFailure(t *testing.T) {
	ctx := context.Background()

	redisC := redisutils.NewClient()

	h := newEventHub(redisC)

	api := "core"
	version := "v1"

	{
		kind := newTestKind()
		streamKey := getRscStreamKey(api, version, kind)

		t.Cleanup(func() {
			redisC.Del(context.Background(), streamKey)
		})

		srv := &Server{
			redisC:   newUnreachableRedisClient(),
			eventHub: h,
		}

		sub, err := h.subscribe(ctx, api, version, kind)
		assert.Nil(t, err)

		otherKind := newTestKind()
		otherSub, err := h.subscribe(ctx, api, version, otherKind)
		assert.Nil(t, err)

		assert.NotNil(t, srv.publishWatchEvent(ctx, api, version, kind,
			newTestWatchEvent(api, version, kind, "lost")))

		assert.True(t, waitForDone(sub, 1*time.Second))
		assert.False(t, h.hasSubscribers(streamKey))

		assert.False(t, waitForDone(otherSub, 100*time.Millisecond))
		h.unsubscribe(otherSub)
	}

	{
		kind := newTestKind()

		srv := &Server{
			redisC:   newUnreachableRedisClient(),
			eventHub: h,
		}

		sub, err := h.subscribe(ctx, api, version, kind)
		assert.Nil(t, err)

		assert.NotNil(t, srv.doPostUpdate(ctx,
			newTestUser("new"), newTestUser("old"), api, version, kind))
		assert.True(t, waitForDone(sub, 1*time.Second))
	}

	{
		kind := newTestKind()

		srv := &Server{
			redisC: newUnreachableRedisClient(),
		}

		assert.NotNil(t, srv.publishWatchEvent(ctx, api, version, kind,
			newTestWatchEvent(api, version, kind, "lost")))
	}

	{
		kind := newTestKind()
		streamKey := getRscStreamKey(api, version, kind)

		t.Cleanup(func() {
			redisC.Del(context.Background(), streamKey)
		})

		srv := &Server{
			redisC:   redisC,
			eventHub: h,
		}

		sub, err := h.subscribe(ctx, api, version, kind)
		assert.Nil(t, err)

		assert.Nil(t, srv.publishWatchEvent(ctx, api, version, kind,
			newTestWatchEvent(api, version, kind, "published")))
		assert.False(t, waitForDone(sub, 100*time.Millisecond))
		assert.True(t, h.hasSubscribers(streamKey))

		h.unsubscribe(sub)
	}
}

func TestPostCommitContext(t *testing.T) {
	ctx := context.Background()

	redisC := redisutils.NewClient()

	h := newEventHub(redisC)
	assert.Nil(t, h.Start(ctx))
	defer h.Stop()

	srv := &Server{
		redisC:   redisC,
		eventHub: h,
	}

	api := "core"
	version := "v1"

	cctx, cancel := context.WithCancel(ctx)
	cancel()

	{
		pctx, pcancel := getPostCommitContext(cctx)
		defer pcancel()

		assert.Nil(t, pctx.Err())
		deadline, ok := pctx.Deadline()
		assert.True(t, ok)
		assert.True(t, time.Until(deadline) <= postCommitTimeout)
	}

	{
		kind := newTestKind()
		streamKey := getRscStreamKey(api, version, kind)

		obj := newTestUser(utilrand.GetRandomStringCanonical(8))

		t.Cleanup(func() {
			redisC.Del(context.Background(), streamKey,
				getObjectKeyByName(api, version, kind, obj.Metadata.Name),
				getObjectKeyByUID(obj.Metadata.Uid))
		})

		sub, err := h.subscribe(ctx, api, version, kind)
		assert.Nil(t, err)

		assert.Nil(t, srv.doPostCreate(cctx, obj, api, version, kind))

		ev := waitForEvent(sub, 10*time.Second)
		assert.NotNil(t, ev)
		assert.Equal(t, obj.Metadata.Name, getEventName(ev))

		cached, err := redisC.Get(ctx, getObjectKeyByUID(obj.Metadata.Uid)).Result()
		assert.Nil(t, err)

		res := &corev1.User{}
		assert.Nil(t, pbutils.Unmarshal([]byte(cached), res))
		assert.Equal(t, obj.Metadata.Uid, res.Metadata.Uid)

		h.unsubscribe(sub)
	}

	{
		kind := newTestKind()
		streamKey := getRscStreamKey(api, version, kind)

		obj := newTestUser(utilrand.GetRandomStringCanonical(8))

		t.Cleanup(func() {
			redisC.Del(context.Background(), streamKey)
		})

		sub, err := h.subscribe(ctx, api, version, kind)
		assert.Nil(t, err)

		assert.Nil(t, srv.doPostDelete(cctx, obj, api, version, kind))

		ev := waitForEvent(sub, 10*time.Second)
		assert.NotNil(t, ev)

		res := &corev1.User{}
		assert.Nil(t, ev.GetEvent().GetDelete().GetItem().UnmarshalTo(res))
		assert.Equal(t, obj.Metadata.Uid, res.Metadata.Uid)

		h.unsubscribe(sub)
	}
}

func TestDoSetCacheFailure(t *testing.T) {
	ctx := context.Background()

	redisC := redisutils.NewClient()

	usr := fmt.Sprintf("octelium-tst-%s", utilrand.GetRandomStringLowercase(8))
	passwd := utilrand.GetRandomString(32)

	assert.Nil(t, redisC.Do(ctx, "ACL", "SETUSER", usr, "reset", "on",
		fmt.Sprintf(">%s", passwd), "~*", "&*", "+@all", "-set").Err())
	t.Cleanup(func() {
		redisC.Do(context.Background(), "ACL", "DELUSER", usr)
	})

	srv := &Server{
		redisC: redis.NewClient(&redis.Options{
			Addr:     redisC.Options().Addr,
			DB:       redisC.Options().DB,
			Username: usr,
			Password: passwd,
		}),
	}

	api := "core"
	version := "v1"
	kind := newTestKind()

	obj := newTestUser(utilrand.GetRandomStringCanonical(8))

	nameKey := getObjectKeyByName(api, version, kind, obj.Metadata.Name)
	uidKey := getObjectKeyByUID(obj.Metadata.Uid)

	t.Cleanup(func() {
		redisC.Del(context.Background(), nameKey, uidKey)
	})

	stale := pbutils.Clone(obj).(*corev1.User)
	stale.Metadata.ResourceVersion = vutils.UUIDv7()

	staleBytes, err := pbutils.Marshal(stale)
	assert.Nil(t, err)

	assert.Nil(t, redisC.Set(ctx, nameKey, string(staleBytes), cacheResourceTTL).Err())
	assert.Nil(t, redisC.Set(ctx, uidKey, string(staleBytes), cacheResourceTTL).Err())

	assert.NotNil(t, srv.redisC.Set(ctx, nameKey, "x", cacheResourceTTL).Err())

	srv.doSetCache(ctx, obj, api, version, kind)

	assert.Equal(t, redis.Nil, redisC.Get(ctx, nameKey).Err())
	assert.Equal(t, redis.Nil, redisC.Get(ctx, uidKey).Err())

	{
		_, found, err := (&Server{
			redisC: redisC,
			opts: &Opts{
				NewResourceObject: vutils.NewResourceObject,
			},
		}).doGetCache(ctx, &rmetav1.GetOptions{Uid: obj.Metadata.Uid}, api, version, kind)
		assert.Nil(t, err)
		assert.False(t, found)
	}
}
