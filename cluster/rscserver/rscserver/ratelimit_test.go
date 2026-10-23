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
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rratelimitv1"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRatLimit(t *testing.T) {
	srvCache := &srvRateLimit{
		redisC: redisutils.NewClient(),
	}

	ctx := context.Background()
	{

		key := utilrand.GetRandomBytesMust(32)
		{
			resp, err := srvCache.CheckSlidingWindow(ctx, &rratelimitv1.CheckSlidingWindowRequest{
				Key: key,
				Window: &metav1.Duration{
					Type: &metav1.Duration_Seconds{
						Seconds: 4,
					},
				},
				Limit: 2,
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, resp.IsAllowed)
		}

		time.Sleep(1 * time.Second)
		{
			resp, err := srvCache.CheckSlidingWindow(ctx, &rratelimitv1.CheckSlidingWindowRequest{
				Key: key,
				Window: &metav1.Duration{
					Type: &metav1.Duration_Seconds{
						Seconds: 4,
					},
				},
				Limit: 2,
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, resp.IsAllowed)
		}

		time.Sleep(1 * time.Second)
		{
			resp, err := srvCache.CheckSlidingWindow(ctx, &rratelimitv1.CheckSlidingWindowRequest{
				Key: key,
				Window: &metav1.Duration{
					Type: &metav1.Duration_Seconds{
						Seconds: 4,
					},
				},
				Limit: 2,
			})
			assert.Nil(t, err, "%+v", err)
			assert.False(t, resp.IsAllowed)
		}

		time.Sleep(5 * time.Second)
		{
			resp, err := srvCache.CheckSlidingWindow(ctx, &rratelimitv1.CheckSlidingWindowRequest{
				Key: key,
				Window: &metav1.Duration{
					Type: &metav1.Duration_Seconds{
						Seconds: 4,
					},
				},
				Limit: 2,
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, resp.IsAllowed)
		}
		{
			resp, err := srvCache.CheckSlidingWindow(ctx, &rratelimitv1.CheckSlidingWindowRequest{
				Key: key,
				Window: &metav1.Duration{
					Type: &metav1.Duration_Seconds{
						Seconds: 4,
					},
				},
				Limit: 2,
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, resp.IsAllowed)
		}

		time.Sleep(5 * time.Millisecond)
		{
			resp, err := srvCache.CheckSlidingWindow(ctx, &rratelimitv1.CheckSlidingWindowRequest{
				Key: key,
				Window: &metav1.Duration{
					Type: &metav1.Duration_Seconds{
						Seconds: 4,
					},
				},
				Limit: 2,
			})
			assert.Nil(t, err, "%+v", err)
			assert.False(t, resp.IsAllowed)
		}
	}

}

func TestReserveSlidingWindow(t *testing.T) {
	srvCache := &srvRateLimit{
		redisC: redisutils.NewClient(),
	}

	ctx := context.Background()

	window := &metav1.Duration{
		Type: &metav1.Duration_Seconds{
			Seconds: 4,
		},
	}

	{
		key := utilrand.GetRandomBytesMust(32)
		id1 := utilrand.GetRandomBytesMust(16)
		id2 := utilrand.GetRandomBytesMust(16)

		{
			resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
				Key:    key,
				Window: window,
				Limit:  100,
				Id:     id1,
				Amount: 60,
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, resp.IsAllowed)
			assert.Equal(t, int64(60), resp.Total)
		}

		{
			resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
				Key:    key,
				Window: window,
				Limit:  100,
				Id:     id2,
				Amount: 50,
			})
			assert.Nil(t, err, "%+v", err)
			assert.False(t, resp.IsAllowed)
			assert.Equal(t, int64(60), resp.Total)
		}

		{
			resp, err := srvCache.ReconcileSlidingWindow(ctx, &rratelimitv1.ReconcileSlidingWindowRequest{
				Key:    key,
				Window: window,
				Id:     id1,
				Amount: 10,
			})
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, int64(10), resp.Total)
		}

		{
			resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
				Key:    key,
				Window: window,
				Limit:  100,
				Id:     id2,
				Amount: 50,
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, resp.IsAllowed)
			assert.Equal(t, int64(60), resp.Total)
		}

		{
			resp, err := srvCache.ReconcileSlidingWindow(ctx, &rratelimitv1.ReconcileSlidingWindowRequest{
				Key:    key,
				Window: window,
				Id:     id2,
			})
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, int64(10), resp.Total)
		}
	}

	{
		key := utilrand.GetRandomBytesMust(32)

		{
			resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
				Key:    key,
				Window: window,
				Limit:  100,
				Id:     utilrand.GetRandomBytesMust(16),
				Amount: 100,
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, resp.IsAllowed)
		}

		{
			resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
				Key:    key,
				Window: window,
				Limit:  100,
				Id:     utilrand.GetRandomBytesMust(16),
				Amount: 0,
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, resp.IsAllowed)
		}

		{
			resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
				Key:    key,
				Window: window,
				Limit:  100,
				Id:     utilrand.GetRandomBytesMust(16),
				Amount: 1,
			})
			assert.Nil(t, err, "%+v", err)
			assert.False(t, resp.IsAllowed)
		}

		time.Sleep(5 * time.Second)
		{
			resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
				Key:    key,
				Window: window,
				Limit:  100,
				Id:     utilrand.GetRandomBytesMust(16),
				Amount: 100,
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, resp.IsAllowed)
			assert.Equal(t, int64(100), resp.Total)
		}
	}

	{
		key := utilrand.GetRandomBytesMust(32)
		id := utilrand.GetRandomBytesMust(16)

		{
			resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
				Key:    key,
				Window: window,
				Limit:  100,
				Id:     id,
				Amount: 20,
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, resp.IsAllowed)
		}

		time.Sleep(5 * time.Second)
		{
			resp, err := srvCache.ReconcileSlidingWindow(ctx, &rratelimitv1.ReconcileSlidingWindowRequest{
				Key:    key,
				Window: window,
				Id:     id,
				Amount: 30,
			})
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, int64(30), resp.Total)
		}
	}

	{
		_, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    utilrand.GetRandomBytesMust(32),
			Window: window,
			Limit:  100,
			Amount: 1,
		})
		assert.NotNil(t, err)
	}

	{
		_, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    utilrand.GetRandomBytesMust(32),
			Window: window,
			Limit:  100,
			Id:     utilrand.GetRandomBytesMust(16),
			Amount: -1,
		})
		assert.NotNil(t, err)
	}

	{
		_, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    utilrand.GetRandomBytesMust(32),
			Limit:  100,
			Id:     utilrand.GetRandomBytesMust(16),
			Amount: 1,
		})
		assert.NotNil(t, err)
	}

	{
		_, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key: utilrand.GetRandomBytesMust(32),
			Window: &metav1.Duration{
				Type: &metav1.Duration_Seconds{
					Seconds: 0,
				},
			},
			Limit:  100,
			Id:     utilrand.GetRandomBytesMust(16),
			Amount: 1,
		})
		assert.NotNil(t, err)
	}

	{
		_, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    utilrand.GetRandomBytesMust(32),
			Window: window,
			Id:     utilrand.GetRandomBytesMust(16),
			Amount: 1,
		})
		assert.NotNil(t, err)
	}

	{
		_, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    utilrand.GetRandomBytesMust(32),
			Window: window,
			Limit:  100,
			Id:     utilrand.GetRandomBytesMust(16),
			Amount: maxSlidingWindowAmount + 1,
		})
		assert.NotNil(t, err)
	}
}

func TestReserveSlidingWindowDeniedUpdate(t *testing.T) {
	srvCache := &srvRateLimit{
		redisC: redisutils.NewClient(),
	}

	ctx := context.Background()

	window := &metav1.Duration{
		Type: &metav1.Duration_Seconds{
			Seconds: 10,
		},
	}

	key := utilrand.GetRandomBytesMust(32)
	id1 := utilrand.GetRandomBytesMust(16)
	id2 := utilrand.GetRandomBytesMust(16)

	{
		resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    key,
			Window: window,
			Limit:  100,
			Id:     id1,
			Amount: 60,
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsAllowed)
	}

	{
		resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    key,
			Window: window,
			Limit:  100,
			Id:     id2,
			Amount: 30,
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsAllowed)
		assert.Equal(t, int64(90), resp.Total)
	}

	{
		resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    key,
			Window: window,
			Limit:  100,
			Id:     id1,
			Amount: 80,
		})
		assert.Nil(t, err, "%+v", err)
		assert.False(t, resp.IsAllowed)
		assert.Equal(t, int64(90), resp.Total)
	}

	{
		resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    key,
			Window: window,
			Limit:  100,
			Id:     utilrand.GetRandomBytesMust(16),
			Amount: 10,
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsAllowed)
		assert.Equal(t, int64(100), resp.Total)
	}
}

func TestReconcileSlidingWindowTimestamp(t *testing.T) {
	srvCache := &srvRateLimit{
		redisC: redisutils.NewClient(),
	}

	ctx := context.Background()

	window := &metav1.Duration{
		Type: &metav1.Duration_Seconds{
			Seconds: 4,
		},
	}

	key := utilrand.GetRandomBytesMust(32)
	id := utilrand.GetRandomBytesMust(16)

	{
		resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    key,
			Window: window,
			Limit:  100,
			Id:     id,
			Amount: 20,
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsAllowed)
	}

	time.Sleep(3 * time.Second)
	{
		resp, err := srvCache.ReconcileSlidingWindow(ctx, &rratelimitv1.ReconcileSlidingWindowRequest{
			Key:    key,
			Window: window,
			Id:     id,
			Amount: 30,
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, int64(30), resp.Total)
	}

	time.Sleep(2 * time.Second)
	{
		resp, err := srvCache.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
			Key:    key,
			Window: window,
			Limit:  100,
			Id:     utilrand.GetRandomBytesMust(16),
			Amount: 71,
		})
		assert.Nil(t, err, "%+v", err)
		assert.False(t, resp.IsAllowed)
		assert.Equal(t, int64(30), resp.Total)
	}
}

func TestReserveSlidingWindowConcurrent(t *testing.T) {
	srv := &srvRateLimit{redisC: redisutils.NewClient()}
	t.Cleanup(func() { srv.redisC.Close() })
	ctx := t.Context()
	for _, sameID := range []bool{false, true} {
		t.Run(fmt.Sprintf("same-id-%t", sameID), func(t *testing.T) {
			key := utilrand.GetRandomBytesMust(32)
			t.Cleanup(func() { srv.redisC.Del(context.Background(), getReservationKeys(key)...) })
			var wg sync.WaitGroup
			results := make(chan bool, 128)
			start := make(chan struct{})
			for i := range 128 {
				wg.Go(func() {
					<-start
					id := []byte(fmt.Sprintf("id-%d", i))
					if sameID {
						id = []byte("same-id")
					}
					res, err := srv.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
						Key: key, Id: id, Window: durMinutes(1), Limit: 25, Amount: 1,
					})
					if assert.Nil(t, err) {
						results <- res.IsAllowed
					}
				})
			}
			close(start)
			wg.Wait()
			close(results)
			allowed := 0
			for ok := range results {
				if ok {
					allowed++
				}
			}
			expected := 25
			if sameID {
				expected = 128
			}
			assert.Equal(t, expected, allowed)
			res, err := srv.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{
				Key: key, Id: []byte("probe"), Window: durMinutes(1), Limit: 25,
			})
			require.Nil(t, err)
			assert.True(t, res.IsAllowed)
			total := int64(25)
			if sameID {
				total = 1
			}
			assert.Equal(t, total, res.Total)
		})
	}
}

func TestRateLimitErrors(t *testing.T) {
	srv := &srvRateLimit{redisC: redisutils.NewClient()}
	require.Nil(t, srv.redisC.Close())
	ctx := t.Context()
	_, err := srv.CheckSlidingWindow(ctx, &rratelimitv1.CheckSlidingWindowRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = srv.CheckSlidingWindow(ctx, &rratelimitv1.CheckSlidingWindowRequest{Key: []byte("key"), Window: durSeconds(1), Limit: 1})
	assert.Equal(t, codes.Internal, status.Code(err))
	_, err = srv.ReserveSlidingWindow(ctx, &rratelimitv1.ReserveSlidingWindowRequest{Key: []byte("key"), Id: []byte("id"), Window: durSeconds(1), Limit: 1})
	assert.Equal(t, codes.Internal, status.Code(err))
	_, err = srv.ReconcileSlidingWindow(ctx, &rratelimitv1.ReconcileSlidingWindowRequest{Key: []byte("key"), Id: []byte("id"), Window: durSeconds(1)})
	assert.Equal(t, codes.Internal, status.Code(err))
	for _, req := range []*rratelimitv1.ReconcileSlidingWindowRequest{
		{}, {Key: []byte("key")}, {Key: []byte("key"), Id: []byte("id")},
		{Key: []byte("key"), Id: []byte("id"), Window: durSeconds(0)},
		{Key: []byte("key"), Id: []byte("id"), Window: durSeconds(1), Amount: -1},
		{Key: []byte("key"), Id: []byte("id"), Window: durSeconds(1), Amount: maxSlidingWindowAmount + 1},
	} {
		_, err := srv.ReconcileSlidingWindow(ctx, req)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}
}
