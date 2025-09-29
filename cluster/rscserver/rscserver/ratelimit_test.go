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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rratelimitv1"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
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
