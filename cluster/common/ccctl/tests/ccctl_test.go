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

package ccctltests

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/ccctl"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestNewAndGet(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	c, err := ccctl.New(ctx, fakeC.OcteliumC, nil)
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, c)

	cc := c.Get()
	assert.NotNil(t, cc)
	assert.Equal(t, "default", cc.Metadata.Name)

	{
		other := c.Get()
		assert.NotNil(t, other)
		assert.Equal(t, cc.Metadata.Uid, other.Metadata.Uid)

		assert.False(t, cc == other)

		cc.Status.Domain = utilrand.GetRandomStringLowercase(8)
		assert.NotEqual(t, cc.Status.Domain, c.Get().Status.Domain)
	}
}

func TestRunOnUpdate(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	var mu sync.Mutex
	var updates int

	c, err := ccctl.New(ctx, fakeC.OcteliumC, &ccctl.Opts{
		OnUpdate: func(ctx context.Context, new, old *corev1.ClusterConfig) error {
			mu.Lock()
			updates = updates + 1
			mu.Unlock()
			return nil
		},
	})
	assert.Nil(t, err, "%+v", err)

	assert.Nil(t, c.Run(ctx))

	time.Sleep(2 * time.Second)

	cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err, "%+v", err)

	newDomain := utilrand.GetRandomStringLowercase(10)
	cc.Status.Domain = newDomain

	_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	assert.Nil(t, err, "%+v", err)

	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return updates > 0
	}, 30*time.Second, 200*time.Millisecond)

	assert.Eventually(t, func() bool {
		return c.Get().Status.Domain == newDomain
	}, 30*time.Second, 200*time.Millisecond)
}

func TestRunWithoutOpts(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	c, err := ccctl.New(ctx, fakeC.OcteliumC, nil)
	assert.Nil(t, err, "%+v", err)

	assert.Nil(t, c.Run(ctx))

	time.Sleep(2 * time.Second)

	cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err, "%+v", err)

	newDomain := utilrand.GetRandomStringLowercase(10)
	cc.Status.Domain = newDomain

	_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	assert.Nil(t, err, "%+v", err)

	assert.Eventually(t, func() bool {
		return c.Get().Status.Domain == newDomain
	}, 30*time.Second, 200*time.Millisecond)
}
