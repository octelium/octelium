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
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/ccctl"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
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

type tstClusterConfigClient struct {
	octeliumc.ClientInterface
	cc *corev1.ClusterConfig
}

func (c *tstClusterConfigClient) CoreV1Utils() octeliumc.CoreV1Utils { return c }

func (c *tstClusterConfigClient) GetClusterConfig(ctx context.Context) (*corev1.ClusterConfig, error) {
	return c.cc, nil
}

type tstClusterConfigUpdates struct {
	mu      sync.Mutex
	updates [][2]*corev1.ClusterConfig
}

func (u *tstClusterConfigUpdates) onUpdate(ctx context.Context, new, old *corev1.ClusterConfig) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.updates = append(u.updates, [2]*corev1.ClusterConfig{new, old})
	return nil
}

func (u *tstClusterConfigUpdates) get() [][2]*corev1.ClusterConfig {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([][2]*corev1.ClusterConfig(nil), u.updates...)
}

func TestNewDoesNotShareInitialClusterConfig(t *testing.T) {
	cc := &corev1.ClusterConfig{
		Metadata: &metav1.Metadata{Name: "default"},
		Status:   &corev1.ClusterConfig_Status{Domain: "example.com"},
	}
	c, err := ccctl.New(t.Context(), &tstClusterConfigClient{cc: cc}, nil)
	require.Nil(t, err)
	cc.Status.Domain = "changed.example.com"
	assert.Equal(t, "example.com", c.Get().Status.Domain)
}

func TestRunReconcilesUpdateBeforeWatchStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })

	initial, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	require.Nil(t, err)

	updates := &tstClusterConfigUpdates{}
	c, err := ccctl.New(ctx, &tstClusterConfigClient{ClientInterface: tst.C.OcteliumC, cc: initial},
		&ccctl.Opts{OnUpdate: updates.onUpdate})
	require.Nil(t, err)

	cc := proto.Clone(initial).(*corev1.ClusterConfig)
	cc.Status.Domain = utilrand.GetRandomStringLowercase(10)
	cc, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	require.Nil(t, err)

	require.Nil(t, c.Run(ctx))

	require.Eventually(t, func() bool {
		return c.Get().Status.Domain == cc.Status.Domain
	}, 30*time.Second, 50*time.Millisecond)
	require.Eventually(t, func() bool { return len(updates.get()) == 1 }, 5*time.Second, 50*time.Millisecond)
	update := updates.get()[0]
	assert.Equal(t, cc.Status.Domain, update[0].Status.Domain)
	assert.Equal(t, initial.Status.Domain, update[1].Status.Domain)
	assert.Equal(t, initial.Metadata.ResourceVersion, update[1].Metadata.ResourceVersion)
}

func TestRunIgnoresUnchangedInitialClusterConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })

	updates := &tstClusterConfigUpdates{}
	c, err := ccctl.New(ctx, tst.C.OcteliumC, &ccctl.Opts{OnUpdate: updates.onUpdate})
	require.Nil(t, err)
	require.Nil(t, c.Run(ctx))

	assert.Never(t, func() bool { return len(updates.get()) > 0 }, 2*time.Second, 50*time.Millisecond)

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	require.Nil(t, err)
	cc.Status.Domain = utilrand.GetRandomStringLowercase(10)
	_, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	require.Nil(t, err)

	require.Eventually(t, func() bool { return len(updates.get()) == 1 }, 30*time.Second, 50*time.Millisecond)
	assert.Equal(t, cc.Status.Domain, updates.get()[0][0].Status.Domain)
}
