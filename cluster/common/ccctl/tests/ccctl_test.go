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
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/ccctl"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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
	cc     *corev1.ClusterConfig
	events chan *rmetav1.WatchEvent
}

func (c *tstClusterConfigClient) CoreV1Utils() octeliumc.CoreV1Utils { return c }

func (c *tstClusterConfigClient) CoreC() rcorev1.ResourceServiceClient {
	return &tstClusterConfigWatchClient{events: c.events}
}

func (c *tstClusterConfigClient) GetClusterConfig(ctx context.Context) (*corev1.ClusterConfig, error) {
	return c.cc, nil
}

type tstClusterConfigWatchClient struct {
	rcorev1.ResourceServiceClient
	events <-chan *rmetav1.WatchEvent
}

func (c *tstClusterConfigWatchClient) WatchClusterConfig(ctx context.Context, opts *rmetav1.WatchOptions,
	callOpts ...grpc.CallOption) (grpc.ServerStreamingClient[rmetav1.WatchEvent], error) {
	return &tstClusterConfigStream{ctx: ctx, events: c.events}, nil
}

type tstClusterConfigStream struct {
	grpc.ServerStreamingClient[rmetav1.WatchEvent]
	ctx    context.Context
	events <-chan *rmetav1.WatchEvent
}

func (s *tstClusterConfigStream) RecvMsg(m any) error {
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case ev := <-s.events:
		proto.Merge(m.(*rmetav1.WatchEvent), ev)
		return nil
	}
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

func TestRunDoesNotShareUpdatedClusterConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	initial := &corev1.ClusterConfig{
		Metadata: &metav1.Metadata{Name: "default", Uid: "cluster-config", ResourceVersion: "initial"},
		Status: &corev1.ClusterConfig_Status{
			Domain:  "example.com",
			Network: &corev1.ClusterConfig_Status_Network{V6RangePrefix: []byte{1, 2, 3, 4}},
		},
	}
	client := &tstClusterConfigClient{cc: initial, events: make(chan *rmetav1.WatchEvent, 1)}
	updates := &tstClusterConfigUpdates{}
	c, err := ccctl.New(ctx, client, &ccctl.Opts{OnUpdate: updates.onUpdate})
	require.Nil(t, err)

	cc := proto.Clone(initial).(*corev1.ClusterConfig)
	cc.Metadata.ResourceVersion = "updated"
	cc.Metadata.LastResourceVersion = initial.Metadata.ResourceVersion
	cc.Status.Domain = "updated.example.com"
	client.events <- &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			Type: &rmetav1.WatchEvent_Event_Update_{
				Update: &rmetav1.WatchEvent_Event_Update{
					NewItem: pbutils.MessageToAnyMust(cc),
					OldItem: pbutils.MessageToAnyMust(initial),
				},
			},
		},
	}
	require.Nil(t, c.Run(ctx))

	require.Eventually(t, func() bool { return len(updates.get()) == 1 }, 5*time.Second, 50*time.Millisecond)
	update := updates.get()[0]
	assert.True(t, proto.Equal(cc, update[0]))
	assert.True(t, proto.Equal(initial, update[1]))
	assert.True(t, proto.Equal(cc, c.Get()))

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			got := c.Get()
			assert.True(t, proto.Equal(cc, got))
			got.Status.Domain = "reader.example.com"
			got.Status.Network.V6RangePrefix[0]++
		}
	})
	for range 1000 {
		update[0].Status.Domain = "callback.example.com"
		update[0].Status.Network.V6RangePrefix[0]++
		update[1].Status.Domain = "old.example.com"
		update[1].Status.Network.V6RangePrefix[0]++
	}
	wg.Wait()
	assert.True(t, proto.Equal(cc, c.Get()))
}

func TestRunReconcilesInitialClusterConfig(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withOpts bool
	}{
		{name: "WithOpts", withOpts: true},
		{name: "WithoutOpts"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			initial := &corev1.ClusterConfig{
				Metadata: &metav1.Metadata{Name: "default", Uid: "cluster-config", ResourceVersion: "initial"},
				Status:   &corev1.ClusterConfig_Status{Domain: "example.com"},
			}
			cc := proto.Clone(initial).(*corev1.ClusterConfig)
			cc.Metadata.ResourceVersion = "updated"
			cc.Metadata.LastResourceVersion = initial.Metadata.ResourceVersion
			cc.Status.Domain = "updated.example.com"
			client := &tstClusterConfigClient{cc: initial, events: make(chan *rmetav1.WatchEvent, 1)}
			client.events <- &rmetav1.WatchEvent{
				Event: &rmetav1.WatchEvent_Event{
					Type: &rmetav1.WatchEvent_Event_Create_{
						Create: &rmetav1.WatchEvent_Event_Create{Item: pbutils.MessageToAnyMust(cc)},
					},
				},
			}
			updates := &tstClusterConfigUpdates{}
			var opts *ccctl.Opts
			if tc.withOpts {
				opts = &ccctl.Opts{OnUpdate: updates.onUpdate}
			}
			c, err := ccctl.New(ctx, client, opts)
			require.Nil(t, err)
			require.Nil(t, c.Run(ctx))

			require.Eventually(t, func() bool { return proto.Equal(cc, c.Get()) }, 5*time.Second, 50*time.Millisecond)
			if tc.withOpts {
				require.Eventually(t, func() bool { return len(updates.get()) == 1 }, 5*time.Second, 50*time.Millisecond)
				assert.True(t, proto.Equal(cc, updates.get()[0][0]))
				assert.True(t, proto.Equal(initial, updates.get()[0][1]))
			}
		})
	}
}

func TestRunIgnoresUnchangedInitialClusterConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	initial := &corev1.ClusterConfig{
		Metadata: &metav1.Metadata{Name: "default", Uid: "cluster-config", ResourceVersion: "initial"},
		Status:   &corev1.ClusterConfig_Status{Domain: "example.com"},
	}
	other := proto.Clone(initial).(*corev1.ClusterConfig)
	other.Metadata.Uid = "other-cluster-config"
	other.Status.Domain = "other.example.com"
	client := &tstClusterConfigClient{cc: initial, events: make(chan *rmetav1.WatchEvent, 3)}
	for _, cc := range []*corev1.ClusterConfig{initial, other} {
		client.events <- &rmetav1.WatchEvent{
			Event: &rmetav1.WatchEvent_Event{
				Type: &rmetav1.WatchEvent_Event_Create_{
					Create: &rmetav1.WatchEvent_Event_Create{Item: pbutils.MessageToAnyMust(cc)},
				},
			},
		}
	}
	client.events <- &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			Type: &rmetav1.WatchEvent_Event_Delete_{
				Delete: &rmetav1.WatchEvent_Event_Delete{Item: pbutils.MessageToAnyMust(other)},
			},
		},
	}
	updates := &tstClusterConfigUpdates{}
	c, err := ccctl.New(ctx, client, &ccctl.Opts{OnUpdate: updates.onUpdate})
	require.Nil(t, err)
	require.Nil(t, c.Run(ctx))

	assert.Never(t, func() bool { return len(updates.get()) > 0 }, 2*time.Second, 50*time.Millisecond)
	assert.True(t, proto.Equal(initial, c.Get()))

	cc := proto.Clone(initial).(*corev1.ClusterConfig)
	cc.Metadata.ResourceVersion = "updated"
	cc.Metadata.LastResourceVersion = initial.Metadata.ResourceVersion
	cc.Status.Domain = "updated.example.com"
	client.events <- &rmetav1.WatchEvent{
		Event: &rmetav1.WatchEvent_Event{
			Type: &rmetav1.WatchEvent_Event_Update_{
				Update: &rmetav1.WatchEvent_Event_Update{
					NewItem: pbutils.MessageToAnyMust(cc),
					OldItem: pbutils.MessageToAnyMust(initial),
				},
			},
		},
	}

	require.Eventually(t, func() bool { return len(updates.get()) == 1 }, 5*time.Second, 50*time.Millisecond)
	assert.True(t, proto.Equal(cc, updates.get()[0][0]))
	assert.True(t, proto.Equal(initial, updates.get()[0][1]))
	assert.True(t, proto.Equal(cc, c.Get()))
}
