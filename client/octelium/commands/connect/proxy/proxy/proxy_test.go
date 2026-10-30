// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy/userspace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type testProxyImplementor struct {
	mu        sync.Mutex
	err       error
	closes    int
	upstreams []userspace.OptsUpstream
}

func (p *testProxyImplementor) Start(context.Context) error {
	return nil
}

func (p *testProxyImplementor) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closes++
	return nil
}

func (p *testProxyImplementor) UpdateUpstream(upstream userspace.OptsUpstream) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.upstreams = append(p.upstreams, upstream)
	return nil
}

func (p *testProxyImplementor) state() (int, []userspace.OptsUpstream) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closes, append([]userspace.OptsUpstream(nil), p.upstreams...)
}

func newTestHostedService() *userv1.HostedService {
	return &userv1.HostedService{
		Name: "web.default", Port: 8080, L4Type: userv1.HostedService_TCP,
		Address:  &metav1.DualStackIP{Ipv4: "100.64.0.2", Ipv6: "fd00::2"},
		Upstream: &userv1.HostedService_Upstream{Host: "localhost", Port: 3000},
		Mode:     userv1.HostedService_MODE_DEFAULT,
	}
}

func TestIsUpstreamOnlyChange(t *testing.T) {
	for _, tc := range []struct {
		name   string
		update func(*userv1.HostedService)
		want   bool
	}{
		{"identical", func(*userv1.HostedService) {}, true},
		{"upstream-port", func(svc *userv1.HostedService) { svc.Upstream.Port = 3001 }, true},
		{"upstream-host", func(svc *userv1.HostedService) { svc.Upstream.Host = "127.0.0.1" }, true},
		{"upstream-removed", func(svc *userv1.HostedService) { svc.Upstream = nil }, true},
		{"name", func(svc *userv1.HostedService) { svc.Name = "api.default" }, false},
		{"port", func(svc *userv1.HostedService) { svc.Port = 8081 }, false},
		{"l4-type", func(svc *userv1.HostedService) { svc.L4Type = userv1.HostedService_UDP }, false},
		{"address", func(svc *userv1.HostedService) { svc.Address.Ipv4 = "100.64.0.3" }, false},
		{"address-removed", func(svc *userv1.HostedService) { svc.Address = nil }, false},
		{"mode", func(svc *userv1.HostedService) { svc.Mode = userv1.HostedService_MODE_ESSH }, false},
		{"upstream-and-port", func(svc *userv1.HostedService) {
			svc.Upstream.Port = 3001
			svc.Port = 8081
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cur := newTestHostedService()
			svc := proto.Clone(cur).(*userv1.HostedService)
			tc.update(svc)
			assert.Equal(t, tc.want, isUpstreamOnlyChange(cur, svc))
			assert.True(t, proto.Equal(newTestHostedService(), cur), "the current Service was modified")
		})
	}
}

func TestProxyUpdateUpstream(t *testing.T) {
	cur := newTestHostedService()
	impl := &testProxyImplementor{}
	p := &proxy{svc: cur, p: impl}

	updated := proto.Clone(cur).(*userv1.HostedService)
	updated.Upstream = &userv1.HostedService_Upstream{Host: "127.0.0.1", Port: 3001}
	assert.True(t, p.updateUpstream(updated))
	assert.Same(t, updated, p.svc)
	_, upstreams := impl.state()
	assert.Equal(t, []userspace.OptsUpstream{{Address: "127.0.0.1", Port: 3001}}, upstreams)

	moved := proto.Clone(updated).(*userv1.HostedService)
	moved.Port = 8081
	assert.False(t, p.updateUpstream(moved))

	removed := proto.Clone(updated).(*userv1.HostedService)
	removed.Upstream = nil
	assert.False(t, p.updateUpstream(removed))

	impl.err = errors.New("the upstream cannot be updated in place")
	failed := proto.Clone(updated).(*userv1.HostedService)
	failed.Upstream.Port = 3002
	assert.False(t, p.updateUpstream(failed))

	assert.Same(t, updated, p.svc)
	closes, upstreams := impl.state()
	assert.Zero(t, closes)
	assert.Len(t, upstreams, 1)

	assert.False(t, (&proxy{svc: cur}).updateUpstream(updated))
	var nilProxy *userspace.Proxy
	assert.False(t, (&proxy{svc: cur, p: nilProxy}).updateUpstream(updated))
}

func TestUpdateServiceRoutesUpstreamOnlyChangesInPlace(t *testing.T) {
	cur := newTestHostedService()
	impl := &testProxyImplementor{}
	existing := &proxy{svc: cur, p: impl}
	c := &Controller{proxies: []*proxy{existing}, ipv4Supported: true}
	t.Cleanup(func() { assert.NoError(t, c.Close()) })

	updated := proto.Clone(cur).(*userv1.HostedService)
	updated.Upstream.Port = 3001
	require.NoError(t, c.UpdateService(t.Context(), updated))
	require.Len(t, c.proxies, 1)
	assert.Same(t, existing, c.proxies[0])
	assert.Same(t, updated, existing.svc)

	require.NoError(t, c.UpdateService(t.Context(), proto.Clone(updated).(*userv1.HostedService)))
	assert.Same(t, existing, c.proxies[0])
	closes, upstreams := impl.state()
	assert.Zero(t, closes)
	assert.Equal(t, []userspace.OptsUpstream{{Address: "localhost", Port: 3001}}, upstreams)

	moved := proto.Clone(updated).(*userv1.HostedService)
	moved.Port = 0
	moved.Address = &metav1.DualStackIP{Ipv4: "127.0.0.1"}
	require.NoError(t, c.UpdateService(t.Context(), moved))
	require.Len(t, c.proxies, 1)
	assert.NotSame(t, existing, c.proxies[0])
	assert.Same(t, moved, c.proxies[0].svc)
	closes, upstreams = impl.state()
	assert.Equal(t, 1, closes)
	assert.Len(t, upstreams, 1)
}

func TestUpdateServiceReplacesProxyWhenInPlaceUpdateFails(t *testing.T) {
	cur := newTestHostedService()
	cur.Address = &metav1.DualStackIP{Ipv4: "127.0.0.1"}
	cur.Port = 0
	impl := &testProxyImplementor{err: errors.New("the upstream cannot be updated in place")}
	existing := &proxy{svc: cur, p: impl}
	c := &Controller{proxies: []*proxy{existing}, ipv4Supported: true}
	t.Cleanup(func() { assert.NoError(t, c.Close()) })

	updated := proto.Clone(cur).(*userv1.HostedService)
	updated.Upstream.Port = 3001
	require.NoError(t, c.UpdateService(t.Context(), updated))
	require.Len(t, c.proxies, 1)
	assert.NotSame(t, existing, c.proxies[0])
	assert.Same(t, updated, c.proxies[0].svc)
	closes, upstreams := impl.state()
	assert.Equal(t, 1, closes)
	assert.Empty(t, upstreams)
}
