//go:build linux

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

package liboctelium

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
	"google.golang.org/protobuf/proto"
)

func newTestPipeFD(t *testing.T) int {
	fds := make([]int, 2)
	assert.Nil(t, unix.Pipe(fds))
	t.Cleanup(func() {
		unix.Close(fds[0])
		unix.Close(fds[1])
	})

	return fds[0]
}

func isFDOpen(fd int) bool {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	return err == nil
}

func clearOcteliumEnv(t *testing.T) {
	for _, kv := range os.Environ() {
		if k, _, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(k, "OCTELIUM_") {
			t.Setenv(k, "")
		}
	}
}

func newTestConfig(t *testing.T) *mobilev1.Config {
	clearOcteliumEnv(t)

	return &mobilev1.Config{
		Platform: mobilev1.Config_ANDROID,
		StateDir: t.TempDir(),
		StateKey: utilrand.GetRandomBytesMust(32),
		Device: &mobilev1.Config_Device{
			Id:   utilrand.GetRandomStringCanonical(16),
			Name: "phone",
		},
	}
}

type fakeTUNFactory struct {
	mu      sync.Mutex
	fds     []int
	devs    []*fakeDev
	openErr error
}

func (f *fakeTUNFactory) openTUN(fd int) (tun.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.openErr != nil {
		return nil, f.openErr
	}

	ret := newFakeDev("faketun")
	f.fds = append(f.fds, fd)
	f.devs = append(f.devs, ret)

	return ret, nil
}

func newTestClient(t *testing.T, host *fakeHost) (*Client, *fakeTUNFactory) {
	c, err := New(newTestConfig(t), host)
	assert.Nil(t, err)
	t.Cleanup(func() {
		c.Close()
	})

	factory := &fakeTUNFactory{}
	c.openTUN = factory.openTUN

	return c, factory
}

func completeApplyWithFD(c *Client, fd int) func(id uint64, req *mobilev1.PlatformRequest) {
	return func(id uint64, req *mobilev1.PlatformRequest) {
		c.CompleteRequest(id, pbutils.MarshalMust(&mobilev1.PlatformResponse{
			Type: &mobilev1.PlatformResponse_ApplyTunnelConfiguration_{
				ApplyTunnelConfiguration: &mobilev1.PlatformResponse_ApplyTunnelConfiguration{
					TunFD: proto.Int32(int32(fd)),
				},
			},
		}))
	}
}

func completeApplyWithoutFD(c *Client) func(id uint64, req *mobilev1.PlatformRequest) {
	return func(id uint64, req *mobilev1.PlatformRequest) {
		c.CompleteRequest(id, pbutils.MarshalMust(&mobilev1.PlatformResponse{
			Type: &mobilev1.PlatformResponse_ApplyTunnelConfiguration_{
				ApplyTunnelConfiguration: &mobilev1.PlatformResponse_ApplyTunnelConfiguration{},
			},
		}))
	}
}

func completeWithError(c *Client, msg string) func(id uint64, req *mobilev1.PlatformRequest) {
	return func(id uint64, req *mobilev1.PlatformRequest) {
		c.CompleteRequest(id, pbutils.MarshalMust(&mobilev1.PlatformResponse{
			Type: &mobilev1.PlatformResponse_Error_{
				Error: &mobilev1.PlatformResponse_Error{
					Message: msg,
				},
			},
		}))
	}
}

func newTestApplyRequest() *mobilev1.PlatformRequest {
	return &mobilev1.PlatformRequest{
		Type: &mobilev1.PlatformRequest_ApplyTunnelConfiguration_{
			ApplyTunnelConfiguration: &mobilev1.PlatformRequest_ApplyTunnelConfiguration{
				Domain: "example.com",
			},
		},
	}
}

func TestRequestMap(t *testing.T) {
	m := newRequestMap()

	id1, ch1 := m.add()
	id2, _ := m.add()
	assert.NotEqual(t, id1, id2)

	assert.False(t, m.deliver(id2+1, &platformResponse{}))

	resp := &platformResponse{tunFD: -1}
	assert.True(t, m.deliver(id1, resp))
	assert.Equal(t, resp, <-ch1)
	assert.False(t, m.deliver(id1, resp))

	m.delete(id2)
	assert.False(t, m.deliver(id2, resp))
}

func TestDoPlatformRequest(t *testing.T) {
	ctx := context.Background()

	host := newFakeHost()
	c, _ := newTestClient(t, host)

	{
		pipeFD := newTestPipeFD(t)
		host.onReq = completeApplyWithFD(c, pipeFD)

		resp, err := c.doPlatformRequest(ctx, newTestApplyRequest())
		assert.Nil(t, err, "%+v", err)
		assert.GreaterOrEqual(t, resp.tunFD, 0)
		assert.NotEqual(t, pipeFD, resp.tunFD)
		assert.True(t, isFDOpen(resp.tunFD))

		tunFD := resp.tunFD
		resp.close()
		assert.Equal(t, -1, resp.tunFD)
		assert.False(t, isFDOpen(tunFD))
		assert.True(t, isFDOpen(pipeFD))
	}

	{
		host.onReq = completeWithError(c, "VPN permission denied")

		_, err := c.doPlatformRequest(ctx, newTestApplyRequest())
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "VPN permission denied")
	}

	{
		host.onReq = completeApplyWithoutFD(c)

		_, err := c.doPlatformRequest(ctx, newTestApplyRequest())
		assert.NotNil(t, err)
	}

	{
		host.onReq = completeApplyWithFD(c, -1)

		_, err := c.doPlatformRequest(ctx, newTestApplyRequest())
		assert.NotNil(t, err)
	}

	if isFDOpen(0) {
		host.onReq = completeApplyWithFD(c, 0)

		resp, err := c.doPlatformRequest(ctx, newTestApplyRequest())
		assert.Nil(t, err, "%+v", err)
		assert.Greater(t, resp.tunFD, 0)
		resp.close()
		assert.True(t, isFDOpen(0))
	}

	{
		host.onReq = completeApplyWithFD(c, 100000)

		_, err := c.doPlatformRequest(ctx, newTestApplyRequest())
		assert.NotNil(t, err)
	}

	{
		reqIDCh := make(chan uint64, 1)
		host.onReq = func(id uint64, req *mobilev1.PlatformRequest) {
			reqIDCh <- id
		}

		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		_, err := c.doPlatformRequest(ctx, newTestApplyRequest())
		assert.ErrorIs(t, err, context.DeadlineExceeded)

		err = c.CompleteRequest(<-reqIDCh, pbutils.MarshalMust(&mobilev1.PlatformResponse{}))
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		releaseCh := make(chan struct{})
		reqIDCh := make(chan uint64, 1)
		host.onReq = func(id uint64, req *mobilev1.PlatformRequest) {
			<-releaseCh
			reqIDCh <- id
		}

		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		startedAt := time.Now()
		_, err := c.doPlatformRequest(ctx, newTestApplyRequest())
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Less(t, time.Since(startedAt), 5*time.Second)

		close(releaseCh)

		pipeFD := newTestPipeFD(t)
		err = c.CompleteRequest(<-reqIDCh, pbutils.MarshalMust(&mobilev1.PlatformResponse{
			Type: &mobilev1.PlatformResponse_ApplyTunnelConfiguration_{
				ApplyTunnelConfiguration: &mobilev1.PlatformResponse_ApplyTunnelConfiguration{
					TunFD: proto.Int32(int32(pipeFD)),
				},
			},
		}))
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		err := c.CompleteRequest(1000, []byte{0xff, 0xff, 0xff})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
}

func TestPlatformNetwork(t *testing.T) {
	ctx := context.Background()

	host := newFakeHost()
	c, factory := newTestClient(t, host)

	pipeFD := newTestPipeFD(t)
	host.onReq = completeApplyWithFD(c, pipeFD)

	p := newPlatformNetwork(c, "example.com")

	cfg1 := &mobilev1.TunnelConfiguration{
		Addresses: []string{"fdee:be1d::3/128"},
		Routes:    []string{"fdee:be1d::/96"},
		Mtu:       1280,
	}

	dev1, err := p.OpenTUN(ctx, cfg1)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 1, host.getRequestCount())
	assert.Equal(t, uint64(1), host.requests[1].GetApplyTunnelConfiguration().Generation)
	assert.Equal(t, "example.com", host.requests[1].GetApplyTunnelConfiguration().Domain)
	assert.True(t, pbutils.IsEqual(cfg1, host.requests[1].GetApplyTunnelConfiguration().Configuration))
	assert.Equal(t, []int{p.tunFD}, factory.fds)

	mtu, err := dev1.MTU()
	assert.Nil(t, err)
	assert.Equal(t, 1280, mtu)

	firstFD := p.tunFD

	{
		assert.Nil(t, dev1.Close())
		assert.True(t, factory.devs[0].isClosed())
		assert.True(t, isFDOpen(p.tunFD))
	}

	dev2, err := p.OpenTUN(ctx, cfg1)
	assert.Nil(t, err)
	assert.Equal(t, 1, host.getRequestCount())
	assert.Equal(t, firstFD, p.tunFD)
	assert.Equal(t, 2, len(factory.devs))

	assert.Nil(t, p.SetTunnelConfiguration(ctx, pbutils.Clone(cfg1).(*mobilev1.TunnelConfiguration)))
	assert.Equal(t, 1, host.getRequestCount())

	cfg2 := pbutils.Clone(cfg1).(*mobilev1.TunnelConfiguration)
	cfg2.Dns = &mobilev1.TunnelConfiguration_DNS{
		Servers: []string{"fdee:be1d::53"},
	}

	assert.Nil(t, p.SetTunnelConfiguration(ctx, cfg2))
	assert.Equal(t, 2, host.getRequestCount())
	assert.Equal(t, uint64(2), host.requests[2].GetApplyTunnelConfiguration().Generation)
	assert.Equal(t, 3, len(factory.devs))
	assert.True(t, factory.devs[1].isClosed())
	assert.False(t, factory.devs[2].isClosed())
	assert.False(t, isFDOpen(firstFD) && firstFD != p.tunFD)

	{
		name, err := dev2.Name()
		assert.Nil(t, err)
		assert.Equal(t, "faketun", name)

		factory.devs[2].readCh <- []byte("pkt")
		bufs := [][]byte{make([]byte, 1500)}
		sizes := []int{0}
		n, err := dev2.Read(bufs, sizes, 0)
		assert.Nil(t, err)
		assert.Equal(t, 1, n)
		assert.Equal(t, []byte("pkt"), bufs[0][:sizes[0]])
	}

	{
		host.onReq = completeWithError(c, "could not apply")

		cfg3 := pbutils.Clone(cfg2).(*mobilev1.TunnelConfiguration)
		cfg3.Mtu = 1400

		assert.NotNil(t, p.SetTunnelConfiguration(ctx, cfg3))
		assert.True(t, pbutils.IsEqual(cfg2, p.cfg))
		assert.Equal(t, 3, len(factory.devs))

		host.onReq = completeApplyWithFD(c, pipeFD)
	}

	{
		assert.Nil(t, dev2.Close())

		cfg4 := pbutils.Clone(cfg2).(*mobilev1.TunnelConfiguration)
		cfg4.Mtu = 1300

		assert.Nil(t, p.SetTunnelConfiguration(ctx, cfg4))
		assert.Equal(t, 4, host.getRequestCount())
		assert.Equal(t, 3, len(factory.devs))
		assert.True(t, pbutils.IsEqual(cfg4, p.cfg))
	}

	{
		watchCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		watchCh := p.WatchNetwork(watchCtx)
		c.network.set(true, "cellular")

		select {
		case <-watchCh:
		case <-time.After(5 * time.Second):
			t.Fatal("The network watcher was not notified")
		}
	}

	lastFD := p.tunFD
	p.close()
	assert.Equal(t, -1, p.tunFD)
	assert.False(t, isFDOpen(lastFD) && lastFD != pipeFD)

	_, err = p.OpenTUN(ctx, cfg1)
	assert.NotNil(t, err)
	assert.NotNil(t, p.SetTunnelConfiguration(ctx, cfg1))

	p.close()
	assert.True(t, isFDOpen(pipeFD))
}

func TestPlatformNetworkOpenTUNFailure(t *testing.T) {
	ctx := context.Background()

	host := newFakeHost()
	c, factory := newTestClient(t, host)

	pipeFD := newTestPipeFD(t)
	host.onReq = completeApplyWithFD(c, pipeFD)

	p := newPlatformNetwork(c, "example.com")
	defer p.close()

	cfg1 := &mobilev1.TunnelConfiguration{
		Addresses: []string{"fdee:be1d::3/128"},
		Mtu:       1280,
	}

	dev, err := p.OpenTUN(ctx, cfg1)
	assert.Nil(t, err)
	defer dev.Close()

	cfg2 := pbutils.Clone(cfg1).(*mobilev1.TunnelConfiguration)
	cfg2.Mtu = 1300

	factory.mu.Lock()
	factory.openErr = errors.Errorf("could not open the TUN device")
	factory.mu.Unlock()

	assert.NotNil(t, p.SetTunnelConfiguration(ctx, cfg2))
	assert.Equal(t, 2, host.getRequestCount())
	assert.Nil(t, p.cfg)
	assert.False(t, factory.devs[0].isClosed())

	factory.mu.Lock()
	factory.openErr = nil
	factory.mu.Unlock()

	assert.Nil(t, p.SetTunnelConfiguration(ctx, cfg2))
	assert.Equal(t, 3, host.getRequestCount())
	assert.True(t, pbutils.IsEqual(cfg2, p.cfg))
	assert.Equal(t, 2, len(factory.devs))
	assert.True(t, factory.devs[0].isClosed())

	mtu, err := dev.MTU()
	assert.Nil(t, err)
	assert.Equal(t, 1300, mtu)

	assert.Nil(t, p.SetTunnelConfiguration(ctx, cfg2))
	assert.Equal(t, 3, host.getRequestCount())
}

func TestPlatformNetworkGeneration(t *testing.T) {
	host := newFakeHost()
	c, _ := newTestClient(t, host)

	cfg := &mobilev1.TunnelConfiguration{
		Addresses: []string{"fdee:be1d::3/128"},
		Mtu:       1280,
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		host.onReq = func(id uint64, req *mobilev1.PlatformRequest) {
			cancel()
		}

		p := newPlatformNetwork(c, "example.com")
		_, err := p.OpenTUN(ctx, cfg)
		assert.True(t, errors.Is(err, context.Canceled))
		p.close()
	}

	pipeFD := newTestPipeFD(t)
	host.mu.Lock()
	host.onReq = completeApplyWithFD(c, pipeFD)
	host.mu.Unlock()

	for range 2 {
		p := newPlatformNetwork(c, "example.com")

		dev, err := p.OpenTUN(context.Background(), cfg)
		assert.Nil(t, err)
		assert.Nil(t, dev.Close())
		p.close()
	}

	host.mu.Lock()
	defer host.mu.Unlock()

	assert.Equal(t, 3, len(host.requests))
	assert.Equal(t, uint64(1), host.requests[1].GetApplyTunnelConfiguration().Generation)
	assert.Equal(t, uint64(2), host.requests[2].GetApplyTunnelConfiguration().Generation)
	assert.Equal(t, uint64(3), host.requests[3].GetApplyTunnelConfiguration().Generation)
}
