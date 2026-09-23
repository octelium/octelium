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
	"sync"
	"time"

	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/tun"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const platformRequestTimeout = 30 * time.Second

type platformResponse struct {
	resp  *mobilev1.PlatformResponse
	tunFD int
}

func (r *platformResponse) close() {
	if r.tunFD < 0 {
		return
	}

	if err := closeFD(r.tunFD); err != nil {
		zap.L().Debug("Could not close the TUN file descriptor", zap.Error(err))
	}
	r.tunFD = -1
}

type requestMap struct {
	mu     sync.Mutex
	nextID uint64
	reqMap map[uint64]chan *platformResponse
}

func newRequestMap() *requestMap {
	return &requestMap{
		reqMap: make(map[uint64]chan *platformResponse),
	}
}

func (m *requestMap) add() (uint64, chan *platformResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextID++
	ret := make(chan *platformResponse, 1)
	m.reqMap[m.nextID] = ret

	return m.nextID, ret
}

func (m *requestMap) delete(id uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.reqMap, id)
}

func (m *requestMap) deliver(id uint64, resp *platformResponse) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	ch, ok := m.reqMap[id]
	if !ok {
		return false
	}

	delete(m.reqMap, id)
	ch <- resp

	return true
}

func (c *Client) doPlatformRequest(ctx context.Context,
	req *mobilev1.PlatformRequest) (*platformResponse, error) {
	id, ch := c.requests.add()
	defer func() {
		c.requests.delete(id)

		select {
		case resp := <-ch:
			resp.close()
		default:
		}
	}()

	go c.host.SendPlatformRequest(id, req)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(platformRequestTimeout):
		return nil, errors.Errorf("Timed out waiting for the platform to complete the request")
	case resp := <-ch:
		if resp.resp.GetError() != nil {
			resp.close()
			return nil, errors.Errorf("The platform could not complete the request: %s",
				resp.resp.GetError().GetMessage())
		}

		return resp, nil
	}
}

func (c *Client) CompleteRequest(id uint64, respBytes []byte) error {
	resp := &mobilev1.PlatformResponse{}
	if err := pbutils.Unmarshal(respBytes, resp); err != nil {
		return status.Errorf(codes.InvalidArgument, "Could not unmarshal the platform response: %s", err)
	}

	ret := &platformResponse{
		resp:  resp,
		tunFD: -1,
	}

	if resp.GetApplyTunnelConfiguration() != nil {
		tunFD, err := c.getTUNFD(resp.GetApplyTunnelConfiguration())
		if err != nil {
			ret.resp = &mobilev1.PlatformResponse{
				Type: &mobilev1.PlatformResponse_Error_{
					Error: &mobilev1.PlatformResponse_Error{
						Message: err.Error(),
					},
				},
			}
		} else {
			ret.tunFD = tunFD
		}
	}

	if !c.requests.deliver(id, ret) {
		ret.close()
		return status.Errorf(codes.NotFound, "Unknown platform request: %d", id)
	}

	return nil
}

func (c *Client) getTUNFD(resp *mobilev1.PlatformResponse_ApplyTunnelConfiguration) (int, error) {
	if resp.TunFD == nil {
		if c.cfg.Platform != mobilev1.Config_IOS {
			return -1, errors.Errorf("The TUN file descriptor is not set")
		}

		fd, err := findTUNFD()
		if err != nil {
			return -1, err
		}

		return dupFD(fd)
	}

	if resp.GetTunFD() < 0 {
		return -1, errors.Errorf("Invalid TUN file descriptor: %d", resp.GetTunFD())
	}

	return dupFD(int(resp.GetTunFD()))
}

type platformNetwork struct {
	c      *Client
	domain string

	mu       sync.Mutex
	gen      uint64
	cfg      *mobilev1.TunnelConfiguration
	tunFD    int
	active   *platformTUN
	isClosed bool
}

func newPlatformNetwork(c *Client, domain string) *platformNetwork {
	return &platformNetwork{
		c:      c,
		domain: domain,
		tunFD:  -1,
	}
}

func (p *platformNetwork) OpenTUN(ctx context.Context,
	cfg *mobilev1.TunnelConfiguration) (tun.Device, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isClosed {
		return nil, errors.Errorf("The platform network is closed")
	}

	if p.tunFD < 0 || !pbutils.IsEqual(p.cfg, cfg) {
		if err := p.apply(ctx, cfg); err != nil {
			return nil, err
		}
	}

	dev, err := p.c.openTUN(p.tunFD)
	if err != nil {
		return nil, err
	}

	p.active = newPlatformTUN(dev, int(cfg.Mtu))

	return p.active, nil
}

func (p *platformNetwork) SetTunnelConfiguration(ctx context.Context,
	cfg *mobilev1.TunnelConfiguration) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.isClosed {
		return errors.Errorf("The platform network is closed")
	}

	if p.tunFD >= 0 && pbutils.IsEqual(p.cfg, cfg) {
		return nil
	}

	if err := p.apply(ctx, cfg); err != nil {
		return err
	}

	if p.active == nil || p.active.getIsClosed() {
		return nil
	}

	dev, err := p.c.openTUN(p.tunFD)
	if err != nil {
		p.cfg = nil
		return err
	}

	p.active.swap(dev, int(cfg.Mtu))

	return nil
}

func (p *platformNetwork) apply(ctx context.Context, cfg *mobilev1.TunnelConfiguration) error {
	p.gen++

	zap.L().Debug("Applying the tunnel configuration",
		zap.String("domain", p.domain), zap.Uint64("generation", p.gen), zap.Any("cfg", cfg))

	resp, err := p.c.doPlatformRequest(ctx, &mobilev1.PlatformRequest{
		Type: &mobilev1.PlatformRequest_ApplyTunnelConfiguration_{
			ApplyTunnelConfiguration: &mobilev1.PlatformRequest_ApplyTunnelConfiguration{
				Domain:        p.domain,
				Generation:    p.gen,
				Configuration: cfg,
			},
		},
	})
	if err != nil {
		return err
	}

	if resp.tunFD < 0 {
		return errors.Errorf("The platform did not provide the TUN file descriptor")
	}

	if p.tunFD >= 0 {
		if err := closeFD(p.tunFD); err != nil {
			zap.L().Debug("Could not close the previous TUN file descriptor", zap.Error(err))
		}
	}

	p.tunFD = resp.tunFD
	p.cfg = pbutils.Clone(cfg).(*mobilev1.TunnelConfiguration)

	return nil
}

func (p *platformNetwork) WatchNetwork(ctx context.Context) <-chan struct{} {
	return p.c.network.watch(ctx)
}

func (p *platformNetwork) close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.isClosed = true

	if p.tunFD >= 0 {
		if err := closeFD(p.tunFD); err != nil {
			zap.L().Debug("Could not close the TUN file descriptor", zap.Error(err))
		}
		p.tunFD = -1
	}
}
