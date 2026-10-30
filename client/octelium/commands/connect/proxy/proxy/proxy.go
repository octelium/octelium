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
	"net"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/octelium/octelium/client/octelium/commands/connect/proxy/proxy/userspace"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type Controller struct {
	c             *cliconfigv1.Connection
	proxies       []*proxy
	ipv4Supported bool
	ipv6Supported bool

	mu       sync.Mutex
	isClosed bool
	goNetCtl ccommon.GoNetCtl
}

type goNet interface {
	ListenTCP(addr *net.TCPAddr) (*gonet.TCPListener, error)
}

func NewController(ctx context.Context, c *cliconfigv1.Connection, goNetCtl ccommon.GoNetCtl) (*Controller, error) {
	ipv4Supported := c.GetPreferences().GetL3Mode() == cliconfigv1.Connection_Preferences_BOTH ||
		c.GetPreferences().GetL3Mode() == cliconfigv1.Connection_Preferences_V4
	ipv6Supported := c.GetPreferences().GetL3Mode() == cliconfigv1.Connection_Preferences_BOTH ||
		c.GetPreferences().GetL3Mode() == cliconfigv1.Connection_Preferences_V6

	ret := &Controller{
		c:             c,
		ipv4Supported: ipv4Supported,
		ipv6Supported: ipv6Supported,
		goNetCtl:      goNetCtl,
	}

	return ret, nil
}

func (c *Controller) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The proxy controller is already closed")
	}

	zap.S().Debugf("Starting proxy controller")

	sOpts := c.c.GetConnection().GetServiceOptions()

	if sOpts == nil {
		return nil
	}

	for _, svc := range sOpts.GetServices() {
		if err := c.doAddService(ctx, svc); err != nil {
			return err
		}
	}

	zap.S().Debugf("Started proxy controller")

	return nil
}

func (c *Controller) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return nil
	}
	c.isClosed = true

	for _, c := range c.proxies {
		c.close()
	}

	return nil
}

func (c *Controller) doAddService(ctx context.Context, svc *userv1.HostedService) error {
	if svc.GetName() == "" {
		return errors.Errorf("Cannot add a hosted Service without a name")
	}
	if cur := c.getServiceProxy(svc); cur != nil && proto.Equal(cur.svc, svc) {
		return nil
	}

	if err := c.addProxy(ctx, svc); err != nil {
		return err
	}

	return nil
}

func (c *Controller) addProxy(ctx context.Context, listener *userv1.HostedService) error {
	if listener.GetUpstream() == nil || listener.GetAddress() == nil {
		return nil
	}

	zap.S().Debugf("adding proxy for listener: %+v", listener)
	p, err := c.newProxy(listener, listener.GetAddress(), c.goNetCtl, c.ipv4Supported, c.ipv6Supported)
	if err != nil {
		return err
	}
	if p == nil {
		return nil
	}

	if err := p.start(ctx); err != nil {
		p.close()
		return err
	}
	c.proxies = append(c.proxies, p)
	return nil
}

func (c *Controller) AddService(ctx context.Context, svc *userv1.HostedService) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The proxy controller is already closed")
	}

	return c.doAddService(ctx, svc)
}

func (c *Controller) DeleteService(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return nil
	}
	if name == "" {
		return errors.Errorf("Cannot delete a hosted Service without a name")
	}

	return c.deleteService(name)
}

func (c *Controller) deleteService(name string) error {

	for idx := 0; idx < len(c.proxies); idx++ {
		if c.proxies[idx].svc.GetName() == name {
			c.proxies[idx].close()
			c.proxies = append(c.proxies[:idx], c.proxies[idx+1:]...)
			idx--
		}

	}

	return nil
}

func (c *Controller) deleteProxy(p *proxy) {
	zap.S().Debugf("closing proxy: %+v", p)
	p.close()
	zap.S().Debugf("proxy closed")
	for i := len(c.proxies) - 1; i >= 0; i-- {
		if c.proxies[i] == p {
			zap.S().Debugf("removing proxy %+v", p)
			c.proxies = append(c.proxies[:i], c.proxies[i+1:]...)
		}
	}
}

func (c *Controller) UpdateService(ctx context.Context, svc *userv1.HostedService) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The proxy controller is already closed")
	}

	return c.updateService(ctx, svc)
}

func (c *Controller) updateService(ctx context.Context, svc *userv1.HostedService) error {
	if svc.GetName() == "" {
		return errors.Errorf("Cannot update a hosted Service without a name")
	}

	zap.S().Debugf("Updating svc: %+v", svc)

	if cur := c.getServiceProxy(svc); cur != nil {
		if proto.Equal(cur.svc, svc) {
			zap.S().Debugf("Hoste Service: %+v has not changed. Nothing to be done.", svc)
			return nil
		}

		if cur.updateUpstream(svc) {
			zap.S().Debugf("Updated the upstream of hosted Service: %+v", svc)
			return nil
		}

		zap.S().Debugf("Replacing listener %+v with %+v", cur.svc, svc)
		zap.S().Debugf("Removing listener %+v", cur.svc)
		c.deleteProxy(cur)
		zap.S().Debugf("waiting 100 ms for port to be available")
		time.Sleep(100 * time.Millisecond)
		zap.S().Debugf("Adding replacement listener %+v", svc)
		if err := c.addProxy(ctx, svc); err != nil {
			return err
		}
	} else {
		zap.S().Debugf("Add a new proxy for Service: %+v", svc)
		if err := c.addProxy(ctx, svc); err != nil {
			return err
		}
	}

	zap.S().Debugf("Successfully updated hosted Service: %+v", svc)

	return nil
}

func (c *Controller) getServiceProxy(svc *userv1.HostedService) *proxy {

	for _, p := range c.proxies {
		if p.svc.GetName() == svc.GetName() {
			return p
		}
	}

	return nil
}

type proxy struct {
	svc *userv1.HostedService

	p proxyImlementor
}

type proxyImlementor interface {
	Start(ctx context.Context) error
	Close() error
	UpdateUpstream(upstream userspace.OptsUpstream) error
}

func (c *Controller) newProxy(
	svc *userv1.HostedService,
	addr *metav1.DualStackIP,
	goNetCtl ccommon.GoNetCtl, ipv4Supported, ipv6Supported bool) (*proxy, error) {

	if svc.GetMode() == userv1.HostedService_MODE_ESSH &&
		c.c.GetPreferences().GetESSH().GetIsEnabled() {
		zap.S().Debugf("Service %s is served by the eSSH server. Skipping the proxy", svc.GetName())
		return nil, nil
	}

	return &proxy{
		svc: svc,
		p:   userspace.NewProxyFromServiceListener(svc, addr, goNetCtl, ipv4Supported, ipv6Supported),
	}, nil
}

func (p *proxy) start(ctx context.Context) error {
	if p.p == nil {
		return nil
	}
	return p.p.Start(ctx)
}

func (p *proxy) close() error {
	if p.p == nil {
		return nil
	}
	return p.p.Close()
}

func (p *proxy) updateUpstream(svc *userv1.HostedService) bool {
	if p.p == nil || svc.GetUpstream() == nil || !isUpstreamOnlyChange(p.svc, svc) {
		return false
	}

	if err := p.p.UpdateUpstream(userspace.OptsUpstream{
		Address: svc.GetUpstream().GetHost(),
		Port:    uint32(svc.GetUpstream().GetPort()),
	}); err != nil {
		zap.S().Debugf("Could not update the upstream of hosted Service %s in place: %+v", svc.GetName(), err)
		return false
	}

	p.svc = svc
	return true
}

func isUpstreamOnlyChange(cur, svc *userv1.HostedService) bool {
	curSvc := proto.Clone(cur).(*userv1.HostedService)
	newSvc := proto.Clone(svc).(*userv1.HostedService)
	curSvc.Upstream = nil
	newSvc.Upstream = nil

	return proto.Equal(curSvc, newSvc)
}
