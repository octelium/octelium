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

package controller

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

const (
	gatewayRouteCheckTimeout = 250 * time.Millisecond
	gatewayRouteCheckPort    = 51820
)

func (c *Controller) AddGateway(ctx context.Context, gw *userv1.Gateway) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The controller is already closed")
	}

	return c.addGateway(ctx, gw)
}

func (c *Controller) addGateway(ctx context.Context, gw *userv1.Gateway) error {
	if gw == nil {
		return errors.Errorf("Cannot add a nil Gateway")
	}

	if cur := c.getGatewayFromState(gw.Id); cur != nil {
		if proto.Equal(cur, gw) {
			zap.L().Debug("The Gateway is already added", zap.String("id", gw.Id))
			return nil
		}

		if !c.isQUIC {
			return c.updateGateway(ctx, gw)
		}

		c.removeGatewayFromState(gw.Id)
	}

	c.c.Connection.Gateways = append(c.c.Connection.Gateways, gw)

	if c.isQUIC {
		if c.quicEngine == nil {
			return errors.Errorf("The QUIC engine is not initialized")
		}
		return c.quicEngine.addGW(ctx, gw)
	}

	if c.isNetstack {
		if c.dev == nil {
			return errors.Errorf("The WireGuard device is not initialized")
		}
		if err := c.setWGDev(); err != nil {
			return err
		}

	} else {
		if err := c.SetGatewayWGPeer(gw); err != nil {
			return err
		}
	}

	return nil
}

func (c *Controller) UpdateGateway(ctx context.Context, gw *userv1.Gateway) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The controller is already closed")
	}

	return c.updateGateway(ctx, gw)
}

func (c *Controller) updateGateway(ctx context.Context, gw *userv1.Gateway) error {
	if gw == nil {
		return errors.Errorf("Cannot update a nil Gateway")
	}

	if c.isQUIC {
		return nil
	}

	for i, cur := range c.c.Connection.Gateways {
		if cur.Id == gw.Id {
			c.c.Connection.Gateways[i] = gw

			if c.isNetstack {
				if c.dev == nil {
					return errors.Errorf("The WireGuard device is not initialized")
				}
				if err := c.setWGDev(); err != nil {
					return err
				}
			} else {
				if err := c.UnsetGatewayWGPeer(cur); err != nil {
					return err
				}

				if err := c.SetGatewayWGPeer(gw); err != nil {
					return err
				}
			}

			return nil
		}
	}

	return errors.Errorf("Could not find gw %s to update", gw.Id)
}

func (c *Controller) DeleteGateway(ctx context.Context, gwID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The controller is already closed")
	}

	return c.deleteGateway(ctx, gwID)
}

func (c *Controller) deleteGateway(ctx context.Context, gwID string) error {

	if c.isQUIC {
		c.removeGatewayFromState(gwID)

		if c.quicEngine == nil {
			return nil
		}
		return c.quicEngine.deleteGWByID(gwID)
	}

	removed := c.removeGatewayFromState(gwID)
	if len(removed) == 0 {
		return nil
	}

	zap.L().Debug("Removing gw", zap.Any("gw", removed))

	if c.isNetstack {
		if c.dev == nil {
			return errors.Errorf("The WireGuard device is not initialized")
		}
		return c.setWGDev()
	}

	for _, gw := range removed {
		if err := c.UnsetGatewayWGPeer(gw); err != nil {
			return err
		}
	}

	return nil
}

func (c *Controller) getGatewayFromState(gwID string) *userv1.Gateway {
	for _, gw := range c.c.Connection.Gateways {
		if gw != nil && gw.Id == gwID {
			return gw
		}
	}

	return nil
}

func (c *Controller) removeGatewayFromState(gwID string) []*userv1.Gateway {
	var kept, removed []*userv1.Gateway
	for _, gw := range c.c.Connection.Gateways {
		if gw != nil && gw.Id == gwID {
			removed = append(removed, gw)
		} else {
			kept = append(kept, gw)
		}
	}

	if len(removed) > 0 {
		c.c.Connection.Gateways = kept
	}

	return removed
}

func (c *Controller) getGatewayEndpoint(gw *userv1.Gateway) (*net.UDPAddr, error) {
	addrs := getGatewayAddrs(gw)
	if len(addrs) == 0 {
		return nil, errors.Errorf("Gateway %s does not have a valid endpoint address", gw.Id)
	}

	selected := selectGatewayAddr(addrs, c.checkGatewayRoute)
	return &net.UDPAddr{IP: selected.AsSlice(), Port: int(gw.Wireguard.Port), Zone: selected.Zone()}, nil
}

func getGatewayAddrs(gw *userv1.Gateway) []netip.Addr {
	var ret []netip.Addr
	for _, raw := range gw.Addresses {
		addr, err := netip.ParseAddr(raw)
		if err != nil || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		ret = append(ret, addr.Unmap())
	}
	return ret
}

func selectGatewayAddr(addrs []netip.Addr, isRoutable func(netip.Addr) bool) netip.Addr {
	if len(addrs) < 2 || isRoutable == nil {
		return addrs[0]
	}

	resultCh := make(chan netip.Addr, 1)
	go func() {
		for _, addr := range addrs {
			if isRoutable(addr) {
				resultCh <- addr
				return
			}
		}
		resultCh <- addrs[0]
	}()

	timer := time.NewTimer(gatewayRouteCheckTimeout)
	defer timer.Stop()

	select {
	case addr := <-resultCh:
		return addr
	case <-timer.C:
		zap.L().Debug("Timed out checking the Gateway routes. Using the first advertised address")
		return addrs[0]
	}
}

func isGatewayAddrRoutable(dst netip.Addr) bool {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, gatewayRouteCheckPort)))
	if err != nil {
		zap.L().Debug("No route to Gateway address", zap.String("addr", dst.String()), zap.Error(err))
		return false
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return false
	}

	return isGatewaySrcAddrUsable(local.AddrPort().Addr().Unmap(), dst)
}

func isGatewaySrcAddrUsable(src, dst netip.Addr) bool {
	if !src.IsValid() || src.IsUnspecified() || src.IsLinkLocalUnicast() {
		return false
	}
	if src.IsLoopback() {
		return dst.IsLoopback()
	}
	if src.Is6() && src.IsPrivate() {
		return dst.IsPrivate()
	}
	return true
}
