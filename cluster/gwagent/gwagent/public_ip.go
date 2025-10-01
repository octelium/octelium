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

package gwagent

import (
	"context"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *Server) setNodePublicIPs(ctx context.Context) error {

	node := s.node

	if nIP, ok := node.Annotations["octelium.com/public-ip-test"]; ok {
		s.publicIPs = append(s.publicIPs, nIP)
		return nil
	}

	if ipv4, ok := node.Annotations["octelium.com/public-ipv4"]; ok {
		s.doAppendPublicIPAddr(ipv4)
	}

	if ipv6, ok := node.Annotations["octelium.com/public-ipv6"]; ok {
		s.doAppendPublicIPAddr(ipv6)
	}

	if len(s.publicIPs) == 0 {
		if nIP, ok := node.Annotations["octelium.com/public-ip"]; ok {
			s.doAppendPublicIPAddr(nIP)
		}
	}

	if len(s.publicIPs) == 0 {
		if err := s.setExternalIPFromNode(ctx); err != nil {
			zap.L().Debug("Could not find the node public IP addr via k8s node", zap.Error(err))

		}
	}

	if len(s.publicIPs) == 0 {
		if err := s.setExternalIPFromDev(); err != nil {
			zap.L().Debug("Could not get public IP addr from dev", zap.Error(err))
		}
	}

	if len(s.publicIPs) == 0 {
		if err := s.setPublicIPAddrsFromPublicAPIs(ctx); err != nil {
			zap.L().Warn("Could not get node public IP addrs from public APIs", zap.Error(err))
		}
	}

	if len(s.publicIPs) == 0 {
		return errors.Errorf("Could not obtain the node public IP addrs")
	}

	zap.L().Debug("Set node public IP addresses", zap.Strings("addrs", s.publicIPs))

	return nil
}

func (s *Server) doAppendPublicIPAddr(addr string) {

	addrNet := net.ParseIP(strings.TrimSpace(addr))
	if addrNet == nil {
		return
	}

	if !doIsPublicIP(addrNet) {
		return
	}

	addr = addrNet.String()

	if !slices.Contains(s.publicIPs, addr) {
		zap.L().Debug("Adding public IP addr for node", zap.String("addr", addr))
		s.publicIPs = append(s.publicIPs, addr)
	}
}

func (s *Server) setExternalIPFromNode(ctx context.Context) error {
	node, err := s.k8sC.CoreV1().Nodes().Get(ctx, s.nodeName, k8smetav1.GetOptions{})
	if err != nil {
		return err
	}

	for _, addr := range node.Status.Addresses {
		if addr.Type == "ExternalIP" {
			nodeAddr := net.ParseIP(addr.Address)
			if nodeAddr == nil {
				continue
			}

			s.doAppendPublicIPAddr(nodeAddr.String())
		}
	}

	return errors.Errorf("Could not get external IP from node k8s resource")
}

func (s *Server) setExternalIPFromDev() error {

	linkName, err := getDefaultInterface()
	if err != nil {
		return err
	}

	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return err
	}

	{
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return err
		}

		for _, addr := range addrs {
			if addr.Scope == int(netlink.SCOPE_UNIVERSE) {
				s.doAppendPublicIPAddr(addr.IP.String())
				break
			}
		}
	}

	{
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return err
		}

		for _, addr := range addrs {
			if addr.Scope == int(netlink.SCOPE_UNIVERSE) {
				s.doAppendPublicIPAddr(addr.IP.String())
				break
			}
		}
	}

	return nil
}

func getDefaultInterface() (string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return "", err
	}

	for _, link := range links {

		{
			routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
			if err != nil {
				return "", err
			}

			for _, route := range routes {
				if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" {
					zap.S().Debugf("Found default dev %s", link.Attrs().Name)
					return link.Attrs().Name, nil
				}
			}
		}
		{
			routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
			if err != nil {
				return "", err
			}

			for _, route := range routes {
				if route.Dst == nil || route.Dst.String() == "::/0" {
					zap.S().Debugf("Found default dev %s", link.Attrs().Name)
					return link.Attrs().Name, nil
				}
			}
		}
	}

	return "", errors.Errorf("Could not find default route")
}

func doIsPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}

	return !ip.IsPrivate()
}

func (s *Server) setPublicIPAddrsFromPublicAPIs(ctx context.Context) error {

	publicAPIs := []string{
		"https://checkip.amazonaws.com",
		"https://api.ipify.org",
		"https://ifconfig.me",
	}

	for _, publicAPI := range publicAPIs {
		if err := s.doSetPublicIPAddrFromAPI(ctx, publicAPI, "tcp4"); err == nil {
			if len(s.publicIPs) > 0 {
				return nil
			}
		}
	}

	if len(s.publicIPs) > 0 {
		return nil
	}

	for _, publicAPI := range publicAPIs {
		if err := s.doSetPublicIPAddrFromAPI(ctx, publicAPI, "tcp6"); err == nil {
			if len(s.publicIPs) > 0 {
				return nil
			}
		}
	}

	return nil
}

func (s *Server) doSetPublicIPAddrFromAPI(ctx context.Context, apiURL string, networkType string) error {

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: false,
	}

	resp, err := resty.New().SetDebug(ldflags.IsDev()).SetTimeout(5 * time.Second).SetTransport(&http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, networkType, addr)
		},
	}).
		R().
		SetContext(ctx).
		Get(apiURL)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return errors.Errorf("Could not get public IP addr via: %s", apiURL)
	}

	s.doAppendPublicIPAddr(string(resp.Body()))

	return nil
}
