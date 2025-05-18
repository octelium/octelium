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

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (s *Server) setExternalIP(ctx context.Context) error {

	if err := s.setExternalIPFromNode(ctx); err != nil {
		zap.S().Debug("Could not fin the node external IP via k8s node resource")
		if err := s.setExternalIPFromDev(); err != nil {
			return errors.Errorf("Could not get external node IP from devices: %+v", err)
		}
	}

	return nil
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

			s.publicIPs = append(s.publicIPs, nodeAddr.String())
			return nil
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
				s.publicIPs = append(s.publicIPs, addr.IP.String())
				zap.S().Debugf("Found IPv4 public address %s", addr.IP.String())
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
				s.publicIPs = append(s.publicIPs, addr.IP.String())
				zap.S().Debugf("Found IPv6 public address %s", addr.IP.String())
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
