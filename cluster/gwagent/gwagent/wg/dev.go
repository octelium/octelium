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

package wg

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const devName = "octelium-wg"
const fwChain = "octelium-wg-fw"
const inputChain = "octelium-wg-in"
const tableFilter = "filter"

type wgLink struct {
	attr     netlink.LinkAttrs
	linkType string
}

func (w wgLink) Attrs() *netlink.LinkAttrs {
	return &w.attr
}

func (w wgLink) Type() string {
	return w.linkType
}

func doCleanupDev() error {

	zap.L().Debug("Cleaning up dev iptables rules")
	if ipt, err := newIPTables(); err == nil {
		ipt.OnDelete(true, true)
	}

	zap.L().Debug("Removing wg dev if exists")
	l, err := netlink.LinkByName(devName)
	if err != nil {
		_, ok := err.(netlink.LinkNotFoundError)
		if ok {
			return nil
		}

		return err
	}

	if err := netlink.LinkDel(l); err != nil {
		return err
	}
	zap.L().Debug("Successfully cleaned up existing WireGuard dev")
	return nil
}

func (wg *Wg) initializeDev(gw *corev1.Gateway, cc *corev1.ClusterConfig) error {
	name := devName

	zap.L().Debug("Initializing dev with gw", zap.String("gw", gw.Metadata.Name))

	if err := doCleanupDev(); err != nil {
		zap.L().Debug("Could not doCleanupDev. Continuing anyway...", zap.Error(err))
	}

	hasV4 := gw.Status.Cidr.V4 != ""
	hasV6 := gw.Status.Cidr.V6 != ""

	// netGo := gw.Spec.Cidr.ToGo()

	gwIP, err := vutils.GetDualStackIPByIndex(gw.Status.Cidr, 1)
	if err != nil {
		return err
	}

	/*
		if wg.userspaceMode {
			if err := wg.createDevUserspace(name, ucorev1.ToClusterConfig(cc).GetDevMTUWireGuard()); err != nil {
				return err
			}
		}

	*/

	{

		link := wgLink{attr: netlink.NewLinkAttrs(), linkType: "wireguard"}
		link.attr.Name = name
		link.attr.MTU = ucorev1.ToClusterConfig(cc).GetDevMTUWireGuard()

		if err := netlink.LinkAdd(link); err != nil {
			zap.L().Warn("Could not add wireguard link. Fallbacking to TUN mode", zap.Error(err))
			if err := wg.createDevUserspace(name, ucorev1.ToClusterConfig(cc).GetDevMTUWireGuard()); err != nil {
				return err
			}
			zap.L().Info("Started a WireGuard TUN dev")
		} else {
			zap.L().Info("WireGuard kernel dev successfully added")
		}
	}

	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	if hasV4 {
		if err := netlink.AddrAdd(l, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   net.ParseIP(gwIP.Ipv4),
				Mask: net.CIDRMask(32, 32),
			},
		}); err != nil {
			return err
		}

	}

	if hasV6 {
		if err := netlink.AddrAdd(l, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   net.ParseIP(gwIP.Ipv6),
				Mask: net.CIDRMask(128, 128),
			},
		}); err != nil {
			return err
		}

	}

	if err := netlink.LinkSetUp(l); err != nil {
		return err
	}

	if hasV4 {
		_, routeNet, _ := net.ParseCIDR(cc.Status.Network.WgConnSubnet.V4)

		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       routeNet,
		}); err != nil {
			return err
		}
	}

	if hasV6 {
		_, routeNet, _ := net.ParseCIDR(cc.Status.Network.WgConnSubnet.V6)

		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       routeNet,
		}); err != nil {
			return err
		}
	}

	ipt, err := newIPTables()
	if err != nil {
		return err
	}

	defaultLink, err := getDefaultLink()
	if err != nil {
		return err
	}

	if err := ipt.OnAdd(gw, cc, defaultLink.Attrs().Name); err != nil {
		return err
	}

	return nil
}

func (wg *Wg) createDevUserspace(interfaceName string, mtu int) error {

	logLevel := device.LogLevelError
	tundev, err := tun.CreateTUN(interfaceName, mtu)
	if err != nil {
		return err
	}

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	fileUAPI, err := ipc.UAPIOpen(interfaceName)
	if err != nil {
		return err
	}

	device := device.NewDevice(tundev, conn.NewDefaultBind(), logger)

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	go func() {
		select {
		case <-term:
		case <-errs:
		case <-device.Wait():
		}

		zap.L().Debug("Closing the userspace wg dev")

		uapi.Close()
		device.Close()
	}()

	return nil
}

func getDefaultLink() (netlink.Link, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("Found routes in gw host", zap.Any("routes", routes))

	for _, route := range routes {
		zap.L().Debug("Checking route", zap.Any("route", route))
		if route.Dst == nil || route.Dst.String() == "0.0.0.0/0" || route.Dst.String() == "::/0" {
			zap.L().Debug("found default route link", zap.Any("idx", route.LinkIndex))
			return netlink.LinkByIndex(route.LinkIndex)
		}
	}
	return nil, errors.Errorf("Could not find the default network interface")
}

type iptablesCtl struct {
	iptv4 *iptables.IPTables
	iptv6 *iptables.IPTables
}

func newIPTables() (*iptablesCtl, error) {
	iptv4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	iptv6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return nil, err
	}

	return &iptablesCtl{iptv4: iptv4, iptv6: iptv6}, nil
}

// ugly solution to mitigate `iptables: Resource temporarily unavailable` error
var xtablesMtx sync.Mutex

func (i *iptablesCtl) OnAdd(gw *corev1.Gateway, cc *corev1.ClusterConfig, defaultLink string) error {
	xtablesMtx.Lock()
	defer xtablesMtx.Unlock()

	connSubnet := cc.Status.Network.WgConnSubnet
	gwSubnet := gw.Status.Cidr

	hasV4 := gw.Status.Cidr.V4 != ""
	hasV6 := gw.Status.Cidr.V6 != ""

	fwChain := fmt.Sprintf("%s-fw", devName)
	inputChain := fmt.Sprintf("%s-in", devName)

	doCreateChain := func(table, chain string) error {
		if hasV4 {
			if err := i.iptv4.NewChain(table, chain); err != nil {
				return err
			}
		}

		if hasV6 {
			if err := i.iptv6.NewChain(table, chain); err != nil {
				return err
			}
		}

		return nil
	}

	if err := doCreateChain(tableFilter, fwChain); err != nil {
		return err
	}

	if err := doCreateChain(tableFilter, inputChain); err != nil {
		return err
	}

	ruleBlockGWOut := func(connSubnet, gwIPRange string) []string {
		return []string{
			"-i", devName,
			"-s", connSubnet,
			"-d", gwIPRange,
			"-j", "DROP",
		}
	}

	ruleAllowSvc := func(connSubnet, svcSubnet string) []string {
		return []string{
			"-i", devName,
			"-s", connSubnet,
			"-d", svcSubnet,
			"-j", "ACCEPT",
		}
	}

	ruleICMP := func(connSubnet, svcSubnet string) []string {
		return []string{
			"-i", devName,
			"-s", connSubnet,
			"-d", svcSubnet,
			"-p", "icmp",
			"-j", "ACCEPT",
		}
	}

	defaultRule := func(connSubnet string) []string {
		return []string{
			"-i", devName,
			"-s", connSubnet,
			"-j", "DROP",
		}
	}

	// Allow Connections to ping Services

	if hasV4 {
		if err := i.iptv4.Append(tableFilter, fwChain,
			ruleICMP(connSubnet.V4, gwSubnet.V4)...); err != nil {
			return err
		}
		if err := i.iptv4.Append(tableFilter, inputChain,
			ruleICMP(connSubnet.V4, gwSubnet.V4)...); err != nil {
			return err
		}
	}

	if hasV6 {
		if err := i.iptv6.Append(tableFilter, fwChain,
			ruleICMP(connSubnet.V6, gwSubnet.V6)...); err != nil {
			return err
		}
		if err := i.iptv6.Append(tableFilter, inputChain,
			ruleICMP(connSubnet.V6, gwSubnet.V6)...); err != nil {
			return err
		}
	}

	// Block Connections from accessing Gateway's applications
	if hasV4 {
		// First 16 addrs are reserved to be used by the WG, QUIC, etc... devices
		gwRange := &net.IPNet{
			IP:   umetav1.ToDualStackNetwork(gw.Status.Cidr).ToGo().V4.IP,
			Mask: net.CIDRMask(28, 32),
		}

		if err := i.iptv4.Append(tableFilter, inputChain,
			ruleBlockGWOut(connSubnet.V4, gwRange.String())...); err != nil {
			return err
		}
		if err := i.iptv4.Append(tableFilter, fwChain,
			ruleBlockGWOut(connSubnet.V4, gwRange.String())...); err != nil {
			return err
		}
	}

	if hasV6 {

		gwRange := &net.IPNet{
			IP:   umetav1.ToDualStackNetwork(gw.Status.Cidr).ToGo().V6.IP,
			Mask: net.CIDRMask(124, 128),
		}

		if err := i.iptv6.Append(tableFilter, inputChain,
			ruleBlockGWOut(connSubnet.V6, gwRange.String())...); err != nil {
			return err
		}
		if err := i.iptv6.Append(tableFilter, fwChain,
			ruleBlockGWOut(connSubnet.V6, gwRange.String())...); err != nil {
			return err
		}
	}

	// Allow Connections to access Services
	if hasV4 {
		if err := i.iptv4.Append(tableFilter, fwChain,
			ruleAllowSvc(connSubnet.V4, gwSubnet.V4)...); err != nil {
			return err
		}
	}

	if hasV6 {
		if err := i.iptv6.Append(tableFilter, fwChain,
			ruleAllowSvc(connSubnet.V6, gwSubnet.V6)...); err != nil {
			return err
		}
	}

	// Drop everything coming from Connection subnet

	if hasV4 {
		if err := i.iptv4.Append(tableFilter, fwChain,
			defaultRule(connSubnet.V4)...); err != nil {
			return err
		}
		if err := i.iptv4.Append(tableFilter, inputChain,
			defaultRule(connSubnet.V4)...); err != nil {
			return err
		}
	}

	if hasV6 {
		if err := i.iptv6.Append(tableFilter, fwChain,
			defaultRule(connSubnet.V6)...); err != nil {
			return err
		}
		if err := i.iptv6.Append(tableFilter, inputChain,
			defaultRule(connSubnet.V6)...); err != nil {
			return err
		}
	}

	if hasV4 {
		if err := i.iptv4.Insert(tableFilter, "FORWARD", 1, "-j", fwChain); err != nil {
			return err
		}
		if err := i.iptv4.Insert(tableFilter, "INPUT", 1, "-j", inputChain); err != nil {
			return err
		}
	}

	if hasV6 {
		if err := i.iptv6.Insert(tableFilter, "FORWARD", 1, "-j", fwChain); err != nil {
			return err
		}
		if err := i.iptv6.Insert(tableFilter, "INPUT", 1, "-j", inputChain); err != nil {
			return err
		}
	}

	return nil
}

func (i *iptablesCtl) OnDelete(hasV4, hasV6 bool) error {
	xtablesMtx.Lock()
	defer xtablesMtx.Unlock()

	var err error

	if hasV4 {
		err = i.iptv4.Delete(tableFilter, "FORWARD", "-j", fwChain)
		err = i.iptv4.Delete(tableFilter, "INPUT", "-j", inputChain)
	}

	if hasV6 {
		err = i.iptv6.Delete(tableFilter, "FORWARD", "-j", fwChain)
		err = i.iptv6.Delete(tableFilter, "INPUT", "-j", inputChain)
	}

	doDeleteChain := func(table, chain string) error {

		if hasV4 {
			err = i.iptv4.ClearChain(table, chain)
			err = i.iptv4.DeleteChain(table, chain)
		}

		if hasV6 {
			err = i.iptv6.ClearChain(table, chain)
			err = i.iptv6.DeleteChain(table, chain)
		}

		return nil
	}

	doDeleteChain(tableFilter, fwChain)
	doDeleteChain(tableFilter, inputChain)

	return err
}
