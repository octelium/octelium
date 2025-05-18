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

package quicv0

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

const devName = "octelium-quic"
const tunPacketOffset = 0

const (
	IPv4offsetSrc = 12
	IPv4offsetDst = IPv4offsetSrc + net.IPv4len
)

const (
	IPv6offsetSrc = 8
	IPv6offsetDst = IPv6offsetSrc + net.IPv6len
)

var quicV0TunPath = "/dev/net/oct-quickv001"

func createTUN(name string, mtu int) (tun.Device, error) {
	nfd, err := unix.Open(quicV0TunPath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		zap.L().Error("Could not open QUIC tun dev", zap.String("path", quicV0TunPath), zap.Error(err))
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}

	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	err = unix.IoctlIfreq(nfd, unix.TUNSETIFF, ifr)
	if err != nil {
		return nil, err
	}

	err = unix.SetNonblock(nfd, true)
	if err != nil {
		unix.Close(nfd)
		return nil, err
	}

	fd := os.NewFile(uintptr(nfd), quicV0TunPath)
	return tun.CreateTUNFromFile(fd, mtu)
}

func (s *QUICController) createTunDev(ctx context.Context, gw *corev1.Gateway, cc *corev1.ClusterConfig) error {
	var err error

	zap.L().Debug("Creating tun dev", zap.Int("mtu", ucorev1.ToClusterConfig(cc).GetDevMTUQUIV0()))

	if ldflags.IsTest() {
		quicV0TunPath = "/dev/net/tun"
	} else {
		os.Remove(quicV0TunPath)
	}

	cmds := []string{
		"mkdir -p /dev/net",
		fmt.Sprintf("mknod %s c 10 200", quicV0TunPath),
		fmt.Sprintf("chmod 600 %s", quicV0TunPath),
	}

	for _, cmd := range cmds {
		if err := exec.Command("sh", "-c", cmd).Run(); err != nil {
			zap.L().Error("Could not mknod quicV0 device", zap.Error(err))
		}
	}

	s.tundev, err = createTUN(devName, ucorev1.ToClusterConfig(cc).GetDevMTUQUIV0())
	if err != nil {
		return errors.Errorf("Could not create tun dev: %+v", err)
	}

	l, err := netlink.LinkByName(devName)
	if err != nil {
		return errors.Errorf("Could not get dev by name: %+v", err)
	}

	hasV4 := gw.Status.Cidr.V4 != ""
	hasV6 := gw.Status.Cidr.V6 != ""

	gwIP, err := vutils.GetDualStackIPByIndex(gw.Status.Cidr, 2)
	if err != nil {
		return err
	}

	zap.L().Debug("Adding QUICv0 tun dev addrs")

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

	zap.L().Debug("Setting QUICv0 dev up")

	if err := netlink.LinkSetUp(l); err != nil {
		return errors.Errorf("Could not set dev up: %+v", err)
	}

	zap.L().Debug("Setting QUICv0 dev routes")

	if hasV4 {
		_, routeNet, _ := net.ParseCIDR(cc.Status.Network.QuicConnSubnet.V4)

		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       routeNet,
		}); err != nil {
			return err
		}
	}

	if hasV6 {
		_, routeNet, _ := net.ParseCIDR(cc.Status.Network.QuicConnSubnet.V6)

		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Scope:     netlink.SCOPE_LINK,
			Dst:       routeNet,
		}); err != nil {
			return err
		}
	}

	zap.L().Debug("QUICv0 tun dev successfully created")

	return nil
}

func (s *QUICController) runTunDev(ctx context.Context) error {

	go s.startTunRecvFromDevLoop(ctx)
	go s.startTunSendToDevLoop(ctx)
	go s.startProcessPacketLoop(ctx)

	return nil
}

func (s *QUICController) startTunSendToDevLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-s.tunWriteCh:

			buffs := make([][]byte, 1)
			buffs[0] = pkt[:]

			if _, err := s.tundev.Write(buffs, 0); err != nil {
				zap.L().Error("Could not write to QUICv0 tun...", zap.Error(err), zap.Int("len", len(pkt[:])))
			}
		}
	}
}

func (s *QUICController) startProcessPacketLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-s.tunReadCh:
			s.doProcessTunPacket(pkt)
		}
	}
}

func (s *QUICController) doProcessTunPacket(pkt []byte) {

	s.lookupMap.RLock()
	defer s.lookupMap.RUnlock()

	dctx := s.getDctxFromTunPacket(pkt)
	if dctx == nil {
		return
	}

	dctx.sendCh <- pkt
}

func (s *QUICController) getDctxFromTunPacket(pkt []byte) *dctx {

	lenPkt := len(pkt)

	if lenPkt <= ipv4.HeaderLen || lenPkt > s.mtu {
		zap.L().Debug("Invalid pkt len from tun", zap.Int("len", lenPkt))
		return nil
	}

	var dst netip.Addr

	switch pkt[0] >> 4 {
	case ipv4.Version:
		var dstBytes [4]byte
		copy(dstBytes[:], pkt[IPv4offsetDst:IPv4offsetDst+net.IPv4len])

		dst = netip.AddrFrom4(dstBytes)
	case ipv6.Version:
		if lenPkt < ipv6.HeaderLen {
			return nil
		}

		var dstBytes [16]byte
		copy(dstBytes[:], pkt[IPv6offsetDst:IPv6offsetDst+net.IPv6len])

		dst = netip.AddrFrom16(dstBytes)

	default:
		return nil
	}

	ret, ok := s.lookupMap.lookupMap[dst.String()]
	if !ok {
		return nil
	}

	return ret
}

func (s *QUICController) startTunRecvFromDevLoop(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffs := make([][]byte, 1)
			sizes := make([]int, 1)
			buffs[0] = make([]byte, 1500)

			n, err := s.tundev.Read(buffs, sizes, tunPacketOffset)
			if err != nil {
				zap.L().Warn("Could not read from tun", zap.Error(err))
				continue
			}

			for i := 0; i < n; i++ {
				pktBuf := buffs[i][tunPacketOffset : sizes[i]+tunPacketOffset]
				s.tunReadCh <- pktBuf
			}

		}
	}
}
