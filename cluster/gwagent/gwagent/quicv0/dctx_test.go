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
	"net"
	"net/netip"
	"testing"

	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

func genTstIPPacketV4(src, dst netip.Addr, len int) []byte {
	ret := make([]byte, len)
	ret[0] = ipv4.Version << 4
	copy(ret[IPv4offsetSrc:IPv4offsetSrc+net.IPv4len], src.AsSlice())
	copy(ret[IPv4offsetDst:IPv4offsetDst+net.IPv4len], dst.AsSlice())

	return ret
}

func TestIsPacketValid(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	mtu := 1280

	dctx := &dctx{
		mtu: mtu,
		svcCIDRs: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		addrs: []netip.Prefix{
			netip.MustParsePrefix("10.0.1.1/32"),
		},
	}

	assert.True(t, netip.MustParsePrefix("10.0.1.1/32").Contains(netip.MustParseAddr("10.0.1.1")))

	assert.False(t, dctx.isPacketValid(nil))
	assert.False(t, dctx.isPacketValid(utilrand.GetRandomBytesMust(10)))
	assert.False(t, dctx.isPacketValid(utilrand.GetRandomBytesMust(2000)))

	assert.False(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("8.8.8.8"), 100)))

	assert.False(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), 1000)))
	assert.False(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("8.8.8.8"), 1000)))

	assert.True(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("10.0.0.16"), ipv4.HeaderLen)))
	assert.True(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("10.0.0.16"), ipv4.HeaderLen+1)))
	assert.True(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("10.0.0.16"), mtu)))
	assert.False(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("10.0.0.16"), mtu+1)))

	assert.False(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("10.0.0.1"), ipv4.HeaderLen)))
}

func genTstIPPacketV6(src, dst netip.Addr, len int) []byte {
	ret := make([]byte, len)
	ret[0] = ipv6.Version << 4
	copy(ret[IPv6offsetSrc:IPv6offsetSrc+net.IPv6len], src.AsSlice())
	copy(ret[IPv6offsetDst:IPv6offsetDst+net.IPv6len], dst.AsSlice())

	return ret
}

func TestIsDstValid(t *testing.T) {
	v4Only := &dctx{
		svcCIDRs: []netip.Prefix{
			netip.MustParsePrefix("100.64.1.0/24"),
		},
	}

	assert.True(t, v4Only.isDstValid(netip.MustParseAddr("100.64.1.16"), 0))
	assert.False(t, v4Only.isDstValid(netip.MustParseAddr("fdee::100:10"), 0))

	dctx := &dctx{
		mtu: 1280,
		svcCIDRs: []netip.Prefix{
			netip.MustParsePrefix("100.64.1.0/24"),
			netip.MustParsePrefix("fdee::100:0/112"),
		},
		addrs: []netip.Prefix{
			netip.MustParsePrefix("100.66.0.10/32"),
			netip.MustParsePrefix("fdee::2:0:0:10/128"),
		},
	}

	for _, proto := range []uint8{0, unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_ICMPV6} {
		for _, addr := range []string{
			"100.64.1.0", "100.64.1.1", "100.64.1.2", "100.64.1.15", "100.64.1.255",
			"100.64.2.16", "100.64.0.255", "8.8.8.8",
		} {
			assert.False(t, dctx.isDstValid(netip.MustParseAddr(addr), proto), addr)
		}

		for _, addr := range []string{"100.64.1.16", "100.64.1.100", "100.64.1.254"} {
			assert.True(t, dctx.isDstValid(netip.MustParseAddr(addr), proto), addr)
		}
	}

	for _, addr := range []string{
		"100.64.1.0", "100.64.1.1", "100.64.1.2", "100.64.1.15", "100.64.1.16", "100.64.1.255",
	} {
		assert.True(t, dctx.isDstValid(netip.MustParseAddr(addr), unix.IPPROTO_ICMP), addr)
	}

	for _, addr := range []string{"100.64.2.1", "8.8.8.8"} {
		assert.False(t, dctx.isDstValid(netip.MustParseAddr(addr), unix.IPPROTO_ICMP), addr)
	}

	for _, proto := range []uint8{0, unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6} {
		for _, addr := range []string{
			"fdee::100:0", "fdee::100:1", "fdee::100:2", "fdee::100:f",
			"fdee::101:10", "::ffff:100.64.1.16", "2001:db8::1",
		} {
			assert.False(t, dctx.isDstValid(netip.MustParseAddr(addr), proto), addr)
		}

		for _, addr := range []string{"fdee::100:10", "fdee::100:1234", "fdee::100:ffff"} {
			assert.True(t, dctx.isDstValid(netip.MustParseAddr(addr), proto), addr)
		}
	}

	{
		src := netip.MustParseAddr("100.66.0.10")

		pkt := genTstIPPacketV4(src, netip.MustParseAddr("100.64.1.2"), 100)
		assert.False(t, dctx.isPacketValid(pkt))

		pkt[IPv4offsetProtocol] = unix.IPPROTO_ICMP
		assert.True(t, dctx.isPacketValid(pkt))

		pkt = genTstIPPacketV4(src, netip.MustParseAddr("100.64.1.16"), 100)
		pkt[IPv4offsetProtocol] = unix.IPPROTO_TCP
		assert.True(t, dctx.isPacketValid(pkt))

		pkt = genTstIPPacketV4(netip.MustParseAddr("100.66.0.11"), netip.MustParseAddr("100.64.1.16"), 100)
		assert.False(t, dctx.isPacketValid(pkt))
	}

	{
		src := netip.MustParseAddr("fdee::2:0:0:10")

		assert.False(t, dctx.isPacketValid(genTstIPPacketV6(src, netip.MustParseAddr("fdee::100:2"), 100)))
		assert.True(t, dctx.isPacketValid(genTstIPPacketV6(src, netip.MustParseAddr("fdee::100:10"), 100)))
		assert.False(t, dctx.isPacketValid(
			genTstIPPacketV6(netip.MustParseAddr("fdee::2:0:0:11"), netip.MustParseAddr("fdee::100:10"), 100)))
	}
}

func TestGetBroadcastAddrV4(t *testing.T) {
	for cidr, broadcast := range map[string]string{
		"100.64.1.0/24":   "100.64.1.255",
		"100.64.1.77/24":  "100.64.1.255",
		"100.64.0.0/16":   "100.64.255.255",
		"100.64.1.128/25": "100.64.1.255",
		"100.64.1.0/25":   "100.64.1.127",
		"100.64.1.1/32":   "100.64.1.1",
		"0.0.0.0/0":       "255.255.255.255",
	} {
		assert.Equal(t, netip.MustParseAddr(broadcast), getBroadcastAddrV4(netip.MustParsePrefix(cidr)), cidr)
	}
}
