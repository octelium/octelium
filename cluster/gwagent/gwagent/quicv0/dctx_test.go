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

	assert.False(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("10.0.0.1"), ipv4.HeaderLen)))
	assert.True(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("10.0.0.1"), ipv4.HeaderLen+1)))
	assert.True(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("10.0.0.1"), mtu)))
	assert.False(t, dctx.isPacketValid(
		genTstIPPacketV4(netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("10.0.0.1"), mtu+1)))
}
