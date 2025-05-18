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
	"net/netip"
	"testing"

	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestGetDctxFromTunPacket(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	ctl, err := New(ctx, tst.C.OcteliumC, utilrand.GetRandomStringCanonical(8))
	assert.Nil(t, err)

	netw := netip.MustParsePrefix("10.0.0.0/24")

	netwAddr := netw.Addr()

	dctxs := []*dctx{}

	mtu := 1280

	ctl.mtu = mtu

	for i := 0; i < 20; i++ {
		netwAddr = netwAddr.Next()
		dctx := &dctx{
			id: vutils.UUIDv4(),
			addrs: []netip.Prefix{
				netip.PrefixFrom(netwAddr, 32),
			},
			mtu: mtu,
		}

		dctxs = append(dctxs, dctx)

		for _, addr := range dctx.addrs {
			ctl.lookupMap.lookupMap[addr.Addr().String()] = dctx
		}
	}

	{
		assert.Nil(t, ctl.getDctxFromTunPacket(nil))
		assert.Nil(t, ctl.getDctxFromTunPacket(utilrand.GetRandomBytesMust(8)))
		assert.Nil(t, ctl.getDctxFromTunPacket(utilrand.GetRandomBytesMust(800)))

		idx := utilrand.GetRandomRangeMath(0, 19)

		dctx := ctl.getDctxFromTunPacket(
			genTstIPPacketV4(netip.MustParseAddr("1.1.1.1"), dctxs[idx].addrs[0].Addr(), 100))
		assert.NotNil(t, dctx)

		assert.Equal(t, dctxs[idx].id, dctx.id)
	}

}
