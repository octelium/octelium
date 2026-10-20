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
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/tun"
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

func TestTunPacketRouting(t *testing.T) {
	d := &dctx{sendCh: make(chan []byte, 1)}
	ctl := &QUICController{
		mtu: 1280,
		lookupMap: lookupMap{lookupMap: map[string]*dctx{
			"100.66.0.10": d, "fdee::2:0:0:10": d,
		}},
	}
	v4 := genTstIPPacketV4(netip.MustParseAddr("100.64.1.16"), netip.MustParseAddr("100.66.0.10"), 1280)
	v6 := genTstIPPacketV6(netip.MustParseAddr("fdee::100:10"), netip.MustParseAddr("fdee::2:0:0:10"), 1280)
	for size := 0; size <= 1280; size++ {
		assert.Equal(t, size > ipv4.HeaderLen, ctl.getDctxFromTunPacket(v4[:size]) == d, size)
		assert.Equal(t, size >= ipv6.HeaderLen, ctl.getDctxFromTunPacket(v6[:size]) == d, size)
	}
	assert.Nil(t, ctl.getDctxFromTunPacket(append(v4, 0)))
	assert.Nil(t, ctl.getDctxFromTunPacket(append(v6, 0)))
	assert.Nil(t, ctl.getDctxFromTunPacket(genTstIPPacketV4(
		netip.MustParseAddr("100.64.1.16"), netip.MustParseAddr("100.66.0.11"), 60)))
	for version := byte(0); version < 16; version++ {
		if version == ipv4.Version || version == ipv6.Version {
			continue
		}
		pkt := append([]byte(nil), v4[:60]...)
		pkt[0] = version << 4
		assert.Nil(t, ctl.getDctxFromTunPacket(pkt))
	}
	ctl.doProcessTunPacket(nil)
	assert.Empty(t, d.sendCh)
	ctl.doProcessTunPacket(v4)
	ctl.doProcessTunPacket(v6)
	require.Len(t, d.sendCh, 1)
	assert.Equal(t, v4, <-d.sendCh)
	ctl.doProcessTunPacket(v6)
	assert.Equal(t, v6, <-d.sendCh)
}

func TestTunPacketRoutingConcurrent(t *testing.T) {
	ctl := &QUICController{mtu: 1280, lookupMap: lookupMap{lookupMap: make(map[string]*dctx)}}
	var wg sync.WaitGroup
	for i := range 32 {
		addr := netip.MustParseAddr(fmt.Sprintf("100.66.0.%d", i+1))
		d := &dctx{sendCh: make(chan []byte, 64)}
		ctl.lookupMap.lookupMap[addr.String()] = d
	}
	for addr := range ctl.lookupMap.lookupMap {
		wg.Go(func() {
			pkt := genTstIPPacketV4(netip.MustParseAddr("100.64.1.16"), netip.MustParseAddr(addr), 60)
			for range 64 {
				ctl.doProcessTunPacket(pkt)
			}
		})
	}
	wg.Wait()
	for addr, d := range ctl.lookupMap.lookupMap {
		require.Len(t, d.sendCh, 64)
		for range 64 {
			pkt := <-d.sendCh
			assert.Equal(t, addr, netip.AddrFrom4([4]byte(pkt[IPv4offsetDst:IPv4offsetDst+4])).String())
		}
	}
}

type tstTunDevice struct {
	tun.Device
	readFn  func([][]byte, []int, int) (int, error)
	writeFn func([][]byte, int) (int, error)
}

func (d *tstTunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return d.readFn(bufs, sizes, offset)
}

func (d *tstTunDevice) Write(bufs [][]byte, offset int) (int, error) {
	return d.writeFn(bufs, offset)
}

func TestTunDeviceLoops(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	pkt := genTstIPPacketV4(netip.MustParseAddr("100.64.1.16"), netip.MustParseAddr("100.66.0.10"), 60)
	d := &dctx{sendCh: make(chan []byte, 1)}
	writes := make(chan []byte, 2)
	readCount := 0
	ctl := &QUICController{
		mtu: 1280, tunReadCh: make(chan []byte, 1), tunWriteCh: make(chan []byte, 1),
		lookupMap: lookupMap{lookupMap: map[string]*dctx{"100.66.0.10": d}},
		tundev: &tstTunDevice{
			readFn: func(bufs [][]byte, sizes []int, offset int) (int, error) {
				readCount++
				switch readCount {
				case 1:
					return 0, fmt.Errorf("read failed")
				case 2:
					assert.Equal(t, tunPacketOffset, offset)
					copy(bufs[0], pkt)
					sizes[0] = len(pkt)
					return 1, nil
				default:
					<-ctx.Done()
					return 0, ctx.Err()
				}
			},
			writeFn: func(bufs [][]byte, offset int) (int, error) {
				assert.Zero(t, offset)
				require.Len(t, bufs, 1)
				writes <- append([]byte(nil), bufs[0]...)
				return 0, fmt.Errorf("write failed")
			},
		},
	}
	var wg sync.WaitGroup
	wg.Go(func() { ctl.startTunRecvFromDevLoop(ctx) })
	wg.Go(func() { ctl.startProcessPacketLoop(ctx) })
	wg.Go(func() { ctl.startTunSendToDevLoop(ctx) })
	ctl.tunWriteCh <- pkt
	select {
	case got := <-writes:
		assert.Equal(t, pkt, got)
	case <-time.After(5 * time.Second):
		t.Fatal("The packet was not written to the device")
	}
	ctl.tunWriteCh <- pkt
	select {
	case <-writes:
	case <-time.After(5 * time.Second):
		t.Fatal("The write loop stopped after a device error")
	}
	select {
	case got := <-d.sendCh:
		assert.Equal(t, pkt, got)
	case <-time.After(5 * time.Second):
		t.Fatal("The device packet was not routed")
	}
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("The device loops did not stop")
	}
}
