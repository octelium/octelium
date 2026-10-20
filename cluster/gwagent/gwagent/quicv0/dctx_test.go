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
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestNewDctx(t *testing.T) {
	for _, mode := range []corev1.Session_Status_Connection_L3Mode{
		corev1.Session_Status_Connection_BOTH,
		corev1.Session_Status_Connection_V4,
		corev1.Session_Status_Connection_V6,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			sess := newTstQUICSession()
			sess.Status.Connection.L3Mode = mode
			sess.Status.Connection.Addresses = append(sess.Status.Connection.Addresses, &metav1.DualStackNetwork{})
			tunCh := make(chan []byte, 1)
			cidrs := []netip.Prefix{
				netip.MustParsePrefix("100.64.1.0/24"), netip.MustParsePrefix("fdee::100:0/112"),
			}
			d := newDctx(sess, nil, tunCh, cidrs, 1280)
			assert.Equal(t, sess.Metadata.Uid, d.id)
			assert.Equal(t, sess.Status.Connection.StartedAt.AsTime(), d.connStartedAt)
			assert.False(t, d.createdAt.IsZero())
			assert.Equal(t, 1280, d.mtu)
			assert.Equal(t, 1024, cap(d.sendCh))
			assert.Equal(t, 1024, cap(d.processCh))
			count := 1
			if mode == corev1.Session_Status_Connection_BOTH {
				count = 2
			}
			assert.Len(t, d.addrs, count)
			assert.Len(t, d.svcCIDRs, count)
			assert.Equal(t, mode != corev1.Session_Status_Connection_V6,
				d.isSrcValid(netip.MustParseAddr("100.66.0.10")))
			assert.Equal(t, mode != corev1.Session_Status_Connection_V4,
				d.isSrcValid(netip.MustParseAddr("fdee::2:0:0:10")))
			assert.Equal(t, mode != corev1.Session_Status_Connection_V6,
				d.isDstValid(netip.MustParseAddr("100.64.1.16"), unix.IPPROTO_TCP))
			assert.Equal(t, mode != corev1.Session_Status_Connection_V4,
				d.isDstValid(netip.MustParseAddr("fdee::100:10"), unix.IPPROTO_TCP))
		})
	}
}

func TestPacketValidationBoundaries(t *testing.T) {
	d := &dctx{
		mtu:      1280,
		addrs:    []netip.Prefix{netip.MustParsePrefix("100.66.0.10/32"), netip.MustParsePrefix("fdee::2:0:0:10/128")},
		svcCIDRs: []netip.Prefix{netip.MustParsePrefix("100.64.1.0/24"), netip.MustParsePrefix("fdee::100:0/112")},
	}
	v4 := genTstIPPacketV4(netip.MustParseAddr("100.66.0.10"), netip.MustParseAddr("100.64.1.16"), 1280)
	v6 := genTstIPPacketV6(netip.MustParseAddr("fdee::2:0:0:10"), netip.MustParseAddr("fdee::100:10"), 1280)
	for size := 0; size <= 1280; size++ {
		assert.Equal(t, size >= ipv4.HeaderLen, d.isPacketValid(v4[:size]), size)
		assert.Equal(t, size >= ipv6.HeaderLen, d.isPacketValid(v6[:size]), size)
	}
	for version := byte(0); version < 16; version++ {
		if version == ipv4.Version || version == ipv6.Version {
			continue
		}
		pkt := append([]byte(nil), v4[:60]...)
		pkt[0] = version << 4
		assert.False(t, d.isPacketValid(pkt), version)
	}
	for _, src := range []string{"0.0.0.0", "127.0.0.1", "100.66.0.9", "100.66.0.11", "255.255.255.255"} {
		assert.False(t, d.isPacketValid(genTstIPPacketV4(netip.MustParseAddr(src), netip.MustParseAddr("100.64.1.16"), 60)), src)
	}
	assert.False(t, d.isSrcValid(netip.Addr{}))
	assert.False(t, d.isDstValid(netip.Addr{}, unix.IPPROTO_TCP))
}

func TestProcessPackets(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tunCh := make(chan []byte, 64)
	d := newDctx(newTstQUICSession(), nil, tunCh,
		[]netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")}, 1280)
	done := make(chan struct{})
	go func() {
		d.startProcessLoop(ctx)
		close(done)
	}()
	valid := genTstIPPacketV4(netip.MustParseAddr("100.66.0.10"), netip.MustParseAddr("100.64.1.16"), 60)
	invalid := genTstIPPacketV4(netip.MustParseAddr("100.66.0.11"), netip.MustParseAddr("100.64.1.16"), 60)
	for range 64 {
		d.processCh <- invalid
		d.processCh <- nil
		d.processCh <- valid
	}
	for range 64 {
		select {
		case pkt := <-tunCh:
			assert.Equal(t, valid, pkt)
		case <-time.After(5 * time.Second):
			t.Fatal("The valid packet was not forwarded")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("The packet processor did not stop")
	}
	assert.Empty(t, tunCh)
}

func TestProcessPacketsBackpressure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	d := newDctx(newTstQUICSession(), nil, make(chan []byte),
		[]netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")}, 1280)
	done := make(chan struct{})
	go func() {
		d.startProcessLoop(ctx)
		close(done)
	}()
	d.processCh <- genTstIPPacketV4(netip.MustParseAddr("100.66.0.10"), netip.MustParseAddr("100.64.1.16"), 60)
	require.Eventually(t, func() bool { return len(d.processCh) == 0 }, 5*time.Second, time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("The blocked packet processor did not stop")
	}
}

func TestDctx(t *testing.T) {
	for _, peerClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "peerClosed"}[peerClose], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			server, client := newTstQUICPair(t)
			tunCh := make(chan []byte, 1)
			d := newDctx(newTstQUICSession(), server, tunCh,
				[]netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")}, 256)
			done := make(chan error, 1)
			go func() { done <- d.runAndWait(ctx) }()
			for _, buf := range [][]byte{nil, {1, 2, 3}, make([]byte, 257), make([]byte, 60)} {
				require.Nil(t, client.SendDatagram(buf))
			}
			pkt := genTstIPPacketV4(netip.MustParseAddr("100.66.0.10"), netip.MustParseAddr("100.64.1.16"), 60)
			require.Nil(t, client.SendDatagram(pkt))
			select {
			case got := <-tunCh:
				assert.Equal(t, pkt, got)
			case <-time.After(5 * time.Second):
				t.Fatal("The valid datagram was not forwarded")
			}
			d.sendCh <- make([]byte, 2000)
			d.sendCh <- pkt
			rcvCtx, rcvCancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer rcvCancel()
			got, err := client.ReceiveDatagram(rcvCtx)
			require.Nil(t, err)
			assert.Equal(t, pkt, got)
			if peerClose {
				require.Nil(t, client.CloseWithError(0, ""))
			} else {
				cancel()
			}
			select {
			case err := <-done:
				assert.Nil(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("The data context did not stop")
			}
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() { assert.Nil(t, d.close()) })
			}
			wg.Wait()
			assert.True(t, d.isClosed)
			assert.Nil(t, d.runAndWait(t.Context()))
		})
	}
}

func TestDctxRegistration(t *testing.T) {
	ctl := &QUICController{
		dctxMap:   dctxMap{dctxMap: make(map[string]*dctx)},
		lookupMap: lookupMap{lookupMap: make(map[string]*dctx)},
	}
	server, _ := newTstQUICPair(t)
	sess := newTstQUICSession()
	old := newDctx(sess, server, nil, nil, 1280)
	require.Nil(t, ctl.addDctx(old))
	assert.Same(t, old, ctl.dctxMap.dctxMap[old.id])
	for _, addr := range old.addrs {
		assert.Same(t, old, ctl.lookupMap.lookupMap[addr.Addr().String()])
	}
	duplicate := newDctx(sess, nil, nil, nil, 1280)
	assert.NotNil(t, ctl.addDctx(duplicate))
	assert.Same(t, old, ctl.dctxMap.dctxMap[old.id])

	sess.Status.Connection.StartedAt = pbutils.Timestamp(old.connStartedAt.Add(time.Second))
	currentServer, _ := newTstQUICPair(t)
	current := newDctx(sess, currentServer, nil, nil, 1280)
	require.Nil(t, ctl.addDctx(current))
	assert.True(t, old.isClosed)
	ctl.removeDctx(old)
	assert.Same(t, current, ctl.dctxMap.dctxMap[current.id])
	for _, addr := range current.addrs {
		assert.Same(t, current, ctl.lookupMap.lookupMap[addr.Addr().String()])
	}
	ctl.removeDctx(current)
	ctl.removeDctx(current)
	assert.Empty(t, ctl.dctxMap.dctxMap)
	assert.Empty(t, ctl.lookupMap.lookupMap)
}

func TestRemoveQUICConnection(t *testing.T) {
	for _, name := range []string{"disconnected", "wireguard", "missing", "stale", "current"} {
		t.Run(name, func(t *testing.T) {
			server, _ := newTstQUICPair(t)
			sess := newTstQUICSession()
			d := newDctx(sess, server, nil, nil, 1280)
			ctl := &QUICController{dctxMap: dctxMap{dctxMap: map[string]*dctx{d.id: d}}}
			switch name {
			case "disconnected":
				sess.Status.Connection = nil
			case "wireguard":
				sess.Status.Connection.Type = corev1.Session_Status_Connection_WIREGUARD
			case "missing":
				sess.Metadata.Uid = "missing"
			case "stale":
				sess.Status.Connection.StartedAt = pbutils.Timestamp(d.connStartedAt.Add(-time.Second))
			}
			require.Nil(t, ctl.RemoveConnection(sess))
			assert.Equal(t, name == "current", d.isClosed)
			assert.Nil(t, ctl.RemoveConnection(sess))
		})
	}
}
