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
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/quic-go/quic-go"
	"go.uber.org/zap"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type dctx struct {
	id string

	createdAt time.Time

	mu       sync.Mutex
	isClosed bool
	conn     *quic.Conn

	sendCh    chan []byte
	processCh chan []byte

	cancelFn context.CancelFunc
	tunCh    chan<- []byte
	addrs    []netip.Prefix

	svcCIDRs []netip.Prefix

	mtu int
}

func newDctx(sess *corev1.Session,
	conn *quic.Conn, tunCh chan<- []byte, svcCIDRs []netip.Prefix, mtu int) *dctx {

	zap.L().Debug("Creating a new dctx", zap.String("sessionUID", sess.Metadata.Uid), zap.Int("mtu", mtu))

	ret := &dctx{
		id:        sess.Metadata.Uid,
		createdAt: time.Now(),
		conn:      conn,
		sendCh:    make(chan []byte, 1024),
		processCh: make(chan []byte, 1024),
		tunCh:     tunCh,
		mtu:       mtu,
	}

	for _, addr := range sess.Status.Connection.Addresses {
		if addr.V4 != "" && ucorev1.ToSession(sess).HasV4() {
			ret.addrs = append(ret.addrs, netip.MustParsePrefix(addr.V4))
		}
		if addr.V6 != "" && ucorev1.ToSession(sess).HasV6() {
			ret.addrs = append(ret.addrs, netip.MustParsePrefix(addr.V6))
		}
	}

	for _, cidr := range svcCIDRs {
		if cidr.Addr().Is4() && ucorev1.ToSession(sess).HasV4() {
			ret.svcCIDRs = append(ret.svcCIDRs, cidr)
		}

		if cidr.Addr().Is6() && ucorev1.ToSession(sess).HasV6() {
			ret.svcCIDRs = append(ret.svcCIDRs, cidr)
		}
	}

	return ret
}

func (d *dctx) close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.isClosed {
		return nil
	}
	zap.L().Debug("Closing dctx", zap.String("id", d.id))
	d.isClosed = true
	d.cancelFn()
	d.conn.CloseWithError(12, "")
	zap.L().Debug("dctx is now closed", zap.String("id", d.id))
	return nil
}

func (d *dctx) runAndWait(ctx context.Context) error {
	ctx, cancelFn := context.WithCancel(ctx)
	d.cancelFn = cancelFn
	zap.L().Debug("Starting running dctx", zap.String("id", d.id))

	go d.startReceiveLoop(ctx)
	go d.startSendLoop(ctx)
	go d.startProcessLoop(ctx)

	zap.L().Debug("Waiting for dctx to close", zap.String("id", d.id))

	select {
	case <-ctx.Done():
		zap.L().Debug("closing dctx due to ctx closed", zap.String("id", d.id))
	case <-d.conn.Context().Done():
		zap.L().Debug("closing dctx due to conn dctx closed", zap.String("id", d.id))
	}

	return d.close()
}

func (d *dctx) startProcessLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case buf := <-d.processCh:
			if d.isPacketValid(buf) {
				d.tunCh <- buf
			}
		}
	}
}

func (d *dctx) isPacketValid(buf []byte) bool {
	lenBuf := len(buf)
	if lenBuf <= ipv4.HeaderLen || lenBuf > d.mtu {
		return false
	}

	var src netip.Addr
	var dst netip.Addr

	switch buf[0] >> 4 {
	case ipv4.Version:
		var srcBytes [4]byte
		var dstBytes [4]byte
		copy(srcBytes[:], buf[IPv4offsetSrc:IPv4offsetSrc+net.IPv4len])
		copy(dstBytes[:], buf[IPv4offsetDst:IPv4offsetDst+net.IPv4len])

		src = netip.AddrFrom4(srcBytes)
		dst = netip.AddrFrom4(dstBytes)
	case ipv6.Version:
		if lenBuf <= 40 {
			return false
		}

		var srcBytes [16]byte
		var dstBytes [16]byte
		copy(srcBytes[:], buf[IPv6offsetSrc:IPv6offsetSrc+net.IPv6len])
		copy(dstBytes[:], buf[IPv6offsetDst:IPv6offsetDst+net.IPv6len])

		src = netip.AddrFrom16(srcBytes)
		dst = netip.AddrFrom16(dstBytes)
	default:
		return false
	}

	if !d.isSrcValid(src) {
		return false
	}

	if !d.isDstValid(dst) {
		return false
	}

	return true
}

func (d *dctx) isSrcValid(src netip.Addr) bool {
	for _, addr := range d.addrs {
		if addr.Contains(src) {
			return true
		}
	}
	return false
}

func (d *dctx) isDstValid(dst netip.Addr) bool {
	for _, addr := range d.svcCIDRs {
		if addr.Contains(dst) {
			return true
		}
	}
	return false
}

func (d *dctx) startReceiveLoop(ctx context.Context) {

	mtu := d.mtu
	for {
		select {
		case <-ctx.Done():
			return
		default:
			msg, err := d.conn.ReceiveDatagram(ctx)
			if err != nil {
				zap.L().Debug("Could not rcv message", zap.String("id", d.id))
				time.Sleep(100 * time.Millisecond)
				continue
			}
			lenMsg := len(msg)
			if lenMsg <= ipv4.HeaderLen || lenMsg > mtu {
				continue
			}
			d.processCh <- msg
		}
	}
}

func (d *dctx) startSendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case buf := <-d.sendCh:
			if err := d.conn.SendDatagram(buf); err != nil {
				zap.L().Debug("Could not send message",
					zap.String("id", d.id), zap.Error(err), zap.Int("packet len", len(buf)))
				time.Sleep(100 * time.Millisecond)
				continue
			}

		}
	}
}
